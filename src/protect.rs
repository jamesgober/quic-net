//! Packet protection (RFC 9001 section 5): the Initial key schedule, header
//! protection, sealing and opening a packet around the wire layer's headers,
//! the AEAD limits, and the Retry integrity tag.
//!
//! The ciphers are behind two traits. [`PacketKey`] seals and opens a
//! payload in place under the nonce made from a packet number, and
//! [`HeaderKey`] turns a 16-byte sample into the 5-byte header mask. A TLS
//! session provides both for the Handshake and 1-RTT levels; for Initial
//! packets, [`InitialSecrets`] and [`Secret::key_material`] derive the bytes
//! that a cipher implementation turns into keys. This module does the
//! framing around them: where the sample is, which bits the mask covers, the
//! packet number's length and value, the reserved bits, and the counts that
//! RFC 9001 section 6.6 limits.

use core::fmt;
use core::ops::Range;

use crypt_io::mac::HmacSha256;

use crate::cid::{ConnectionId, ct_eq};
use crate::error::TransportErrorCode;
use crate::packet::decode_packet_number;
use crate::params::Side;

/// The length of the AEAD tag of every QUIC version 1 cipher suite.
pub const TAG_LEN: usize = 16;

/// The length of the header protection sample.
pub const SAMPLE_LEN: usize = 16;

/// The salt Initial secrets are extracted with (RFC 9001 section 5.2).
pub const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// The AES-128-GCM key of the Retry integrity tag (RFC 9001 section 5.8).
pub const RETRY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// The nonce of the Retry integrity tag (RFC 9001 section 5.8).
pub const RETRY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// A cipher failed: a key could not be made or used. The packet is dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoError;

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a cryptographic operation failed")
    }
}

impl std::error::Error for CryptoError {}

/// An AEAD key of one direction and level: seals and opens a payload in
/// place. The nonce is the key's IV with the packet number XORed into its
/// last 8 bytes (RFC 9001 section 5.3); the associated data is the header,
/// packet number included.
pub trait PacketKey {
    /// Encrypts `payload` in place and returns its tag.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the cipher fails.
    fn seal(
        &self,
        pn: u64,
        header: &[u8],
        payload: &mut [u8],
    ) -> Result<[u8; TAG_LEN], CryptoError>;

    /// Checks the tag at the end of `payload_and_tag` and decrypts the rest
    /// in place; returns the plaintext's length. The payload and its tag are
    /// one slice because they are contiguous in a packet, and TLS libraries
    /// open them that way.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the tag does not match (the payload is then not
    /// to be read) or the cipher fails.
    fn open(
        &self,
        pn: u64,
        header: &[u8],
        payload_and_tag: &mut [u8],
    ) -> Result<usize, CryptoError>;

    /// The cipher's limits (RFC 9001 section 6.6).
    fn limits(&self) -> AeadLimits;
}

/// A header protection key of one direction and level.
pub trait HeaderKey {
    /// The mask for `sample`: AES-ECB of the sample, or ChaCha20 with the
    /// sample as counter and nonce (RFC 9001 section 5.4). Only the first 5
    /// bytes are used.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the cipher fails.
    fn mask(&self, sample: &[u8; SAMPLE_LEN]) -> Result<[u8; 5], CryptoError>;
}

/// Why a packet could not be protected or opened.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectError {
    /// The packet is too short to sample (RFC 9001 section 5.4.2) or to hold
    /// its tag. Received, it is dropped; to be sent, it needs padding.
    TooShort,
    /// A key failed. A received packet is dropped; one being sealed is not
    /// sent.
    Crypto,
    /// The payload did not authenticate. The packet is dropped and counted
    /// against the integrity limit ([`AeadUsage::failed`]).
    Authentication,
    /// The reserved bits were not zero after both protections were removed:
    /// a `PROTOCOL_VIOLATION` (RFC 9000 section 17.2).
    ReservedBits,
    /// Sealing: the packet number given is not the one the header holds.
    PacketNumber,
}

impl ProtectError {
    /// The error to close the connection with, or `None` when the packet is
    /// only dropped.
    #[must_use]
    pub fn code(&self) -> Option<TransportErrorCode> {
        match self {
            ProtectError::ReservedBits => Some(TransportErrorCode::PROTOCOL_VIOLATION),
            _ => None,
        }
    }
}

impl fmt::Display for ProtectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ProtectError::TooShort => "the packet is too short to protect",
            ProtectError::Crypto => "a packet protection key failed",
            ProtectError::Authentication => "the packet did not authenticate",
            ProtectError::ReservedBits => "the reserved bits are not zero",
            ProtectError::PacketNumber => "the packet number does not match the header",
        })
    }
}

impl std::error::Error for ProtectError {}

/// What removing header protection revealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unprotected {
    /// The full packet number.
    pub pn: u64,
    /// How many bytes the packet number took (1 to 4).
    pub pn_len: usize,
    /// The key phase bit (short headers; `false` for long ones). A change
    /// means the peer moved to the next keys (RFC 9001 section 6).
    pub key_phase: bool,
    first: u8,
    header_len: usize,
}

impl Unprotected {
    /// The header's length, packet number included: where the payload
    /// starts.
    #[must_use]
    pub fn header_len(&self) -> usize {
        self.header_len
    }
}

fn is_long(first: u8) -> bool {
    first & 0x80 != 0
}

/// The first byte's bits that header protection covers.
fn protected_bits(first: u8) -> u8 {
    if is_long(first) { 0x0f } else { 0x1f }
}

fn reserved_bits(first: u8) -> u8 {
    if is_long(first) { 0x0c } else { 0x18 }
}

fn sample(packet: &[u8], pn_offset: usize) -> Result<&[u8; SAMPLE_LEN], ProtectError> {
    let start = pn_offset.checked_add(4).ok_or(ProtectError::TooShort)?;
    let end = start
        .checked_add(SAMPLE_LEN)
        .ok_or(ProtectError::TooShort)?;
    packet
        .get(start..end)
        .and_then(|s| <&[u8; SAMPLE_LEN]>::try_from(s).ok())
        .ok_or(ProtectError::TooShort)
}

/// Seals a packet in place: `packet` holds the header as the wire layer
/// wrote it (packet number included, at `pn_offset`), then the plaintext
/// payload, then [`TAG_LEN`] bytes for the tag. The payload is encrypted,
/// the tag written, and header protection applied.
///
/// For a long header, its length field must already count the packet
/// number, the payload, and the tag ([`LongHeader::encode`](crate::LongHeader::encode)
/// takes that length). The payload must be long enough to sample: with the
/// packet number, at least 4 bytes before the tag (RFC 9001 section 5.4.2).
///
/// # Errors
///
/// [`ProtectError::TooShort`], [`ProtectError::PacketNumber`] when `pn` is
/// not what the header holds, [`ProtectError::Crypto`] when a key fails. On
/// an error the packet's contents are not to be sent.
pub fn seal_packet<K: PacketKey + ?Sized, H: HeaderKey + ?Sized>(
    packet: &mut [u8],
    pn_offset: usize,
    pn: u64,
    key: &K,
    hp: &H,
) -> Result<(), ProtectError> {
    // A packet that can be sampled holds its header and its packet number.
    sample(packet, pn_offset)?;
    let first = packet[0];
    let pn_len = usize::from(first & 0x03) + 1;
    let header_len = pn_offset + pn_len;
    if packet.len() < header_len + TAG_LEN {
        return Err(ProtectError::TooShort);
    }
    let written = packet[pn_offset..header_len]
        .iter()
        .fold(0u64, |v, b| (v << 8) | u64::from(*b));
    if written != pn & ((1u64 << (8 * pn_len)) - 1) {
        return Err(ProtectError::PacketNumber);
    }
    let (header, rest) = packet.split_at_mut(header_len);
    let tag_at = rest.len() - TAG_LEN;
    let (payload, tag_room) = rest.split_at_mut(tag_at);
    let tag = key
        .seal(pn, header, payload)
        .map_err(|_| ProtectError::Crypto)?;
    tag_room.copy_from_slice(&tag);
    let m = hp
        .mask(sample(packet, pn_offset)?)
        .map_err(|_| ProtectError::Crypto)?;
    packet[0] ^= m[0] & protected_bits(first);
    for (b, m) in packet[pn_offset..header_len].iter_mut().zip(&m[1..]) {
        *b ^= m;
    }
    Ok(())
}

/// Removes header protection from one received packet (as
/// [`parse_packet`](crate::parse_packet) delimits it), in place, and
/// recovers the full packet number from `largest_pn`, the largest packet
/// number received in the same packet number space so far.
///
/// The payload is still sealed: [`open_payload`] comes next, with the key
/// the key phase picks. Nothing read here is trusted until it does.
///
/// # Errors
///
/// [`ProtectError::TooShort`] when the packet cannot be sampled,
/// [`ProtectError::Crypto`] when the key fails. Either way the packet is
/// dropped.
pub fn remove_header_protection<H: HeaderKey + ?Sized>(
    packet: &mut [u8],
    pn_offset: usize,
    largest_pn: Option<u64>,
    hp: &H,
) -> Result<Unprotected, ProtectError> {
    let m = hp
        .mask(sample(packet, pn_offset)?)
        .map_err(|_| ProtectError::Crypto)?;
    let first = packet[0] ^ (m[0] & protected_bits(packet[0]));
    packet[0] = first;
    let pn_len = usize::from(first & 0x03) + 1;
    let header_len = pn_offset + pn_len;
    let mut truncated = 0u64;
    for (b, m) in packet[pn_offset..header_len].iter_mut().zip(&m[1..]) {
        *b ^= m;
        truncated = (truncated << 8) | u64::from(*b);
    }
    Ok(Unprotected {
        pn: decode_packet_number(largest_pn, truncated, pn_len),
        pn_len,
        key_phase: !is_long(first) && first & 0x04 != 0,
        first,
        header_len,
    })
}

/// Opens the payload of a packet whose header protection
/// [`remove_header_protection`] removed: checks the tag, decrypts in place,
/// then checks the reserved bits. Returns where the plaintext frames are.
///
/// # Errors
///
/// [`ProtectError::Authentication`] (drop the packet and count it with
/// [`AeadUsage::failed`]), or [`ProtectError::ReservedBits`] for a packet
/// that authenticated with reserved bits set (close the connection with
/// [`ProtectError::code`]).
pub fn open_payload<K: PacketKey + ?Sized>(
    packet: &mut [u8],
    unprotected: &Unprotected,
    key: &K,
) -> Result<Range<usize>, ProtectError> {
    let header_len = unprotected.header_len;
    if packet.len() < header_len + TAG_LEN {
        return Err(ProtectError::TooShort);
    }
    let (header, rest) = packet.split_at_mut(header_len);
    let tag_at = rest.len() - TAG_LEN;
    let n = key
        .open(unprotected.pn, header, rest)
        .map_err(|_| ProtectError::Authentication)?;
    if n != tag_at {
        return Err(ProtectError::Authentication);
    }
    if unprotected.first & reserved_bits(unprotected.first) != 0 {
        return Err(ProtectError::ReservedBits);
    }
    Ok(header_len..header_len + tag_at)
}

/// The limits of one AEAD (RFC 9001 section 6.6): how many packets one key
/// may seal, and how many forged packets a connection may receive across
/// all its keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AeadLimits {
    /// Packets one key may seal before the keys must be updated.
    pub confidentiality: u64,
    /// Packets failing authentication a connection may receive before it
    /// must close with `AEAD_LIMIT_REACHED`.
    pub integrity: u64,
}

impl AeadLimits {
    /// `AEAD_AES_128_GCM` and `AEAD_AES_256_GCM`: 2^23 and 2^52.
    pub const AES_GCM: AeadLimits = AeadLimits {
        confidentiality: 1 << 23,
        integrity: 1 << 52,
    };
    /// `AEAD_CHACHA20_POLY1305`: no confidentiality limit below the 2^62
    /// packet numbers a connection has, and 2^36.
    pub const CHACHA20_POLY1305: AeadLimits = AeadLimits {
        confidentiality: 1 << 62,
        integrity: 1 << 36,
    };
    /// `AEAD_AES_128_CCM`: 2^21.5 both.
    pub const AES_CCM: AeadLimits = AeadLimits {
        confidentiality: 2_965_820,
        integrity: 2_965_820,
    };
}

/// Counts a connection's AEAD use against [`AeadLimits`]: packets sealed
/// under the current 1-RTT key, and packets that failed authentication
/// under any key.
#[derive(Clone, Debug)]
pub struct AeadUsage {
    limits: AeadLimits,
    sealed: u64,
    failed: u64,
}

impl AeadUsage {
    /// Counting from zero against `limits`.
    #[must_use]
    pub fn new(limits: AeadLimits) -> AeadUsage {
        AeadUsage {
            limits,
            sealed: 0,
            failed: 0,
        }
    }

    /// Whether the current key may seal another packet. When it may not,
    /// the keys must be updated (RFC 9001 section 6.6) or, if an update is
    /// not possible, the connection closed.
    #[must_use]
    pub fn may_seal(&self) -> bool {
        self.sealed < self.limits.confidentiality
    }

    /// Counts a sealed packet.
    pub fn sealed(&mut self) {
        self.sealed = self.sealed.saturating_add(1);
    }

    /// Packets sealed under the current key.
    #[must_use]
    pub fn sealed_count(&self) -> u64 {
        self.sealed
    }

    /// The keys were updated: the new key starts from zero.
    pub fn key_updated(&mut self) {
        self.sealed = 0;
    }

    /// Counts a packet that failed authentication.
    ///
    /// # Errors
    ///
    /// `AEAD_LIMIT_REACHED` once the count reaches the integrity limit: the
    /// connection must close.
    pub fn failed(&mut self) -> Result<(), TransportErrorCode> {
        self.failed = self.failed.saturating_add(1);
        if self.failed >= self.limits.integrity {
            Err(TransportErrorCode::AEAD_LIMIT_REACHED)
        } else {
            Ok(())
        }
    }
}

fn wipe(b: &mut [u8]) {
    b.fill(0);
    std::hint::black_box(b);
}

/// A TLS 1.3 traffic secret of a SHA-256 cipher suite (32 bytes), zeroed on
/// drop. Initial secrets are always of this kind.
pub struct Secret([u8; 32]);

impl Secret {
    /// A secret of these bytes.
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Secret {
        Secret(bytes)
    }

    /// The secret's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `HKDF-Expand-Label(secret, label, "", out.len())` (RFC 8446 section
    /// 7.1), with the `tls13 ` prefix added here.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] for an output over 8,160 bytes or a label over 249.
    pub fn expand_label(&self, label: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
        expand_label(&self.0, label, out)
    }

    /// The keys a cipher suite with a `key_len`-byte key (16 or 32) needs:
    /// the AEAD key, the IV, and the header protection key, which has the
    /// AEAD key's length in every version 1 suite (RFC 9001 section 5.1).
    ///
    /// # Errors
    ///
    /// [`CryptoError`] for any other key length.
    pub fn key_material(&self, key_len: usize) -> Result<KeyMaterial, CryptoError> {
        if key_len != 16 && key_len != 32 {
            return Err(CryptoError);
        }
        let mut m = KeyMaterial {
            key: [0; 32],
            hp: [0; 32],
            iv: [0; 12],
            len: key_len,
        };
        expand_label(&self.0, b"quic key", &mut m.key[..key_len])?;
        expand_label(&self.0, b"quic iv", &mut m.iv)?;
        expand_label(&self.0, b"quic hp", &mut m.hp[..key_len])?;
        Ok(m)
    }

    /// The secret after a key update: `HKDF-Expand-Label(secret, "quic ku")`
    /// (RFC 9001 section 6.1). The header protection key does not change.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the hash fails.
    pub fn next(&self) -> Result<Secret, CryptoError> {
        let mut out = [0u8; 32];
        expand_label(&self.0, b"quic ku", &mut out)?;
        Ok(Secret(out))
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// The key bytes of one direction and level, zeroed on drop: what a cipher
/// implementation turns into a [`PacketKey`] and a [`HeaderKey`].
pub struct KeyMaterial {
    key: [u8; 32],
    hp: [u8; 32],
    iv: [u8; 12],
    len: usize,
}

impl KeyMaterial {
    /// The AEAD key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        &self.key[..self.len]
    }

    /// The IV the nonce is made from.
    #[must_use]
    pub fn iv(&self) -> &[u8; 12] {
        &self.iv
    }

    /// The header protection key.
    #[must_use]
    pub fn hp(&self) -> &[u8] {
        &self.hp[..self.len]
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        wipe(&mut self.key);
        wipe(&mut self.hp);
        wipe(&mut self.iv);
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyMaterial(..)")
    }
}

/// The nonce for packet number `pn`: the IV with `pn` XORed into its last 8
/// bytes (RFC 9001 section 5.3). For [`PacketKey`] implementations.
#[must_use]
pub fn nonce(iv: &[u8; 12], pn: u64) -> [u8; 12] {
    let mut n = *iv;
    for (b, p) in n[4..].iter_mut().zip(pn.to_be_bytes()) {
        *b ^= p;
    }
    n
}

/// The Initial secrets of a connection, from the destination ID of the
/// client's first Initial packet (RFC 9001 section 5.2). Anyone who sees
/// that packet can derive them: Initial protection guards against
/// off-path tampering and ossification, not against observers.
pub struct InitialSecrets {
    /// The client's secret.
    pub client: Secret,
    /// The server's secret.
    pub server: Secret,
}

impl InitialSecrets {
    /// The secrets for `dcid`, the destination ID the client first chose.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the hash fails.
    pub fn new(dcid: &ConnectionId) -> Result<InitialSecrets, CryptoError> {
        let mut h = HmacSha256::new(&INITIAL_SALT_V1).map_err(|_| CryptoError)?;
        h.update(dcid.as_slice());
        let initial = Secret(h.finalize());
        let mut client = [0u8; 32];
        let mut server = [0u8; 32];
        initial.expand_label(b"client in", &mut client)?;
        initial.expand_label(b"server in", &mut server)?;
        Ok(InitialSecrets {
            client: Secret(client),
            server: Secret(server),
        })
    }

    /// The secret `side` seals with.
    #[must_use]
    pub fn local(&self, side: Side) -> &Secret {
        match side {
            Side::Client => &self.client,
            Side::Server => &self.server,
        }
    }

    /// The secret `side` opens with.
    #[must_use]
    pub fn remote(&self, side: Side) -> &Secret {
        match side {
            Side::Client => &self.server,
            Side::Server => &self.client,
        }
    }
}

impl fmt::Debug for InitialSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InitialSecrets(..)")
    }
}

fn expand_label(secret: &[u8; 32], label: &[u8], out: &mut [u8]) -> Result<(), CryptoError> {
    const PREFIX: &[u8] = b"tls13 ";
    let len = out.len();
    if len > 255 * 32 || PREFIX.len() + label.len() > 255 {
        return Err(CryptoError);
    }
    // HkdfLabel: length (2 bytes), label (length-prefixed, with the
    // prefix), context (empty).
    let mut info = [0u8; 2 + 1 + 255 + 1];
    info[..2].copy_from_slice(&(len as u16).to_be_bytes());
    info[2] = (PREFIX.len() + label.len()) as u8;
    info[3..3 + PREFIX.len()].copy_from_slice(PREFIX);
    info[3 + PREFIX.len()..3 + PREFIX.len() + label.len()].copy_from_slice(label);
    let info = &info[..4 + PREFIX.len() + label.len()];
    // HKDF-Expand (RFC 5869 section 2.3).
    let mut t = [0u8; 32];
    let mut t_len = 0;
    let mut at = 0;
    let mut i = 1u8;
    while at < len {
        let mut h = HmacSha256::new(secret).map_err(|_| CryptoError)?;
        h.update(&t[..t_len]).update(info).update(&[i]);
        t = h.finalize();
        t_len = 32;
        let n = (len - at).min(32);
        out[at..at + n].copy_from_slice(&t[..n]);
        at += n;
        i = i.wrapping_add(1);
    }
    wipe(&mut t);
    Ok(())
}

/// AES-128-GCM under [`RETRY_KEY_V1`] and [`RETRY_NONCE_V1`], for the Retry
/// integrity tag.
pub trait RetryIntegrity {
    /// The tag of an empty plaintext with `pseudo_packet` as associated data.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the cipher fails.
    fn tag(&self, pseudo_packet: &[u8]) -> Result<[u8; 16], CryptoError>;
}

/// The Retry integrity tag (RFC 9001 section 5.8) of `retry`, a Retry packet
/// without its tag, answering a client whose first destination ID was
/// `original_dcid`. Pass it to [`write_retry`](crate::write_retry).
///
/// # Errors
///
/// [`CryptoError`] when the cipher fails.
pub fn retry_tag<A: RetryIntegrity + ?Sized>(
    original_dcid: &ConnectionId,
    retry: &[u8],
    aead: &A,
) -> Result<[u8; 16], CryptoError> {
    let mut pseudo = Vec::with_capacity(1 + original_dcid.len() + retry.len());
    pseudo.push(original_dcid.len() as u8);
    pseudo.extend_from_slice(original_dcid.as_slice());
    pseudo.extend_from_slice(retry);
    aead.tag(&pseudo)
}

/// Whether `packet`, a whole Retry packet, carries the right integrity tag
/// for `original_dcid`, the destination ID of the client's first Initial.
/// The tag is compared in constant time. A client discards a Retry that
/// fails (RFC 9001 section 5.8).
#[must_use]
pub fn verify_retry<A: RetryIntegrity + ?Sized>(
    original_dcid: &ConnectionId,
    packet: &[u8],
    aead: &A,
) -> bool {
    let Some(split) = packet.len().checked_sub(16) else {
        return false;
    };
    let (body, tag) = packet.split_at(split);
    let Ok(tag) = <&[u8; 16]>::try_from(tag) else {
        return false;
    };
    match retry_tag(original_dcid, body, aead) {
        Ok(expected) => ct_eq(&expected, tag),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A key that XORs with a fixed byte and tags with the sum of the
    /// header, so the framing can be tested without a cipher.
    struct Toy;

    impl PacketKey for Toy {
        fn seal(
            &self,
            pn: u64,
            header: &[u8],
            payload: &mut [u8],
        ) -> Result<[u8; 16], CryptoError> {
            for b in payload.iter_mut() {
                *b ^= 0x5a;
            }
            Ok(toy_tag(pn, header, payload))
        }
        fn open(
            &self,
            pn: u64,
            header: &[u8],
            payload_and_tag: &mut [u8],
        ) -> Result<usize, CryptoError> {
            let at = payload_and_tag.len().checked_sub(16).ok_or(CryptoError)?;
            let (payload, tag) = payload_and_tag.split_at_mut(at);
            if toy_tag(pn, header, payload) != *tag {
                return Err(CryptoError);
            }
            for b in payload.iter_mut() {
                *b ^= 0x5a;
            }
            Ok(at)
        }
        fn limits(&self) -> AeadLimits {
            AeadLimits::AES_GCM
        }
    }

    impl HeaderKey for Toy {
        fn mask(&self, sample: &[u8; 16]) -> Result<[u8; 5], CryptoError> {
            Ok([sample[0] ^ 0xff, sample[1], sample[2], sample[3], sample[4]])
        }
    }

    fn toy_tag(pn: u64, header: &[u8], ct: &[u8]) -> [u8; 16] {
        let mut t = [0u8; 16];
        t[..8].copy_from_slice(&pn.to_be_bytes());
        for (i, b) in header.iter().chain(ct).enumerate() {
            t[8 + i % 8] = t[8 + i % 8].wrapping_add(*b).rotate_left(1);
        }
        t
    }

    fn short(pn: u64, pn_len: usize, payload: &[u8]) -> (Vec<u8>, usize) {
        let dcid = ConnectionId::new(&[3; 8]).unwrap();
        let mut p = Vec::new();
        let at = crate::write_short(&mut p, &dcid, false, true, pn, pn_len);
        p.extend_from_slice(payload);
        p.extend_from_slice(&[0; TAG_LEN]);
        (p, at)
    }

    #[test]
    fn test_round_trip_for_each_packet_number_length() {
        for pn_len in 1..=4 {
            let pn = 0x0102_0304 & ((1u64 << (8 * pn_len)) - 1);
            let (mut p, at) = short(pn, pn_len, b"0123456789");
            let plain = p.clone();
            seal_packet(&mut p, at, pn, &Toy, &Toy).unwrap();
            assert_ne!(p, plain);
            let u = remove_header_protection(&mut p, at, pn.checked_sub(1), &Toy).unwrap();
            assert_eq!((u.pn, u.pn_len, u.key_phase), (pn, pn_len, true));
            let r = open_payload(&mut p, &u, &Toy).unwrap();
            assert_eq!(&p[r], b"0123456789");
            assert_eq!(p[..u.header_len()], plain[..u.header_len()]);
        }
    }

    #[test]
    fn test_short_packets_are_refused() {
        // 1 byte of packet number and 2 of payload: 3 short of the sample.
        let (mut p, at) = short(1, 1, b"ab");
        assert_eq!(
            seal_packet(&mut p, at, 1, &Toy, &Toy),
            Err(ProtectError::TooShort)
        );
        assert_eq!(
            remove_header_protection(&mut p, at, None, &Toy),
            Err(ProtectError::TooShort)
        );
        for at in [usize::MAX, usize::MAX - 4, usize::MAX - 19] {
            assert_eq!(
                remove_header_protection(&mut p, at, None, &Toy),
                Err(ProtectError::TooShort)
            );
            assert_eq!(
                seal_packet(&mut p, at, 1, &Toy, &Toy),
                Err(ProtectError::TooShort)
            );
        }
        let (mut p, at) = short(1, 1, b"abc");
        assert!(seal_packet(&mut p, at, 1, &Toy, &Toy).is_ok());
    }

    #[test]
    fn test_a_packet_number_the_header_does_not_hold_is_refused() {
        let (mut p, at) = short(0x1234, 2, b"payload");
        assert_eq!(
            seal_packet(&mut p, at, 0x1235, &Toy, &Toy),
            Err(ProtectError::PacketNumber)
        );
        assert!(seal_packet(&mut p, at, 0x9_1234, &Toy, &Toy).is_ok());
    }

    #[test]
    fn test_tampering_fails_authentication() {
        let (mut p, at) = short(7, 2, b"payload!");
        seal_packet(&mut p, at, 7, &Toy, &Toy).unwrap();
        for i in 0..p.len() {
            let mut q = p.clone();
            q[i] ^= 0x01;
            let r = remove_header_protection(&mut q, at, Some(6), &Toy)
                .and_then(|u| open_payload(&mut q, &u, &Toy));
            assert!(r.is_err(), "byte {i}");
        }
    }

    #[test]
    fn test_reserved_bits_are_checked_after_authentication() {
        let (mut p, at) = short(7, 2, b"payload!");
        p[0] |= 0x08;
        seal_packet(&mut p, at, 7, &Toy, &Toy).unwrap();
        let u = remove_header_protection(&mut p, at, Some(6), &Toy).unwrap();
        let e = open_payload(&mut p, &u, &Toy).unwrap_err();
        assert_eq!(e, ProtectError::ReservedBits);
        assert_eq!(e.code(), Some(TransportErrorCode::PROTOCOL_VIOLATION));
        assert_eq!(ProtectError::Authentication.code(), None);
    }

    #[test]
    fn test_usage_limits() {
        let mut u = AeadUsage::new(AeadLimits {
            confidentiality: 2,
            integrity: 3,
        });
        assert!(u.may_seal());
        u.sealed();
        u.sealed();
        assert!(!u.may_seal());
        assert_eq!(u.sealed_count(), 2);
        u.key_updated();
        assert!(u.may_seal());
        assert!(u.failed().is_ok());
        assert!(u.failed().is_ok());
        assert_eq!(u.failed(), Err(TransportErrorCode::AEAD_LIMIT_REACHED));
    }

    #[test]
    fn test_nonce() {
        // RFC 9001 appendix A.5.
        let iv = [
            0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x4a, 0x41, 0xc1, 0x44,
        ];
        let want = [
            0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x6d, 0x41, 0x7e, 0xb0,
        ];
        assert_eq!(nonce(&iv, 654_360_564), want);
    }

    #[test]
    fn test_expand_label_bounds() {
        let s = Secret::new([1; 32]);
        let mut big = vec![0u8; 255 * 32 + 1];
        assert_eq!(s.expand_label(b"x", &mut big), Err(CryptoError));
        assert!(s.expand_label(b"x", &mut big[..255 * 32]).is_ok());
        assert_eq!(s.expand_label(&[b'a'; 250], &mut [0; 4]), Err(CryptoError));
        assert!(s.expand_label(&[b'a'; 249], &mut [0; 4]).is_ok());
        assert!(s.key_material(24).is_err());
        assert_eq!(format!("{s:?}"), "Secret(..)");
    }
}
