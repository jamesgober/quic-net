//! Packet headers (RFC 9000 section 17), version negotiation, splitting a
//! datagram's coalesced packets (section 12.2), and packet number encoding
//! (appendix A).
//!
//! Headers are read before header protection is removed: the reserved bits,
//! the key phase, and the packet number length in the first byte, and the
//! packet number itself, are still protected. A parsed header says where the
//! packet number starts and where the packet ends; removing protection is the
//! packet protection layer's job (RFC 9001 section 5.4).

use crate::cid::{ConnectionId, MAX_CID_LEN};
use crate::error::DecodeError;
use crate::varint::{self, Reader};

/// QUIC version 1 (RFC 9000).
pub const VERSION_1: u32 = 1;

/// The smallest UDP payload of a datagram carrying a client's Initial
/// packet; a server discards smaller ones (RFC 9000 section 14.1).
pub const MIN_INITIAL_SIZE: usize = 1200;

/// The most packets read from one datagram. A datagram of 1,500 bytes holds
/// at most a few real ones (Initial, Handshake, and 1-RTT); the bound stops a
/// datagram of tiny packets from costing a parse each.
pub const MAX_COALESCED: usize = 8;

/// The bytes a protected packet needs from the packet number on: 4 for the
/// packet number's longest form and 16 for the header protection sample
/// (RFC 9001 section 5.4.2). A shorter packet cannot be unprotected.
pub const MIN_PROTECTED: usize = 20;

/// The type of a long header packet in version 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LongType {
    /// The client's first flight and the server's reply, with Initial keys.
    Initial,
    /// Early data under 0-RTT keys.
    ZeroRtt,
    /// The rest of the handshake, with Handshake keys.
    Handshake,
    /// A server's request that the client prove its address.
    Retry,
}

impl LongType {
    fn bits(self) -> u8 {
        match self {
            LongType::Initial => 0,
            LongType::ZeroRtt => 1,
            LongType::Handshake => 2,
            LongType::Retry => 3,
        }
    }
}

/// A packet header, read from a datagram before header protection is removed.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Header<'a> {
    /// A long header packet with a packet number: Initial, 0-RTT, or Handshake.
    Long {
        /// Its type (never `Retry` here).
        ty: LongType,
        /// The version (1).
        version: u32,
        /// The destination connection ID.
        dcid: ConnectionId,
        /// The source connection ID.
        scid: ConnectionId,
        /// The token (Initial packets only; empty otherwise).
        token: &'a [u8],
    },
    /// A Retry packet.
    Retry {
        /// The version (1).
        version: u32,
        /// The destination connection ID.
        dcid: ConnectionId,
        /// The source connection ID: the one the client must use next.
        scid: ConnectionId,
        /// The token the client must send back.
        token: &'a [u8],
        /// The Retry integrity tag (RFC 9001 section 5.8).
        integrity_tag: [u8; 16],
    },
    /// A short header (1-RTT) packet.
    Short {
        /// The destination connection ID.
        dcid: ConnectionId,
        /// The spin bit (not protected).
        spin: bool,
    },
    /// A version negotiation packet: the versions the server supports.
    VersionNegotiation {
        /// The destination connection ID (any length up to 255).
        dcid: &'a [u8],
        /// The source connection ID (any length up to 255).
        scid: &'a [u8],
        /// The versions, 4 bytes each; see [`Header::versions`].
        versions: &'a [u8],
    },
    /// A long header of a version this crate does not speak; a server
    /// answers with version negotiation. Its connection IDs may be up to 255
    /// bytes (RFC 8999 section 5.1).
    Unsupported {
        /// The version.
        version: u32,
        /// The destination connection ID.
        dcid: &'a [u8],
        /// The source connection ID.
        scid: &'a [u8],
    },
}

impl Header<'_> {
    /// The versions a version negotiation packet lists.
    pub fn versions(&self) -> impl Iterator<Item = u32> + '_ {
        let list: &[u8] = match self {
            Header::VersionNegotiation { versions, .. } => versions,
            _ => &[],
        };
        list.chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
    }
}

/// One packet of a datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    /// Its header.
    pub header: Header<'a>,
    /// Where the protected packet number starts, from the packet's first byte
    /// (0 for packets without one: Retry, version negotiation, unsupported).
    pub pn_offset: usize,
    /// The whole packet: its header, packet number, and payload.
    pub bytes: &'a [u8],
}

/// Reads the first packet of `datagram`. `short_dcid_len` is the length of
/// the connection IDs this endpoint issued, which a short header does not
/// carry.
///
/// # Errors
///
/// [`DecodeError`] for a malformed header: the fixed bit clear, a
/// connection ID over 20 bytes in version 1, a length past the datagram, a
/// packet too short to unprotect, a version negotiation list that is not
/// whole versions.
///
/// ```
/// use quic_net::{ConnectionId, Header, LongHeader, LongType, parse_packet};
/// let dcid = ConnectionId::new(&[1; 8])?;
/// let mut out = Vec::new();
/// let h = LongHeader { ty: LongType::Handshake, dcid, scid: ConnectionId::EMPTY, token: &[] };
/// let pn_offset = h.encode(&mut out, 0, 1, 40);
/// out.resize(pn_offset + 1 + 40, 0);
/// let p = parse_packet(&out, 8)?;
/// assert_eq!(p.pn_offset, pn_offset);
/// assert!(matches!(p.header, Header::Long { ty: LongType::Handshake, .. }));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_packet(datagram: &[u8], short_dcid_len: usize) -> Result<Packet<'_>, DecodeError> {
    let mut r = Reader::new(datagram);
    let first = r.u8()?;
    if first & 0x80 == 0 {
        // Short header: runs to the end of the datagram.
        if first & 0x40 == 0 {
            return Err(DecodeError::BadPacket);
        }
        if short_dcid_len > MAX_CID_LEN {
            return Err(DecodeError::ConnectionIdTooLong);
        }
        let dcid = cid(r.bytes(short_dcid_len)?)?;
        let pn_offset = r.position();
        if r.remaining() < MIN_PROTECTED {
            return Err(DecodeError::BadPacket);
        }
        return Ok(Packet {
            header: Header::Short {
                dcid,
                spin: first & 0x20 != 0,
            },
            pn_offset,
            bytes: datagram,
        });
    }
    let version = r.u32()?;
    let dcid_len = usize::from(r.u8()?);
    let dcid = r.bytes(dcid_len)?;
    let scid_len = usize::from(r.u8()?);
    let scid = r.bytes(scid_len)?;
    if version == 0 {
        let versions = r.rest();
        if versions.is_empty() || versions.len() % 4 != 0 {
            return Err(DecodeError::BadPacket);
        }
        return Ok(Packet {
            header: Header::VersionNegotiation {
                dcid,
                scid,
                versions,
            },
            pn_offset: 0,
            bytes: datagram,
        });
    }
    if version != VERSION_1 {
        return Ok(Packet {
            header: Header::Unsupported {
                version,
                dcid,
                scid,
            },
            pn_offset: 0,
            bytes: datagram,
        });
    }
    if first & 0x40 == 0 {
        return Err(DecodeError::BadPacket);
    }
    let (dcid, scid) = (cid(dcid)?, cid(scid)?);
    let ty = match (first >> 4) & 0x03 {
        0 => LongType::Initial,
        1 => LongType::ZeroRtt,
        2 => LongType::Handshake,
        _ => LongType::Retry,
    };
    if ty == LongType::Retry {
        let rest = r.rest();
        if rest.len() < 16 {
            return Err(DecodeError::BadPacket);
        }
        let (token, tag) = rest.split_at(rest.len() - 16);
        let mut integrity_tag = [0u8; 16];
        integrity_tag.copy_from_slice(tag);
        return Ok(Packet {
            header: Header::Retry {
                version,
                dcid,
                scid,
                token,
                integrity_tag,
            },
            pn_offset: 0,
            bytes: datagram,
        });
    }
    let token = if ty == LongType::Initial {
        let n = r.length()?;
        r.bytes(n)?
    } else {
        &[]
    };
    let length = r.length()?;
    if length < MIN_PROTECTED {
        return Err(DecodeError::BadPacket);
    }
    let pn_offset = r.position();
    let end = pn_offset + length;
    Ok(Packet {
        header: Header::Long {
            ty,
            version,
            dcid,
            scid,
            token,
        },
        pn_offset,
        bytes: &datagram[..end],
    })
}

fn cid(bytes: &[u8]) -> Result<ConnectionId, DecodeError> {
    ConnectionId::new(bytes).map_err(|_| DecodeError::ConnectionIdTooLong)
}

/// The packets of a datagram, in order (RFC 9000 section 12.2). Packets after
/// the first whose destination connection ID differs are not returned, as
/// the RFC asks; at most [`MAX_COALESCED`] are read. A short header packet
/// takes the rest of the datagram.
///
/// ```
/// use quic_net::{ConnectionId, LongHeader, LongType, coalesced};
/// let dcid = ConnectionId::new(&[7; 4])?;
/// let mut d = Vec::new();
/// for ty in [LongType::Initial, LongType::Handshake] {
///     let h = LongHeader { ty, dcid, scid: ConnectionId::EMPTY, token: &[] };
///     let start = d.len();
///     let at = h.encode(&mut d, 0, 1, 30);
///     d.resize(start + at + 31, 0);
/// }
/// let packets: Vec<_> = coalesced(&d, 4).collect();
/// assert_eq!(packets.len(), 2);
/// # Ok::<(), quic_net::CidError>(())
/// ```
pub fn coalesced(datagram: &[u8], short_dcid_len: usize) -> Coalesced<'_> {
    Coalesced {
        rest: datagram,
        short_dcid_len,
        first_dcid: None,
        count: 0,
    }
}

/// The iterator of [`coalesced`].
#[derive(Debug)]
pub struct Coalesced<'a> {
    rest: &'a [u8],
    short_dcid_len: usize,
    first_dcid: Option<ConnectionId>,
    count: usize,
}

impl<'a> Iterator for Coalesced<'a> {
    type Item = Result<Packet<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() || self.count == MAX_COALESCED {
            return None;
        }
        self.count += 1;
        let p = match parse_packet(self.rest, self.short_dcid_len) {
            Ok(p) => p,
            Err(e) => {
                self.rest = &[];
                return Some(Err(e));
            }
        };
        self.rest = &self.rest[p.bytes.len()..];
        let dcid = match &p.header {
            Header::Long { dcid, .. } | Header::Short { dcid, .. } | Header::Retry { dcid, .. } => {
                Some(*dcid)
            }
            _ => None,
        };
        match (self.first_dcid, dcid) {
            (None, d) => self.first_dcid = d,
            (Some(first), Some(d)) if first != d => {
                self.rest = &[];
                return None;
            }
            _ => {}
        }
        Some(Ok(p))
    }
}

/// A long header to write.
#[derive(Clone, Copy, Debug)]
pub struct LongHeader<'a> {
    /// Initial, 0-RTT, or Handshake (Retry has [`write_retry`]).
    pub ty: LongType,
    /// The destination connection ID.
    pub dcid: ConnectionId,
    /// The source connection ID.
    pub scid: ConnectionId,
    /// The token (Initial only).
    pub token: &'a [u8],
}

impl LongHeader<'_> {
    /// Writes the header for a version 1 packet with packet number `pn` on
    /// `pn_len` bytes (1 to 4) and `payload_len` bytes of protected payload
    /// (its AEAD tag included). Returns where the packet number starts; the
    /// caller appends the payload after it.
    pub fn encode(&self, out: &mut Vec<u8>, pn: u64, pn_len: usize, payload_len: usize) -> usize {
        let pn_len = pn_len.clamp(1, 4);
        let start = out.len();
        out.push(0xC0 | (self.ty.bits() << 4) | (pn_len as u8 - 1));
        out.extend_from_slice(&VERSION_1.to_be_bytes());
        out.push(self.dcid.len() as u8);
        out.extend_from_slice(self.dcid.as_slice());
        out.push(self.scid.len() as u8);
        out.extend_from_slice(self.scid.as_slice());
        if self.ty == LongType::Initial {
            varint::put(out, self.token.len() as u64);
            out.extend_from_slice(self.token);
        }
        varint::put(out, (pn_len + payload_len) as u64);
        let pn_offset = out.len() - start;
        put_pn(out, pn, pn_len);
        pn_offset
    }
}

/// Writes a short header with packet number `pn` on `pn_len` bytes (1 to 4).
/// Returns where the packet number starts.
pub fn write_short(
    out: &mut Vec<u8>,
    dcid: &ConnectionId,
    spin: bool,
    key_phase: bool,
    pn: u64,
    pn_len: usize,
) -> usize {
    let pn_len = pn_len.clamp(1, 4);
    let start = out.len();
    out.push(0x40 | (u8::from(spin) << 5) | (u8::from(key_phase) << 2) | (pn_len as u8 - 1));
    out.extend_from_slice(dcid.as_slice());
    let pn_offset = out.len() - start;
    put_pn(out, pn, pn_len);
    pn_offset
}

/// Writes a version negotiation packet answering a client's packet: `dcid`
/// is the client's source ID and `scid` its destination ID (RFC 9000 section
/// 17.2.1). `unused` fills the first byte's other bits, which should vary.
pub fn write_version_negotiation(
    out: &mut Vec<u8>,
    dcid: &[u8],
    scid: &[u8],
    versions: &[u32],
    unused: u8,
) {
    out.push(0x80 | (unused & 0x7F));
    out.extend_from_slice(&0u32.to_be_bytes());
    out.push(dcid.len().min(255) as u8);
    out.extend_from_slice(&dcid[..dcid.len().min(255)]);
    out.push(scid.len().min(255) as u8);
    out.extend_from_slice(&scid[..scid.len().min(255)]);
    for v in versions {
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// Writes a Retry packet with its integrity tag (which the caller computes,
/// RFC 9001 section 5.8). `unused` fills the first byte's low 4 bits.
pub fn write_retry(
    out: &mut Vec<u8>,
    dcid: &ConnectionId,
    scid: &ConnectionId,
    token: &[u8],
    integrity_tag: &[u8; 16],
    unused: u8,
) {
    out.push(0xC0 | (LongType::Retry.bits() << 4) | (unused & 0x0F));
    out.extend_from_slice(&VERSION_1.to_be_bytes());
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid.as_slice());
    out.push(scid.len() as u8);
    out.extend_from_slice(scid.as_slice());
    out.extend_from_slice(token);
    out.extend_from_slice(integrity_tag);
}

fn put_pn(out: &mut Vec<u8>, pn: u64, pn_len: usize) {
    let b = pn.to_be_bytes();
    out.extend_from_slice(&b[8 - pn_len..]);
}

/// How many bytes to send packet number `pn` on, given the largest one the
/// peer acknowledged: enough for twice the unacknowledged range (RFC 9000
/// section 17.1 and appendix A.2).
///
/// ```
/// assert_eq!(quic_net::packet_number_len(0xac5c02, Some(0xabe8b3)), 2);
/// assert_eq!(quic_net::packet_number_len(0xace8fe, Some(0xabe8b3)), 3);
/// ```
#[must_use]
pub fn packet_number_len(pn: u64, largest_acked: Option<u64>) -> usize {
    let unacked = match largest_acked {
        Some(l) => pn.saturating_sub(l),
        None => pn.saturating_add(1),
    };
    let bits = 64 - (unacked.saturating_mul(2)).leading_zeros() as usize;
    bits.div_ceil(8).clamp(1, 4)
}

/// Recovers a full packet number from its truncated form on `pn_len` bytes,
/// given the largest one received so far (RFC 9000 appendix A.3).
///
/// ```
/// assert_eq!(quic_net::decode_packet_number(Some(0xa82f30ea), 0x9b32, 2), 0xa82f9b32);
/// ```
#[must_use]
pub fn decode_packet_number(largest: Option<u64>, truncated: u64, pn_len: usize) -> u64 {
    let bits = (pn_len.clamp(1, 4) * 8) as u32;
    let expected = largest.map_or(0, |l| l + 1);
    let win = 1u64 << bits;
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | (truncated & mask);
    if candidate + hwin <= expected && candidate < (1 << 62) - win {
        candidate + win
    } else if candidate > expected + hwin && candidate >= win {
        candidate - win
    } else {
        candidate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(b: u8, n: usize) -> ConnectionId {
        ConnectionId::new(&vec![b; n]).unwrap()
    }

    #[test]
    fn long_headers_round_trip() {
        for ty in [LongType::Initial, LongType::ZeroRtt, LongType::Handshake] {
            for pn_len in 1..=4 {
                let h = LongHeader {
                    ty,
                    dcid: c(1, 8),
                    scid: c(2, 20),
                    token: if ty == LongType::Initial { b"tok" } else { &[] },
                };
                let mut out = Vec::new();
                let at = h.encode(&mut out, 0x1234_5678, pn_len, 50);
                out.resize(at + pn_len + 50, 0xEE);
                let p = parse_packet(&out, 8).unwrap();
                assert_eq!(p.pn_offset, at);
                assert_eq!(p.bytes.len(), out.len());
                let Header::Long {
                    ty: t,
                    dcid,
                    scid,
                    token,
                    ..
                } = p.header
                else {
                    panic!()
                };
                assert_eq!((t, dcid, scid), (ty, h.dcid, h.scid));
                assert_eq!(token, h.token);
                // The unprotected first byte carries the length.
                assert_eq!(usize::from(out[0] & 0x03) + 1, pn_len);
            }
        }
    }

    #[test]
    fn short_retry_and_negotiation() {
        let mut out = Vec::new();
        let at = write_short(&mut out, &c(3, 8), true, true, 7, 2);
        assert_eq!(at, 9);
        out.resize(at + 2 + 30, 0);
        let p = parse_packet(&out, 8).unwrap();
        assert_eq!(
            p.header,
            Header::Short {
                dcid: c(3, 8),
                spin: true
            }
        );
        assert_eq!(out[0] & 0x04, 0x04, "key phase");

        let mut r = Vec::new();
        write_retry(&mut r, &c(4, 8), &c(5, 8), b"retry-token", &[9; 16], 0xF);
        let p = parse_packet(&r, 8).unwrap();
        let Header::Retry {
            token,
            integrity_tag,
            ..
        } = p.header
        else {
            panic!()
        };
        assert_eq!(token, b"retry-token");
        assert_eq!(integrity_tag, [9; 16]);

        let mut v = Vec::new();
        write_version_negotiation(&mut v, &[1; 30], &[2; 3], &[1, 0x6b33_43cf], 0x55);
        let p = parse_packet(&v, 8).unwrap();
        assert_eq!(
            p.header.versions().collect::<Vec<_>>(),
            vec![1, 0x6b33_43cf]
        );
        assert!(matches!(p.header, Header::VersionNegotiation { dcid, .. } if dcid.len() == 30));
    }

    #[test]
    fn malformed_headers_are_refused() {
        // Every truncation of a valid Initial fails without panicking.
        let h = LongHeader {
            ty: LongType::Initial,
            dcid: c(1, 8),
            scid: c(2, 8),
            token: b"abc",
        };
        let mut out = Vec::new();
        let at = h.encode(&mut out, 1, 1, 40);
        out.resize(at + 41, 0);
        for cut in 0..out.len() {
            assert!(parse_packet(&out[..cut], 8).is_err(), "cut {cut}");
        }
        // The fixed bit clear.
        let mut bad = out.clone();
        bad[0] &= !0x40;
        assert_eq!(parse_packet(&bad, 8), Err(DecodeError::BadPacket));
        // A version 1 connection ID of 21 bytes.
        let mut long = vec![0xC0, 0, 0, 0, 1, 21];
        long.extend_from_slice(&[0; 21]);
        long.extend_from_slice(&[0, 0, 30]);
        long.resize(long.len() + 30, 0);
        assert_eq!(
            parse_packet(&long, 8),
            Err(DecodeError::ConnectionIdTooLong)
        );
        // An unknown version keeps long IDs (RFC 8999).
        long[4] = 2;
        assert!(matches!(
            parse_packet(&long, 8).unwrap().header,
            Header::Unsupported { version: 2, .. }
        ));
        // A version negotiation list that is not whole versions.
        let mut v = Vec::new();
        write_version_negotiation(&mut v, &[1], &[2], &[1], 0);
        v.pop();
        assert_eq!(parse_packet(&v, 8), Err(DecodeError::BadPacket));
        // A packet too short to sample for header protection.
        let mut short = Vec::new();
        let at = LongHeader {
            ty: LongType::Handshake,
            dcid: c(1, 4),
            scid: c(1, 4),
            token: &[],
        }
        .encode(&mut short, 0, 1, 10);
        short.resize(at + 11, 0);
        assert_eq!(parse_packet(&short, 4), Err(DecodeError::BadPacket));
    }

    #[test]
    fn coalesced_packets_stop_at_another_dcid_and_the_budget() {
        let mut d = Vec::new();
        for (ty, id) in [
            (LongType::Initial, 1),
            (LongType::Handshake, 1),
            (LongType::Handshake, 2),
        ] {
            let start = d.len();
            let at = LongHeader {
                ty,
                dcid: c(id, 4),
                scid: c(0, 4),
                token: &[],
            }
            .encode(&mut d, 0, 1, 25);
            d.resize(start + at + 26, 0);
        }
        assert_eq!(coalesced(&d, 4).count(), 2);
        let mut many = Vec::new();
        for _ in 0..20 {
            let start = many.len();
            let at = LongHeader {
                ty: LongType::Handshake,
                dcid: c(1, 4),
                scid: c(0, 4),
                token: &[],
            }
            .encode(&mut many, 0, 1, 20);
            many.resize(start + at + 21, 0);
        }
        assert_eq!(coalesced(&many, 4).count(), MAX_COALESCED);
        // An error ends the datagram.
        let mut broken = d[..30].to_vec();
        broken.push(0);
        let items: Vec<_> = coalesced(&broken, 4).collect();
        assert!(items.last().unwrap().is_err());
    }

    #[test]
    fn packet_numbers() {
        // RFC 9000 appendix A.
        assert_eq!(
            decode_packet_number(Some(0xa82f30ea), 0x9b32, 2),
            0xa82f9b32
        );
        assert_eq!(packet_number_len(0xac5c02, Some(0xabe8b3)), 2);
        assert_eq!(packet_number_len(0xace8fe, Some(0xabe8b3)), 3);
        assert_eq!(packet_number_len(0, None), 1);
        // Round trips across the window.
        for largest in [0u64, 100, 0xFFFF, 0x1_0000_0000] {
            for delta in [1u64, 2, 100, 200, 30_000] {
                let pn = largest + delta;
                let len = packet_number_len(pn, Some(largest));
                let truncated = pn & ((1u64 << (len * 8)) - 1);
                assert_eq!(decode_packet_number(Some(largest), truncated, len), pn);
            }
        }
    }
}
