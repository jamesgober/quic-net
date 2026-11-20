//! Address validation (RFC 9000 section 8): Retry and `NEW_TOKEN` tokens,
//! and the anti-amplification limit before an address is validated.
//!
//! Tokens are sealed with XChaCha20-Poly1305 through crypt-io: the contents
//! are hidden as well as authenticated, because a `NEW_TOKEN` token travels
//! in clear in a later connection's Initial packets and must not let an
//! observer link that connection to the one that issued it (section 8.1.3).
//! The 192-bit random nonce means one key can seal tokens for as long as it
//! is in use without a nonce ever repeating.

use core::fmt;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use crypt_io::{Crypt, KeyedCrypt};

use crate::cid::{ConnectionId, MAX_CID_LEN};
use crate::error::TransportErrorCode;
use crate::protect::CryptoError;

/// The longest token [`Tokens::check`] decrypts; anything longer is not one
/// of ours. Ours are at most 111 bytes: a kind and a key ID, the 24-byte
/// nonce, up to 69 bytes of fields, and the 16-byte tag.
pub const MAX_TOKEN_LEN: usize = 160;

const RETRY: u8 = 0x52;
const NEW_TOKEN: u8 = 0x4e;
const AAD: &[u8] = b"quic-net address token v1";
/// A token issued up to this far in the future is accepted, for clocks that
/// step back a little between issuing and checking.
const SKEW: u64 = 2;

/// What a token in a client's Initial says.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenCheck {
    /// A valid Retry token for this address: the address is validated. The
    /// packet's destination ID must be `retry_scid`, and the transport
    /// parameters must carry `original_dcid` and `retry_scid` (RFC 9000
    /// section 7.3).
    Retry {
        /// The destination ID of the client's first Initial.
        original_dcid: ConnectionId,
        /// The source ID of the Retry.
        retry_scid: ConnectionId,
    },
    /// A valid `NEW_TOKEN` token for this address: the address is validated.
    NewToken,
    /// A token our Retry issued that is no longer valid (expired, another
    /// address, altered). Close with [`TokenCheck::code`]: the client will
    /// not accept a second Retry (section 8.1.2).
    InvalidRetry,
    /// Not usable: treat the Initial as if it had no token (section 8.1.3).
    Unusable,
}

impl TokenCheck {
    /// `INVALID_TOKEN` for [`TokenCheck::InvalidRetry`].
    #[must_use]
    pub fn code(&self) -> Option<TransportErrorCode> {
        match self {
            TokenCheck::InvalidRetry => Some(TransportErrorCode::INVALID_TOKEN),
            _ => None,
        }
    }

    /// Whether the token validates the client's address.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, TokenCheck::Retry { .. } | TokenCheck::NewToken)
    }
}

struct TokenKey {
    id: u8,
    aead: KeyedCrypt,
}

impl TokenKey {
    fn new(id: u8, mut key: [u8; 32]) -> Result<TokenKey, CryptoError> {
        let aead = Crypt::xchacha20_poly1305().keyed(&key);
        key.fill(0);
        std::hint::black_box(&key);
        Ok(TokenKey {
            id,
            aead: aead.map_err(|_| CryptoError)?,
        })
    }
}

/// Issues and checks address validation tokens under a secret key, with
/// one previous key kept after a rotation so tokens issued just before it
/// still validate.
///
/// The key must be secret and should differ from the stateless reset key.
/// Anyone holding it can make tokens that skip address validation.
///
/// ```
/// use std::time::Duration;
/// use quic_net::{ConnectionId, TokenCheck, Tokens};
/// let tokens = Tokens::new([7; 32])?;
/// let client = "192.0.2.1:4433".parse().unwrap();
/// let odcid = ConnectionId::new(&[1; 8])?;
/// let scid = ConnectionId::new(&[2; 8])?;
/// let now = Duration::from_secs(1_800_000_000);
/// let token = tokens.retry_token(client, &odcid, &scid, now)?;
/// assert_eq!(
///     tokens.check(&token, client, now + Duration::from_secs(1)),
///     TokenCheck::Retry { original_dcid: odcid, retry_scid: scid },
/// );
/// let elsewhere = "192.0.2.2:4433".parse().unwrap();
/// assert_eq!(tokens.check(&token, elsewhere, now), TokenCheck::InvalidRetry);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct Tokens {
    current: TokenKey,
    previous: Option<TokenKey>,
    retry_lifetime: u64,
    new_token_lifetime: u64,
}

impl Tokens {
    /// Tokens under `key`. A Retry token is valid for 10 seconds (enough
    /// for one round trip), a `NEW_TOKEN` token for 24 hours.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the cipher cannot be set up.
    pub fn new(key: [u8; 32]) -> Result<Tokens, CryptoError> {
        Ok(Tokens {
            current: TokenKey::new(0, key)?,
            previous: None,
            retry_lifetime: 10,
            new_token_lifetime: 24 * 60 * 60,
        })
    }

    /// How long a Retry token stays valid, in whole seconds (at least 1).
    #[must_use]
    pub fn retry_lifetime(mut self, d: Duration) -> Tokens {
        self.retry_lifetime = d.as_secs().max(1);
        self
    }

    /// How long a `NEW_TOKEN` token stays valid, in whole seconds (at least
    /// 1).
    #[must_use]
    pub fn new_token_lifetime(mut self, d: Duration) -> Tokens {
        self.new_token_lifetime = d.as_secs().max(1);
        self
    }

    /// Moves to a new key. Tokens under the current key stay valid until
    /// the next rotation; older ones stop validating.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the cipher cannot be set up; the keys are then
    /// unchanged.
    pub fn rotate(&mut self, key: [u8; 32]) -> Result<(), CryptoError> {
        let next = TokenKey::new(self.current.id.wrapping_add(1), key)?;
        self.previous = Some(core::mem::replace(&mut self.current, next));
        Ok(())
    }

    /// A token for a Retry answering `client`, whose first Initial was sent
    /// to `original_dcid`, telling it to use `retry_scid`. `now` is the
    /// time since the Unix epoch.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the random source or the cipher fails.
    pub fn retry_token(
        &self,
        client: SocketAddr,
        original_dcid: &ConnectionId,
        retry_scid: &ConnectionId,
        now: Duration,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut plain = Vec::with_capacity(80);
        plain.extend_from_slice(&now.as_secs().to_be_bytes());
        put_ip(&mut plain, client.ip());
        plain.extend_from_slice(&client.port().to_be_bytes());
        for cid in [original_dcid, retry_scid] {
            plain.push(cid.len() as u8);
            plain.extend_from_slice(cid.as_slice());
        }
        self.seal(RETRY, &plain)
    }

    /// A token for a `NEW_TOKEN` frame to `client`, for its next
    /// connection. Bound to the client's IP address only: its port is new
    /// on every connection.
    ///
    /// # Errors
    ///
    /// [`CryptoError`] when the random source or the cipher fails.
    pub fn new_token(&self, client: IpAddr, now: Duration) -> Result<Vec<u8>, CryptoError> {
        let mut plain = Vec::with_capacity(32);
        plain.extend_from_slice(&now.as_secs().to_be_bytes());
        put_ip(&mut plain, client);
        self.seal(NEW_TOKEN, &plain)
    }

    fn seal(&self, kind: u8, plain: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut sealed = Vec::new();
        self.current
            .aead
            .encrypt_with_aad_into(plain, &aad(kind, self.current.id), &mut sealed)
            .map_err(|_| CryptoError)?;
        let mut token = Vec::with_capacity(2 + sealed.len());
        token.push(kind);
        token.push(self.current.id);
        token.extend_from_slice(&sealed);
        Ok(token)
    }

    /// Checks the token of an Initial from `client` at `now`. Never fails:
    /// anything that is not a valid token of ours says what to do with it.
    #[must_use]
    pub fn check(&self, token: &[u8], client: SocketAddr, now: Duration) -> TokenCheck {
        let (kind, id, sealed) = match token {
            [kind, id, sealed @ ..] if token.len() <= MAX_TOKEN_LEN => (*kind, *id, sealed),
            _ => return TokenCheck::Unusable,
        };
        let invalid = if kind == RETRY {
            TokenCheck::InvalidRetry
        } else {
            TokenCheck::Unusable
        };
        if kind != RETRY && kind != NEW_TOKEN {
            return TokenCheck::Unusable;
        }
        let key = if id == self.current.id {
            &self.current
        } else {
            match &self.previous {
                Some(p) if p.id == id => p,
                _ => return invalid,
            }
        };
        let Ok(plain) = key.aead.decrypt_with_aad(sealed, &aad(kind, id)) else {
            return invalid;
        };
        let mut r = Fields(&plain);
        let Some(issued) = r.u64() else {
            return invalid;
        };
        let lifetime = if kind == RETRY {
            self.retry_lifetime
        } else {
            self.new_token_lifetime
        };
        let now = now.as_secs();
        if issued > now.saturating_add(SKEW) || now.saturating_sub(issued) > lifetime {
            return invalid;
        }
        if r.ip() != Some(client.ip()) {
            return invalid;
        }
        if kind == NEW_TOKEN {
            return if r.is_empty() {
                TokenCheck::NewToken
            } else {
                invalid
            };
        }
        let port = r.u16();
        let odcid = r.cid();
        let scid = r.cid();
        match (port, odcid, scid) {
            (Some(p), Some(o), Some(s)) if p == client.port() && r.is_empty() => {
                TokenCheck::Retry {
                    original_dcid: o,
                    retry_scid: s,
                }
            }
            _ => invalid,
        }
    }
}

impl fmt::Debug for Tokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tokens")
            .field("key_id", &self.current.id)
            .field("retry_lifetime", &self.retry_lifetime)
            .field("new_token_lifetime", &self.new_token_lifetime)
            .finish_non_exhaustive()
    }
}

fn aad(kind: u8, id: u8) -> [u8; 27] {
    let mut a = [0u8; 27];
    a[..AAD.len()].copy_from_slice(AAD);
    a[AAD.len()] = kind;
    a[AAD.len() + 1] = id;
    a
}

fn put_ip(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// Reads a token's decrypted fields.
struct Fields<'a>(&'a [u8]);

impl Fields<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }

    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_be_bytes)
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map(u16::from_be_bytes)
    }

    fn ip(&mut self) -> Option<IpAddr> {
        let family = *self.take(1)?.first()?;
        match family {
            4 => <[u8; 4]>::try_from(self.take(4)?).ok().map(IpAddr::from),
            6 => <[u8; 16]>::try_from(self.take(16)?).ok().map(IpAddr::from),
            _ => None,
        }
    }

    fn cid(&mut self) -> Option<ConnectionId> {
        let len = usize::from(*self.take(1)?.first()?);
        if len > MAX_CID_LEN {
            return None;
        }
        ConnectionId::new(self.take(len)?).ok()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The anti-amplification limit of one path (RFC 9000 section 8): until the
/// peer's address is validated, a server sends at most three times the
/// bytes it received on the path. Every datagram attributed to the
/// connection counts, including ones whose packets were all dropped.
///
/// ```
/// use quic_net::Amplification;
/// let mut a = Amplification::new();
/// a.on_received(1200);
/// assert_eq!(a.allowance(), 3600);
/// a.on_sent(3600);
/// assert!(a.is_blocked()); // wait for the client to send more
/// a.validate(); // e.g. a Handshake packet arrived, or a valid token
/// assert_eq!(a.allowance(), u64::MAX);
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct Amplification {
    received: u64,
    sent: u64,
    validated: bool,
}

impl Amplification {
    /// A path whose address is not validated yet (a server's view of a new
    /// client).
    #[must_use]
    pub fn new() -> Amplification {
        Amplification::default()
    }

    /// A path whose address needs no validation: a client's view of the
    /// server it chose.
    #[must_use]
    pub fn validated() -> Amplification {
        Amplification {
            validated: true,
            ..Amplification::default()
        }
    }

    /// A datagram of `len` bytes arrived on the path.
    pub fn on_received(&mut self, len: usize) {
        self.received = self.received.saturating_add(len as u64);
    }

    /// A datagram of `len` bytes was sent on the path.
    pub fn on_sent(&mut self, len: usize) {
        self.sent = self.sent.saturating_add(len as u64);
    }

    /// Bytes that may still be sent: unlimited once validated.
    #[must_use]
    pub fn allowance(&self) -> u64 {
        if self.validated {
            u64::MAX
        } else {
            self.received.saturating_mul(3).saturating_sub(self.sent)
        }
    }

    /// Whether nothing may be sent until the peer sends more. The peer
    /// does: a client keeps sending until it knows its address is validated
    /// (RFC 9000 section 8.2.2's anti-deadlock rule).
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.allowance() == 0
    }

    /// The address is validated: a Handshake packet from the peer was
    /// opened, a token checked out, or a path challenge answered.
    pub fn validate(&mut self) {
        self.validated = true;
    }

    /// Whether the address is validated.
    #[must_use]
    pub fn is_validated(&self) -> bool {
        self.validated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(b: u8, n: usize) -> ConnectionId {
        ConnectionId::new(&vec![b; n]).unwrap()
    }

    const T0: Duration = Duration::from_secs(1_800_000_000);

    #[test]
    fn test_retry_tokens() {
        let t = Tokens::new([1; 32]).unwrap();
        let client: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let tok = t.retry_token(client, &cid(1, 20), &cid(2, 0), T0).unwrap();
        assert!(tok.len() <= MAX_TOKEN_LEN, "{}", tok.len());
        let ok = TokenCheck::Retry {
            original_dcid: cid(1, 20),
            retry_scid: cid(2, 0),
        };
        assert_eq!(t.check(&tok, client, T0), ok);
        assert_eq!(t.check(&tok, client, T0 + Duration::from_secs(10)), ok);
        assert_eq!(
            t.check(&tok, client, T0 + Duration::from_secs(11)),
            TokenCheck::InvalidRetry
        );
        // Another port, another address.
        let other_port: SocketAddr = "[2001:db8::1]:444".parse().unwrap();
        assert_eq!(t.check(&tok, other_port, T0), TokenCheck::InvalidRetry);
        let v4: SocketAddr = "192.0.2.1:443".parse().unwrap();
        assert_eq!(t.check(&tok, v4, T0), TokenCheck::InvalidRetry);
        // Issued in the future beyond the skew allowed.
        assert_eq!(
            t.check(&tok, client, T0 - Duration::from_secs(3)),
            TokenCheck::InvalidRetry
        );
        assert_eq!(t.check(&tok, client, T0 - Duration::from_secs(2)), ok);
        assert_eq!(
            TokenCheck::InvalidRetry.code(),
            Some(TransportErrorCode::INVALID_TOKEN)
        );
        // Two tokens for the same inputs differ (fresh nonces).
        let again = t.retry_token(client, &cid(1, 20), &cid(2, 0), T0).unwrap();
        assert_ne!(tok, again);
    }

    #[test]
    fn test_new_tokens_bind_the_ip_only() {
        let t = Tokens::new([1; 32]).unwrap();
        let tok = t.new_token("192.0.2.9".parse().unwrap(), T0).unwrap();
        for port in [1, 443, 65535] {
            let a = SocketAddr::from(([192, 0, 2, 9], port));
            assert_eq!(t.check(&tok, a, T0), TokenCheck::NewToken);
        }
        let a: SocketAddr = "192.0.2.10:1".parse().unwrap();
        assert_eq!(t.check(&tok, a, T0), TokenCheck::Unusable);
        let late = T0 + Duration::from_secs(24 * 3600 + 1);
        let here: SocketAddr = "192.0.2.9:1".parse().unwrap();
        assert_eq!(t.check(&tok, here, late), TokenCheck::Unusable);
        assert!(TokenCheck::NewToken.is_valid() && TokenCheck::NewToken.code().is_none());
    }

    #[test]
    fn test_any_change_is_refused() {
        let t = Tokens::new([1; 32]).unwrap();
        let client: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let tok = t.retry_token(client, &cid(1, 8), &cid(2, 8), T0).unwrap();
        for i in 0..tok.len() {
            let mut bad = tok.clone();
            bad[i] ^= 0x01;
            assert!(!t.check(&bad, client, T0).is_valid(), "byte {i}");
        }
        // A Retry token is never taken for a NEW_TOKEN one, and back.
        let mut swapped = tok.clone();
        swapped[0] = NEW_TOKEN;
        assert_eq!(t.check(&swapped, client, T0), TokenCheck::Unusable);
        let nt = t.new_token(client.ip(), T0).unwrap();
        let mut swapped = nt.clone();
        swapped[0] = RETRY;
        assert_eq!(t.check(&swapped, client, T0), TokenCheck::InvalidRetry);
        // Short, long, empty, and foreign tokens.
        assert_eq!(t.check(&[], client, T0), TokenCheck::Unusable);
        assert_eq!(t.check(&[RETRY], client, T0), TokenCheck::Unusable);
        assert_eq!(t.check(&[RETRY, 0], client, T0), TokenCheck::InvalidRetry);
        assert_eq!(t.check(&[0xff; 40], client, T0), TokenCheck::Unusable);
        let mut long = tok.clone();
        long.resize(MAX_TOKEN_LEN + 1, 0);
        assert_eq!(t.check(&long, client, T0), TokenCheck::Unusable);
        // Another key.
        let other = Tokens::new([2; 32]).unwrap();
        assert_eq!(other.check(&tok, client, T0), TokenCheck::InvalidRetry);
    }

    #[test]
    fn test_rotation_keeps_one_previous_key() {
        let mut t = Tokens::new([1; 32]).unwrap();
        let client: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let first = t.new_token(client.ip(), T0).unwrap();
        t.rotate([2; 32]).unwrap();
        let second = t.new_token(client.ip(), T0).unwrap();
        assert_eq!(t.check(&first, client, T0), TokenCheck::NewToken);
        assert_eq!(t.check(&second, client, T0), TokenCheck::NewToken);
        t.rotate([3; 32]).unwrap();
        assert_eq!(t.check(&first, client, T0), TokenCheck::Unusable);
        assert_eq!(t.check(&second, client, T0), TokenCheck::NewToken);
        assert!(format!("{t:?}").contains("key_id: 2"));
    }

    #[test]
    fn test_lifetimes() {
        let t = Tokens::new([1; 32])
            .unwrap()
            .retry_lifetime(Duration::from_millis(1))
            .new_token_lifetime(Duration::from_secs(60));
        let client: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let r = t.retry_token(client, &cid(1, 8), &cid(2, 8), T0).unwrap();
        assert!(t.check(&r, client, T0 + Duration::from_secs(1)).is_valid());
        assert!(!t.check(&r, client, T0 + Duration::from_secs(2)).is_valid());
        let n = t.new_token(client.ip(), T0).unwrap();
        assert!(t.check(&n, client, T0 + Duration::from_secs(60)).is_valid());
        assert!(!t.check(&n, client, T0 + Duration::from_secs(61)).is_valid());
    }

    #[test]
    fn test_amplification() {
        let mut a = Amplification::new();
        assert!(a.is_blocked());
        a.on_received(100);
        a.on_sent(250);
        assert_eq!(a.allowance(), 50);
        a.on_sent(100);
        assert_eq!(a.allowance(), 0);
        a.on_received(usize::MAX);
        assert!(!a.is_blocked());
        assert!(!a.is_validated());
        let v = Amplification::validated();
        assert!(v.is_validated() && !v.is_blocked());
    }
}
