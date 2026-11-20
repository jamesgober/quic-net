//! Connection IDs, stateless reset tokens, and the bookkeeping of the IDs
//! each side has issued and been given (RFC 9000 sections 5.1, 10.3, 19.15,
//! and 19.16).

use std::collections::BTreeMap;
use std::fmt;

use crate::error::TransportErrorCode;

/// The longest connection ID in QUIC version 1.
pub const MAX_CID_LEN: usize = 20;

/// The shortest datagram that can be a stateless reset: a short header's
/// first byte, room for a connection ID and packet number, and the token
/// (RFC 9000 section 10.3: anything shorter is not one).
pub const MIN_STATELESS_RESET: usize = 21;

/// A connection ID: 0 to 20 bytes.
///
/// ```
/// let cid = quic_net::ConnectionId::new(&[1, 2, 3])?;
/// assert_eq!(cid.as_slice(), &[1, 2, 3]);
/// assert!(quic_net::ConnectionId::new(&[0; 21]).is_err());
/// # Ok::<(), quic_net::CidError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnectionId {
    len: u8,
    bytes: [u8; MAX_CID_LEN],
}

/// A connection ID over 20 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CidError;

impl fmt::Display for CidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a connection ID is longer than 20 bytes")
    }
}

impl std::error::Error for CidError {}

impl ConnectionId {
    /// The empty connection ID.
    pub const EMPTY: ConnectionId = ConnectionId {
        len: 0,
        bytes: [0; MAX_CID_LEN],
    };

    /// A connection ID of these bytes.
    ///
    /// # Errors
    ///
    /// [`CidError`] past 20 bytes.
    pub fn new(bytes: &[u8]) -> Result<ConnectionId, CidError> {
        if bytes.len() > MAX_CID_LEN {
            return Err(CidError);
        }
        let mut b = [0u8; MAX_CID_LEN];
        b[..bytes.len()].copy_from_slice(bytes);
        Ok(ConnectionId {
            len: bytes.len() as u8,
            bytes: b,
        })
    }

    /// The bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The length.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Whether it is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectionId(")?;
        for b in self.as_slice() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// A stateless reset token: 16 bytes that let the holder of a connection ID
/// end the connection without its state. Compared in constant time; its
/// `Debug` output never shows it.
///
/// ```
/// let t = quic_net::ResetToken::new([7; 16]);
/// assert_eq!(t, quic_net::ResetToken::new([7; 16]));
/// assert_eq!(format!("{t:?}"), "ResetToken(..)");
/// ```
#[derive(Clone, Copy, Eq)]
pub struct ResetToken([u8; 16]);

impl ResetToken {
    /// A token of these bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> ResetToken {
        ResetToken(bytes)
    }

    /// The bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl PartialEq for ResetToken {
    fn eq(&self, other: &ResetToken) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl std::hash::Hash for ResetToken {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl fmt::Debug for ResetToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResetToken(..)")
    }
}

/// Equality without an early exit, so the time taken says nothing about
/// where two tokens differ.
fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut d = 0u8;
    for i in 0..16 {
        d |= a[i] ^ b[i];
    }
    std::hint::black_box(d) == 0
}

/// The key stateless reset tokens are derived from: a token is the keyed
/// BLAKE3 of the connection ID, cut to 16 bytes, so a server that lost its
/// state can still compute the token for any ID it issued (RFC 9000 section
/// 10.3.2). The key must be secret and stable across restarts; anyone who
/// has it can end the server's connections.
///
/// ```
/// use quic_net::{ConnectionId, ResetKey};
/// let key = ResetKey::new([42; 32]);
/// let cid = ConnectionId::new(&[1, 2, 3, 4])?;
/// assert_eq!(key.token(&cid), key.token(&cid));
/// assert_ne!(key.token(&cid), ResetKey::new([43; 32]).token(&cid));
/// # Ok::<(), quic_net::CidError>(())
/// ```
pub struct ResetKey([u8; 32]);

impl ResetKey {
    /// A key of these bytes.
    #[must_use]
    pub fn new(key: [u8; 32]) -> ResetKey {
        ResetKey(key)
    }

    /// The token for `cid`.
    #[must_use]
    pub fn token(&self, cid: &ConnectionId) -> ResetToken {
        let mac = crypt_io::mac::blake3_keyed(&self.0, cid.as_slice());
        let mut t = [0u8; 16];
        t.copy_from_slice(&mac[..16]);
        ResetToken(t)
    }
}

impl Drop for ResetKey {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

impl fmt::Debug for ResetKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResetKey(..)")
    }
}

/// Whether `datagram` is a stateless reset for one of `tokens`: at least 21
/// bytes, its last 16 equal to a token. Every token is compared, in constant
/// time, so the time taken says nothing about which one matched.
///
/// ```
/// use quic_net::{is_stateless_reset, ResetToken};
/// let token = ResetToken::new([9; 16]);
/// let mut datagram = vec![0x40; 30];
/// datagram[14..].copy_from_slice(token.as_bytes());
/// assert!(is_stateless_reset(&datagram, [&token]));
/// assert!(!is_stateless_reset(&datagram[10..], [&token]), "under 21 bytes");
/// ```
pub fn is_stateless_reset<'t>(
    datagram: &[u8],
    tokens: impl IntoIterator<Item = &'t ResetToken>,
) -> bool {
    if datagram.len() < MIN_STATELESS_RESET {
        return false;
    }
    let mut tail = [0u8; 16];
    tail.copy_from_slice(&datagram[datagram.len() - 16..]);
    let mut found = false;
    for t in tokens {
        found |= ct_eq(&tail, &t.0);
    }
    found
}

/// One connection ID the peer gave us.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCid {
    /// Its sequence number.
    pub sequence: u64,
    /// The ID.
    pub cid: ConnectionId,
    /// Its stateless reset token (none for the handshake's first ID unless
    /// the server's transport parameters carried one).
    pub reset_token: Option<ResetToken>,
}

/// The connection IDs the peer has given us to use (in NEW_CONNECTION_ID
/// frames), bounded by the `active_connection_id_limit` we advertised
/// (RFC 9000 section 5.1.1).
///
/// ```
/// use quic_net::{ConnectionId, PeerCids, ResetToken};
/// let mut ids = PeerCids::new(ConnectionId::new(&[0])?, 2);
/// let retire = ids.on_new_connection_id(1, 0, ConnectionId::new(&[1])?, ResetToken::new([1; 16])).unwrap();
/// assert!(retire.is_empty());
/// // Retiring everything before 1: sequence 0 must be retired.
/// let retire = ids.on_new_connection_id(2, 1, ConnectionId::new(&[2])?, ResetToken::new([2; 16])).unwrap();
/// assert_eq!(retire, vec![0]);
/// # Ok::<(), quic_net::CidError>(())
/// ```
#[derive(Debug)]
pub struct PeerCids {
    active: BTreeMap<u64, PeerCid>,
    limit: u64,
    retire_prior_to: u64,
    /// Sequence numbers we must send RETIRE_CONNECTION_ID for and have not.
    pending_retire: Vec<u64>,
}

impl PeerCids {
    /// Starts with the ID the peer used during the handshake (sequence 0)
    /// and the limit we advertised (at least 2).
    #[must_use]
    pub fn new(initial: ConnectionId, limit: u64) -> PeerCids {
        let mut active = BTreeMap::new();
        active.insert(
            0,
            PeerCid {
                sequence: 0,
                cid: initial,
                reset_token: None,
            },
        );
        PeerCids {
            active,
            limit: limit.max(2),
            retire_prior_to: 0,
            pending_retire: Vec::new(),
        }
    }

    /// Records the reset token of sequence 0, from the server's transport
    /// parameters.
    pub fn set_initial_token(&mut self, token: ResetToken) {
        if let Some(c) = self.active.get_mut(&0) {
            c.reset_token = Some(token);
        }
    }

    /// Takes a NEW_CONNECTION_ID frame. Returns the sequence numbers now to
    /// retire (send RETIRE_CONNECTION_ID for each).
    ///
    /// # Errors
    ///
    /// `FRAME_ENCODING_ERROR` when `retire_prior_to` is past `sequence`;
    /// `PROTOCOL_VIOLATION` when a sequence number comes back with another
    /// ID or token, or an ID with another sequence number;
    /// `CONNECTION_ID_LIMIT_ERROR` when more are active than our limit, or
    /// more retirements wait than it allows.
    pub fn on_new_connection_id(
        &mut self,
        sequence: u64,
        retire_prior_to: u64,
        cid: ConnectionId,
        token: ResetToken,
    ) -> Result<Vec<u64>, TransportErrorCode> {
        if retire_prior_to > sequence {
            return Err(TransportErrorCode::FRAME_ENCODING_ERROR);
        }
        if cid.is_empty() {
            return Err(TransportErrorCode::PROTOCOL_VIOLATION);
        }
        if let Some(existing) = self.active.get(&sequence) {
            // A repeat is fine; a contradiction is not.
            if existing.cid != cid || existing.reset_token != Some(token) {
                return Err(TransportErrorCode::PROTOCOL_VIOLATION);
            }
        } else if self
            .active
            .values()
            .any(|c| c.cid == cid && c.sequence != sequence)
        {
            return Err(TransportErrorCode::PROTOCOL_VIOLATION);
        }
        let mut retire = Vec::new();
        if sequence < self.retire_prior_to {
            // Already retired by an earlier frame: retire it at once.
            retire.push(sequence);
        } else {
            self.active.insert(
                sequence,
                PeerCid {
                    sequence,
                    cid,
                    reset_token: Some(token),
                },
            );
        }
        if retire_prior_to > self.retire_prior_to {
            self.retire_prior_to = retire_prior_to;
            let old: Vec<u64> = self
                .active
                .range(..retire_prior_to)
                .map(|(&s, _)| s)
                .collect();
            for s in old {
                self.active.remove(&s);
                retire.push(s);
            }
        }
        if self.active.len() as u64 > self.limit {
            return Err(TransportErrorCode::CONNECTION_ID_LIMIT_ERROR);
        }
        self.pending_retire.extend_from_slice(&retire);
        // A peer that makes us retire faster than we can send the frames
        // grows this list; past twice the limit it is refused.
        if self.pending_retire.len() as u64 > 2 * self.limit {
            return Err(TransportErrorCode::CONNECTION_ID_LIMIT_ERROR);
        }
        Ok(retire)
    }

    /// Marks a retirement as sent.
    pub fn retirement_sent(&mut self, sequence: u64) {
        self.pending_retire.retain(|&s| s != sequence);
    }

    /// The IDs we may use, lowest sequence first.
    pub fn active(&self) -> impl Iterator<Item = &PeerCid> {
        self.active.values()
    }

    /// The tokens of the active IDs, for [`is_stateless_reset`].
    pub fn reset_tokens(&self) -> impl Iterator<Item = &ResetToken> {
        self.active.values().filter_map(|c| c.reset_token.as_ref())
    }
}

/// The connection IDs we have issued to the peer, bounded by the peer's
/// `active_connection_id_limit` (RFC 9000 section 5.1.1).
///
/// ```
/// use quic_net::{ConnectionId, LocalCids, ResetKey};
/// let key = ResetKey::new([1; 32]);
/// let mut ids = LocalCids::new(ConnectionId::new(&[0; 8])?);
/// ids.set_peer_limit(4);
/// let (seq, cid, token) = ids.issue(ConnectionId::new(&[1; 8])?, &key).unwrap();
/// assert_eq!(seq, 1);
/// assert_eq!(token, key.token(&cid));
/// assert!(ids.on_retire(1, &ConnectionId::new(&[0; 8])?).is_ok());
/// # Ok::<(), quic_net::CidError>(())
/// ```
#[derive(Debug)]
pub struct LocalCids {
    issued: BTreeMap<u64, ConnectionId>,
    next: u64,
    peer_limit: u64,
}

impl LocalCids {
    /// Starts with the ID we chose for the handshake (sequence 0).
    #[must_use]
    pub fn new(initial: ConnectionId) -> LocalCids {
        let mut issued = BTreeMap::new();
        issued.insert(0, initial);
        LocalCids {
            issued,
            next: 1,
            peer_limit: 2,
        }
    }

    /// The peer's `active_connection_id_limit` (2 when it sent none).
    pub fn set_peer_limit(&mut self, limit: u64) {
        self.peer_limit = limit.max(2);
    }

    /// Issues `cid` with the next sequence number and its token from `key`,
    /// for a NEW_CONNECTION_ID frame; `None` when the peer's limit is reached
    /// or `cid` is already issued.
    pub fn issue(
        &mut self,
        cid: ConnectionId,
        key: &ResetKey,
    ) -> Option<(u64, ConnectionId, ResetToken)> {
        if self.issued.len() as u64 >= self.peer_limit
            || cid.is_empty()
            || self.issued.values().any(|c| *c == cid)
        {
            return None;
        }
        let seq = self.next;
        self.next += 1;
        self.issued.insert(seq, cid);
        Some((seq, cid, key.token(&cid)))
    }

    /// Takes a RETIRE_CONNECTION_ID frame that arrived in a packet sent to
    /// `packet_dcid`. Returns the retired ID (none when already retired).
    ///
    /// # Errors
    ///
    /// `PROTOCOL_VIOLATION` for a sequence number we never issued, or for
    /// the ID the packet itself was sent to (RFC 9000 section 19.16).
    pub fn on_retire(
        &mut self,
        sequence: u64,
        packet_dcid: &ConnectionId,
    ) -> Result<Option<ConnectionId>, TransportErrorCode> {
        if sequence >= self.next {
            return Err(TransportErrorCode::PROTOCOL_VIOLATION);
        }
        if self.issued.get(&sequence) == Some(packet_dcid) {
            return Err(TransportErrorCode::PROTOCOL_VIOLATION);
        }
        Ok(self.issued.remove(&sequence))
    }

    /// Whether `cid` is one of ours that is still active.
    #[must_use]
    pub fn contains(&self, cid: &ConnectionId) -> bool {
        self.issued.values().any(|c| c == cid)
    }

    /// How many are active.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.issued.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid(b: u8) -> ConnectionId {
        ConnectionId::new(&[b; 8]).unwrap()
    }

    fn tok(b: u8) -> ResetToken {
        ResetToken::new([b; 16])
    }

    #[test]
    fn peer_ids_follow_the_rules() {
        let mut ids = PeerCids::new(cid(0), 3);
        assert_eq!(ids.on_new_connection_id(1, 0, cid(1), tok(1)), Ok(vec![]));
        // The same frame again is fine.
        assert_eq!(ids.on_new_connection_id(1, 0, cid(1), tok(1)), Ok(vec![]));
        // The same sequence with another ID, or another token.
        assert_eq!(
            ids.on_new_connection_id(1, 0, cid(9), tok(1)),
            Err(TransportErrorCode::PROTOCOL_VIOLATION)
        );
        assert_eq!(
            ids.on_new_connection_id(1, 0, cid(1), tok(9)),
            Err(TransportErrorCode::PROTOCOL_VIOLATION)
        );
        // The same ID under another sequence.
        assert_eq!(
            ids.on_new_connection_id(2, 0, cid(1), tok(2)),
            Err(TransportErrorCode::PROTOCOL_VIOLATION)
        );
        assert_eq!(
            ids.on_new_connection_id(2, 3, cid(2), tok(2)),
            Err(TransportErrorCode::FRAME_ENCODING_ERROR)
        );
        assert_eq!(ids.on_new_connection_id(2, 0, cid(2), tok(2)), Ok(vec![]));
        // A fourth active ID is over the limit of 3.
        assert_eq!(
            ids.on_new_connection_id(3, 0, cid(3), tok(3)),
            Err(TransportErrorCode::CONNECTION_ID_LIMIT_ERROR)
        );
    }

    #[test]
    fn retire_prior_to_retires_and_late_ids_retire_at_once() {
        let mut ids = PeerCids::new(cid(0), 2);
        ids.on_new_connection_id(1, 0, cid(1), tok(1)).unwrap();
        assert_eq!(
            ids.on_new_connection_id(3, 3, cid(3), tok(3)),
            Ok(vec![0, 1])
        );
        // Sequence 2 arrives late, after everything before 3 was retired.
        assert_eq!(ids.on_new_connection_id(2, 0, cid(2), tok(2)), Ok(vec![2]));
        let active: Vec<u64> = ids.active().map(|c| c.sequence).collect();
        assert_eq!(active, vec![3]);
        assert_eq!(ids.reset_tokens().count(), 1);
    }

    #[test]
    fn pending_retirements_are_bounded() {
        let mut ids = PeerCids::new(cid(0), 2);
        let mut seq = 1;
        let mut failed = false;
        // A peer that keeps retiring everything; we never send the frames.
        for i in 0..20u8 {
            match ids.on_new_connection_id(seq, seq, cid(i + 1), tok(i)) {
                Ok(_) => seq += 1,
                Err(e) => {
                    assert_eq!(e, TransportErrorCode::CONNECTION_ID_LIMIT_ERROR);
                    failed = true;
                    break;
                }
            }
        }
        assert!(failed);
    }

    #[test]
    fn local_ids_follow_the_rules() {
        let key = ResetKey::new([5; 32]);
        let mut ids = LocalCids::new(cid(0));
        assert!(ids.issue(cid(1), &key).is_some());
        assert!(ids.issue(cid(2), &key).is_none(), "the default limit is 2");
        ids.set_peer_limit(3);
        assert!(ids.issue(cid(1), &key).is_none(), "already issued");
        assert!(ids.issue(ConnectionId::EMPTY, &key).is_none());
        let (s, _, _) = ids.issue(cid(2), &key).unwrap();
        assert_eq!(s, 2);
        assert_eq!(
            ids.on_retire(9, &cid(0)),
            Err(TransportErrorCode::PROTOCOL_VIOLATION)
        );
        assert_eq!(
            ids.on_retire(1, &cid(1)),
            Err(TransportErrorCode::PROTOCOL_VIOLATION),
            "the ID the packet was sent to"
        );
        assert_eq!(ids.on_retire(1, &cid(0)), Ok(Some(cid(1))));
        assert_eq!(ids.on_retire(1, &cid(0)), Ok(None));
        assert!(!ids.contains(&cid(1)));
        assert_eq!(ids.active_count(), 2);
    }

    #[test]
    fn reset_detection() {
        let key = ResetKey::new([3; 32]);
        let t1 = key.token(&cid(1));
        let t2 = key.token(&cid(2));
        assert_ne!(t1, t2);
        let mut d = vec![0x41; 40];
        d[24..].copy_from_slice(t2.as_bytes());
        assert!(is_stateless_reset(&d, [&t1, &t2]));
        assert!(!is_stateless_reset(&d, [&t1]));
        assert!(!is_stateless_reset(&d[20..], [&t2]));
        assert!(is_stateless_reset(&d[19..], [&t2]), "exactly 21 bytes");
    }

    #[test]
    fn cids() {
        assert_eq!(ConnectionId::new(&[0; 20]).unwrap().len(), 20);
        assert_eq!(ConnectionId::new(&[0; 21]), Err(CidError));
        assert!(ConnectionId::EMPTY.is_empty());
        assert_eq!(
            format!("{:?}", ConnectionId::new(&[0xab, 1]).unwrap()),
            "ConnectionId(ab01)"
        );
    }
}
