//! Stream IDs and stream limits (RFC 9000 sections 2.1 and 4.6).

use core::fmt;
use core::ops::Range;

use crate::error::TransportErrorCode;
use crate::frame::MAX_STREAMS;
use crate::params::Side;

/// A stream ID: the low bit says who opened it, the next whether it is
/// unidirectional, and the rest is its index among streams of its type.
///
/// ```
/// use quic_net::{Side, StreamId};
/// let id = StreamId::new(Side::Server, false, 3).unwrap();
/// assert_eq!(id.raw(), 15);
/// assert_eq!((id.initiator(), id.is_bidi(), id.index()), (Side::Server, false, 3));
/// assert!(!id.can_send(Side::Client)); // the server's unidirectional stream
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u64);

impl StreamId {
    /// The `index`-th stream of its type opened by `initiator`; `None` past
    /// the 2^60 streams of each type.
    #[must_use]
    pub fn new(initiator: Side, bidi: bool, index: u64) -> Option<StreamId> {
        if index >= MAX_STREAMS {
            return None;
        }
        let low = u64::from(initiator == Side::Server) | (u64::from(!bidi) << 1);
        Some(StreamId((index << 2) | low))
    }

    /// The ID as sent in a frame; `None` past 2^62 - 1.
    #[must_use]
    pub fn from_raw(raw: u64) -> Option<StreamId> {
        (raw >> 62 == 0).then_some(StreamId(raw))
    }

    /// The ID as sent in a frame.
    #[must_use]
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Who opened it.
    #[must_use]
    pub fn initiator(self) -> Side {
        if self.0 & 1 == 0 {
            Side::Client
        } else {
            Side::Server
        }
    }

    /// Whether data flows both ways.
    #[must_use]
    pub fn is_bidi(self) -> bool {
        self.0 & 2 == 0
    }

    /// Its index among the streams of its type.
    #[must_use]
    pub fn index(self) -> u64 {
        self.0 >> 2
    }

    /// Whether `local` may send on it: a bidirectional stream, or a
    /// unidirectional one `local` opened. Frames about a stream's sending
    /// part (`MAX_STREAM_DATA`, `STOP_SENDING`) arriving for a stream we
    /// cannot send on are a `STREAM_STATE_ERROR`.
    #[must_use]
    pub fn can_send(self, local: Side) -> bool {
        self.is_bidi() || self.initiator() == local
    }

    /// Whether `local` may receive on it. Frames about a stream's receiving
    /// part (`STREAM`, `RESET_STREAM`, `STREAM_DATA_BLOCKED`) arriving for a
    /// stream we cannot receive on are a `STREAM_STATE_ERROR`.
    #[must_use]
    pub fn can_receive(self, local: Side) -> bool {
        self.is_bidi() || self.initiator() != local
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StreamId({})", self.0)
    }
}

/// The streams of one type (bidirectional or unidirectional) that this
/// endpoint opens, within the peer's limit.
///
/// ```
/// use quic_net::LocalStreams;
/// let mut s = LocalStreams::new(1);
/// assert_eq!(s.open(), Some(0));
/// assert_eq!(s.open(), None);
/// assert_eq!(s.blocked(), Some(1)); // send STREAMS_BLOCKED 1
/// s.raise(3);
/// assert_eq!(s.open(), Some(1));
/// ```
#[derive(Clone, Debug)]
pub struct LocalStreams {
    next: u64,
    limit: u64,
    blocked_at: Option<u64>,
}

impl LocalStreams {
    /// Up to `limit` streams, from the peer's `initial_max_streams_*`.
    #[must_use]
    pub fn new(limit: u64) -> LocalStreams {
        LocalStreams {
            next: 0,
            limit: limit.min(MAX_STREAMS),
            blocked_at: None,
        }
    }

    /// The index of a new stream, or `None` at the limit.
    pub fn open(&mut self) -> Option<u64> {
        if self.next >= self.limit {
            return None;
        }
        self.next += 1;
        Some(self.next - 1)
    }

    /// Whether the stream at `index` was opened. A frame for one that was
    /// not is a `STREAM_STATE_ERROR`.
    #[must_use]
    pub fn is_opened(&self, index: u64) -> bool {
        index < self.next
    }

    /// A `MAX_STREAMS` frame; a lower limit is ignored.
    pub fn raise(&mut self, max: u64) {
        self.limit = self.limit.max(max.min(MAX_STREAMS));
    }

    /// The limit for a `STREAMS_BLOCKED` frame, once per limit, when no
    /// stream can be opened.
    pub fn blocked(&mut self) -> Option<u64> {
        if self.next >= self.limit && self.blocked_at != Some(self.limit) {
            self.blocked_at = Some(self.limit);
            Some(self.limit)
        } else {
            None
        }
    }
}

/// The streams of one type that the peer opens: at most `window` open at
/// once. The limit moves as streams close.
///
/// ```
/// use quic_net::RemoteStreams;
/// let mut s = RemoteStreams::new(2);
/// assert_eq!(s.on_frame(1)?, 0..2); // stream 1 opens stream 0 too
/// assert!(s.on_frame(2).is_err()); // over the limit of 2
/// s.on_closed();
/// assert_eq!(s.update(), Some(3)); // send MAX_STREAMS 3
/// # Ok::<(), quic_net::TransportErrorCode>(())
/// ```
#[derive(Clone, Debug)]
pub struct RemoteStreams {
    opened: u64,
    closed: u64,
    limit: u64,
    window: u64,
}

impl RemoteStreams {
    /// At most `window` open at once; the first limit advertised is
    /// `window` (`initial_max_streams_*`).
    #[must_use]
    pub fn new(window: u64) -> RemoteStreams {
        let window = window.min(MAX_STREAMS);
        RemoteStreams {
            opened: 0,
            closed: 0,
            limit: window,
            window,
        }
    }

    /// A frame for the peer's stream at `index`. Returns the indexes it
    /// opens: a stream opens every lower one of its type not yet open
    /// (RFC 9000 section 3.2). Empty when it was already open.
    ///
    /// # Errors
    ///
    /// `STREAM_LIMIT_ERROR` past the limit advertised.
    pub fn on_frame(&mut self, index: u64) -> Result<Range<u64>, TransportErrorCode> {
        if index >= self.limit {
            return Err(TransportErrorCode::STREAM_LIMIT_ERROR);
        }
        if index < self.opened {
            return Ok(self.opened..self.opened);
        }
        let opens = self.opened..index + 1;
        self.opened = index + 1;
        Ok(opens)
    }

    /// Whether the stream at `index` was opened.
    #[must_use]
    pub fn is_opened(&self, index: u64) -> bool {
        index < self.opened
    }

    /// One of the peer's streams is finished both ways and its state gone.
    pub fn on_closed(&mut self) {
        self.closed = (self.closed + 1).min(self.opened);
    }

    /// A new limit for a `MAX_STREAMS` frame, once half the window has
    /// closed since the last one.
    pub fn update(&mut self) -> Option<u64> {
        let target = (self.closed + self.window).min(MAX_STREAMS);
        if target > self.limit && (target - self.limit) * 2 >= self.window.max(1) {
            self.limit = target;
            Some(target)
        } else {
            None
        }
    }

    /// The limit advertised.
    #[must_use]
    pub fn limit(&self) -> u64 {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ids() {
        for (side, bidi, low) in [
            (Side::Client, true, 0),
            (Side::Server, true, 1),
            (Side::Client, false, 2),
            (Side::Server, false, 3),
        ] {
            let id = StreamId::new(side, bidi, 5).unwrap();
            assert_eq!(id.raw(), 20 + low);
            assert_eq!(StreamId::from_raw(id.raw()), Some(id));
            assert_eq!((id.initiator(), id.is_bidi(), id.index()), (side, bidi, 5));
        }
        assert!(StreamId::new(Side::Client, true, MAX_STREAMS).is_none());
        assert!(StreamId::new(Side::Client, true, MAX_STREAMS - 1).is_some());
        assert!(StreamId::from_raw(1 << 62).is_none());
        let uni = StreamId::new(Side::Client, false, 0).unwrap();
        assert!(uni.can_send(Side::Client) && !uni.can_receive(Side::Client));
        assert!(!uni.can_send(Side::Server) && uni.can_receive(Side::Server));
        let bi = StreamId::new(Side::Client, true, 0).unwrap();
        assert!(bi.can_send(Side::Server) && bi.can_receive(Side::Server));
        assert_eq!(format!("{bi:?}"), "StreamId(0)");
    }

    #[test]
    fn test_remote_limits() {
        let mut s = RemoteStreams::new(4);
        assert_eq!(s.on_frame(0).unwrap(), 0..1);
        assert_eq!(s.on_frame(0).unwrap(), 1..1);
        assert_eq!(s.on_frame(3).unwrap(), 1..4);
        assert_eq!(s.on_frame(4), Err(TransportErrorCode::STREAM_LIMIT_ERROR));
        assert!(s.is_opened(3) && !s.is_opened(4));
        s.on_closed();
        assert_eq!(s.update(), None);
        s.on_closed();
        assert_eq!(s.update(), Some(6));
        assert_eq!(s.limit(), 6);
        assert_eq!(s.on_frame(5).unwrap(), 4..6);
        // Closing more than were opened is not counted.
        for _ in 0..10 {
            s.on_closed();
        }
        assert_eq!(s.update(), Some(10));
    }

    #[test]
    fn test_zero_window() {
        let mut s = RemoteStreams::new(0);
        assert!(s.on_frame(0).is_err());
        assert_eq!(s.update(), None);
        let mut l = LocalStreams::new(0);
        assert_eq!(l.open(), None);
        assert_eq!(l.blocked(), Some(0));
        assert_eq!(l.blocked(), None);
        assert!(!l.is_opened(0));
        l.raise(u64::MAX);
        assert_eq!(l.open(), Some(0));
        assert!(l.is_opened(0));
    }
}
