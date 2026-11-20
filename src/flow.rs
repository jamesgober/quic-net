//! Flow control credit (RFC 9000 section 4): what we let the peer send
//! (`MAX_DATA`, `MAX_STREAM_DATA` that we advertise), and what the peer lets
//! us send.

use crate::error::TransportErrorCode;
use crate::varint::MAX_VARINT;

/// The credit we give the peer, for a connection or a stream. The limit
/// moves forward as the application reads, a window ahead of what it has
/// read.
///
/// ```
/// use quic_net::RecvCredit;
/// let mut c = RecvCredit::new(1000);
/// c.receive_to(1000)?;
/// assert!(c.receive_to(1001).is_err()); // past the limit
/// c.consumed(600);
/// assert_eq!(c.update(), Some(1600)); // send MAX_STREAM_DATA 1600
/// # Ok::<(), quic_net::TransportErrorCode>(())
/// ```
#[derive(Clone, Debug)]
pub struct RecvCredit {
    max: u64,
    window: u64,
    received: u64,
    consumed: u64,
}

impl RecvCredit {
    /// Credit of `window` bytes ahead of what the application has read.
    #[must_use]
    pub fn new(window: u64) -> RecvCredit {
        let window = window.min(MAX_VARINT);
        RecvCredit {
            max: window,
            window,
            received: 0,
            consumed: 0,
        }
    }

    /// The limit advertised.
    #[must_use]
    pub fn max(&self) -> u64 {
        self.max
    }

    /// The highest offset received (a stream), or the sum of every
    /// stream's (a connection).
    #[must_use]
    pub fn received(&self) -> u64 {
        self.received
    }

    /// The peer's data now reaches `end` (a stream's highest offset).
    ///
    /// # Errors
    ///
    /// `FLOW_CONTROL_ERROR` past the limit.
    pub fn receive_to(&mut self, end: u64) -> Result<(), TransportErrorCode> {
        if end > self.max {
            return Err(TransportErrorCode::FLOW_CONTROL_ERROR);
        }
        self.received = self.received.max(end);
        Ok(())
    }

    /// The peer sent `n` more bytes (a connection: the growth of a stream's
    /// highest offset).
    ///
    /// # Errors
    ///
    /// `FLOW_CONTROL_ERROR` past the limit.
    pub fn receive_more(&mut self, n: u64) -> Result<(), TransportErrorCode> {
        let end = self.received.saturating_add(n);
        if end > self.max {
            return Err(TransportErrorCode::FLOW_CONTROL_ERROR);
        }
        self.received = end;
        Ok(())
    }

    /// The application read (or discarded) `n` bytes.
    pub fn consumed(&mut self, n: u64) {
        self.consumed = self.consumed.saturating_add(n).min(self.received);
    }

    /// A new limit to advertise, once the application has read half a
    /// window: one window past what it has read. `None` while the current
    /// limit is far enough ahead, so updates are not sent for every read.
    pub fn update(&mut self) -> Option<u64> {
        let target = self.consumed.saturating_add(self.window).min(MAX_VARINT);
        if target > self.max && target - self.max >= self.window / 2 {
            self.max = target;
            Some(target)
        } else {
            None
        }
    }
}

/// The credit the peer gives us.
///
/// ```
/// use quic_net::SendCredit;
/// let mut c = SendCredit::new(100);
/// c.consume(100);
/// assert_eq!(c.available(), 0);
/// assert_eq!(c.blocked(), Some(100)); // send DATA_BLOCKED 100, once
/// assert_eq!(c.blocked(), None);
/// c.raise(150);
/// assert_eq!(c.available(), 50);
/// ```
#[derive(Clone, Debug)]
pub struct SendCredit {
    max: u64,
    used: u64,
    blocked_at: Option<u64>,
}

impl SendCredit {
    /// Credit up to `max`, from the peer's transport parameters.
    #[must_use]
    pub fn new(max: u64) -> SendCredit {
        SendCredit {
            max,
            used: 0,
            blocked_at: None,
        }
    }

    /// Bytes that may still be sent.
    #[must_use]
    pub fn available(&self) -> u64 {
        self.max - self.used
    }

    /// The limit.
    #[must_use]
    pub fn max(&self) -> u64 {
        self.max
    }

    /// `n` bytes of new data were sent. Never more than [`available`](Self::available).
    pub fn consume(&mut self, n: u64) {
        self.used = self.used.saturating_add(n).min(self.max);
    }

    /// A `MAX_DATA` or `MAX_STREAM_DATA` frame: a lower limit than the
    /// current one is ignored (RFC 9000 section 4.1).
    pub fn raise(&mut self, max: u64) {
        self.max = self.max.max(max);
    }

    /// The limit to report in a `DATA_BLOCKED` or `STREAM_DATA_BLOCKED`
    /// frame when no credit is left, once per limit.
    pub fn blocked(&mut self) -> Option<u64> {
        if self.available() == 0 && self.blocked_at != Some(self.max) {
            self.blocked_at = Some(self.max);
            Some(self.max)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_updates_wait_for_half_a_window() {
        let mut c = RecvCredit::new(100);
        c.receive_to(100).unwrap();
        c.consumed(49);
        assert_eq!(c.update(), None);
        c.consumed(1);
        assert_eq!(c.update(), Some(150));
        assert_eq!(c.update(), None);
        // Consumed never runs past what was received.
        c.consumed(1000);
        assert_eq!(c.update(), Some(200));
    }

    #[test]
    fn test_connection_credit_adds_up() {
        let mut c = RecvCredit::new(10);
        c.receive_more(6).unwrap();
        c.receive_more(4).unwrap();
        assert_eq!(
            c.receive_more(1),
            Err(TransportErrorCode::FLOW_CONTROL_ERROR)
        );
        assert_eq!(c.received(), 10);
        assert_eq!(
            c.receive_more(u64::MAX),
            Err(TransportErrorCode::FLOW_CONTROL_ERROR)
        );
    }

    #[test]
    fn test_send_credit() {
        let mut c = SendCredit::new(10);
        c.raise(5);
        assert_eq!(c.max(), 10);
        c.consume(20);
        assert_eq!(c.available(), 0);
        assert_eq!(c.blocked(), Some(10));
        assert_eq!(c.blocked(), None);
        c.raise(20);
        assert_eq!(c.blocked(), None);
        c.consume(10);
        assert_eq!(c.blocked(), Some(20));
    }
}
