//! Congestion control (RFC 9002 section 7): NewReno, and pacing.
//!
//! The controller counts the bytes in flight (every packet that is
//! ack-eliciting or padded, in any packet number space) against a
//! congestion window. Slow start doubles the window each round trip until a
//! loss; a loss halves it once per round trip (the recovery period);
//! persistent congestion (losses spanning several probe timeouts with
//! nothing acknowledged between them) drops it to the minimum. ACK-only
//! packets are not counted and are never held back, and probes may go past
//! the window (RFC 9002 section 7.5).

use std::time::{Duration, Instant};

/// RFC 9002 section 7.6.
pub(crate) const PERSISTENT_CONGESTION_THRESHOLD: u32 = 3;

/// The window's state, for statistics and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CongestionState {
    /// The window doubles each round trip.
    SlowStart,
    /// The window grows by one datagram per round trip.
    CongestionAvoidance,
    /// A loss halved the window; losses of packets sent before it do not
    /// halve it again.
    Recovery,
}

/// NewReno (RFC 9002 section 7 and appendix B).
#[derive(Clone, Debug)]
pub(crate) struct NewReno {
    max_datagram: u64,
    window: u64,
    ssthresh: u64,
    in_flight: u64,
    /// Packets sent before this were sent before the last reduction.
    recovery_start: Option<Instant>,
    /// Bytes acknowledged in congestion avoidance, toward the next
    /// datagram of growth.
    acked_in_avoidance: u64,
    /// Until a packet sent after the last reduction is acknowledged.
    recovering: bool,
}

impl NewReno {
    pub(crate) fn new(max_datagram: usize) -> NewReno {
        let max_datagram = max_datagram as u64;
        NewReno {
            max_datagram,
            window: Self::initial_window(max_datagram),
            ssthresh: u64::MAX,
            in_flight: 0,
            recovery_start: None,
            acked_in_avoidance: 0,
            recovering: false,
        }
    }

    /// RFC 9002 section 7.2: ten datagrams, within 14,720 bytes but at
    /// least two datagrams.
    fn initial_window(max_datagram: u64) -> u64 {
        (10 * max_datagram).min(14_720.max(2 * max_datagram))
    }

    fn minimum_window(&self) -> u64 {
        2 * self.max_datagram
    }

    pub(crate) fn window(&self) -> u64 {
        self.window
    }

    pub(crate) fn in_flight(&self) -> u64 {
        self.in_flight
    }

    pub(crate) fn state(&self) -> CongestionState {
        if self.recovering {
            CongestionState::Recovery
        } else if self.window < self.ssthresh {
            CongestionState::SlowStart
        } else {
            CongestionState::CongestionAvoidance
        }
    }

    /// Room in the window for new packets.
    pub(crate) fn available(&self) -> u64 {
        self.window.saturating_sub(self.in_flight)
    }

    /// A packet counted in flight was sent.
    pub(crate) fn on_sent(&mut self, bytes: usize) {
        self.in_flight += bytes as u64;
    }

    /// A packet in flight left the network without being acknowledged or
    /// lost: its keys were discarded.
    pub(crate) fn on_discarded(&mut self, bytes: usize) {
        self.in_flight = self.in_flight.saturating_sub(bytes as u64);
    }

    fn in_recovery(&self, sent: Instant) -> bool {
        self.recovery_start.is_some_and(|r| sent <= r)
    }

    /// A packet in flight was acknowledged.
    pub(crate) fn on_acked(&mut self, bytes: usize, sent: Instant) {
        let bytes = bytes as u64;
        self.in_flight = self.in_flight.saturating_sub(bytes);
        if self.in_recovery(sent) {
            // No growth for packets sent before the reduction.
            return;
        }
        self.recovering = false;
        if self.window < self.ssthresh {
            self.window += bytes;
        } else {
            // One datagram per window acknowledged.
            self.acked_in_avoidance += bytes;
            if self.acked_in_avoidance >= self.window {
                self.acked_in_avoidance -= self.window;
                self.window += self.max_datagram;
            }
        }
    }

    /// Packets in flight were lost; `latest_sent` is when the last of them
    /// was sent. Halves the window once per recovery period.
    pub(crate) fn on_lost(&mut self, bytes: usize, latest_sent: Instant, now: Instant) {
        self.in_flight = self.in_flight.saturating_sub(bytes as u64);
        if self.in_recovery(latest_sent) {
            return;
        }
        self.recovery_start = Some(now);
        self.recovering = true;
        self.window = (self.window / 2).max(self.minimum_window());
        self.ssthresh = self.window;
        self.acked_in_avoidance = 0;
    }

    /// Persistent congestion (RFC 9002 section 7.6): the window drops to
    /// the minimum.
    pub(crate) fn on_persistent_congestion(&mut self) {
        self.window = self.minimum_window();
        self.recovery_start = None;
        self.recovering = false;
        self.acked_in_avoidance = 0;
    }
}

/// A pacer (RFC 9002 section 7.7): packets go out at 1.25 times the window
/// per round trip, with bursts of up to ten datagrams, so a full window is
/// not sent at once into a queue that cannot take it.
#[derive(Clone, Debug)]
pub(crate) struct Pacer {
    /// Bytes that may be sent now.
    budget: f64,
    last: Option<Instant>,
}

/// The pacing gain: 5/4.
const GAIN_NUM: f64 = 5.0;
const GAIN_DEN: f64 = 4.0;
const BURST_DATAGRAMS: f64 = 10.0;

impl Pacer {
    pub(crate) fn new() -> Pacer {
        Pacer {
            budget: f64::MAX,
            last: None,
        }
    }

    fn rate(window: u64, rtt: Duration) -> f64 {
        let secs = rtt.as_secs_f64().max(1e-3);
        window as f64 * GAIN_NUM / GAIN_DEN / secs
    }

    fn refill(&mut self, now: Instant, window: u64, rtt: Duration, max_datagram: usize) {
        let cap = BURST_DATAGRAMS * max_datagram as f64;
        let elapsed = self
            .last
            .map_or(f64::MAX, |l| now.saturating_duration_since(l).as_secs_f64());
        self.budget = (self.budget.min(cap) + elapsed * Self::rate(window, rtt)).min(cap);
        self.last = Some(now);
    }

    /// Whether `bytes` may go out at `now`; if not, when they may.
    pub(crate) fn check(
        &mut self,
        now: Instant,
        bytes: usize,
        window: u64,
        rtt: Duration,
        max_datagram: usize,
    ) -> Result<(), Instant> {
        self.refill(now, window, rtt, max_datagram);
        let need = bytes as f64;
        // Within a byte is enough: the refill is floating point, and a
        // timer set to the exact moment must find the budget there.
        if self.budget + 1.0 >= need {
            return Ok(());
        }
        let wait = (need - self.budget) / Self::rate(window, rtt);
        Err(now + Duration::from_secs_f64(wait.min(1.0)).max(Duration::from_micros(1)))
    }

    pub(crate) fn on_sent(&mut self, bytes: usize) {
        self.budget -= bytes as f64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_and_minimum_windows() {
        assert_eq!(NewReno::new(1200).window(), 12_000);
        assert_eq!(NewReno::new(1500).window(), 14_720);
        assert_eq!(NewReno::new(9000).window(), 18_000);
    }

    #[test]
    fn test_slow_start_then_one_halving_per_recovery() {
        let t0 = Instant::now();
        let mut cc = NewReno::new(1200);
        cc.on_sent(12_000);
        assert_eq!(cc.available(), 0);
        cc.on_acked(12_000, t0);
        assert_eq!(cc.window(), 24_000);
        assert_eq!(cc.state(), CongestionState::SlowStart);
        // A loss halves it; more losses from before the reduction do not.
        let t1 = t0 + Duration::from_millis(100);
        cc.on_sent(10_000);
        cc.on_lost(1200, t0 + Duration::from_millis(50), t1);
        assert_eq!(cc.window(), 12_000);
        cc.on_lost(
            1200,
            t0 + Duration::from_millis(60),
            t1 + Duration::from_millis(1),
        );
        assert_eq!(cc.window(), 12_000);
        // Acks for packets sent before the reduction do not grow it.
        cc.on_acked(1200, t0 + Duration::from_millis(70));
        assert_eq!(cc.window(), 12_000);
        // After it: congestion avoidance, one datagram per window.
        let t2 = t1 + Duration::from_millis(10);
        cc.on_sent(12_000);
        assert_eq!(cc.state(), CongestionState::Recovery);
        cc.on_acked(6000, t2);
        assert_eq!(cc.window(), 12_000);
        cc.on_acked(6000, t2);
        assert_eq!(cc.window(), 13_200);
        assert_eq!(cc.state(), CongestionState::CongestionAvoidance);
        // A new loss after the recovery period halves again.
        cc.on_lost(
            1200,
            t2 + Duration::from_millis(1),
            t2 + Duration::from_millis(5),
        );
        assert_eq!(cc.window(), 6600);
        assert_eq!(cc.state(), CongestionState::Recovery);
    }

    #[test]
    fn test_window_floor_and_persistent_congestion() {
        let t0 = Instant::now();
        let mut cc = NewReno::new(1200);
        for i in 0..10u64 {
            let t = t0 + Duration::from_secs(i + 1);
            cc.on_lost(0, t, t);
        }
        assert_eq!(cc.window(), 2400);
        cc.on_persistent_congestion();
        assert_eq!(cc.window(), 2400);
        cc.on_sent(5000);
        cc.on_discarded(6000);
        assert_eq!(cc.in_flight(), 0);
    }

    #[test]
    fn test_pacer() {
        let t0 = Instant::now();
        let mut p = Pacer::new();
        let rtt = Duration::from_millis(100);
        // A burst of ten datagrams, then the rate: 12,000 * 1.25 / 0.1 s.
        for _ in 0..10 {
            assert!(p.check(t0, 1200, 12_000, rtt, 1200).is_ok());
            p.on_sent(1200);
        }
        let Err(at) = p.check(t0, 1200, 12_000, rtt, 1200) else {
            panic!("the burst is spent");
        };
        assert_eq!(at - t0, Duration::from_millis(8));
        assert!(p.check(at, 1200, 12_000, rtt, 1200).is_ok());
    }
}
