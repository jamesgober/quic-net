//! Receiving stream and CRYPTO data: reassembly, flow control, final size,
//! and reset (RFC 9000 sections 2.2, 3.2, 4.5, 7.5, and 19.6).

use std::collections::VecDeque;

use crate::error::TransportErrorCode;
use crate::flow::RecvCredit;
use crate::ranges::RangeSet;

/// The most separate pieces a stream's unread data may be in: received
/// ranges with gaps between them. More is a `PROTOCOL_VIOLATION`.
///
/// Memory is bounded by flow control already; this bounds the bookkeeping.
/// A sender with this many holes in one stream's window has lost over a
/// thousand packets of that stream at once or is fragmenting on purpose.
pub const MAX_FRAGMENTS: usize = 1024;

/// How far past the read position CRYPTO data may reach, per encryption
/// level. More is a `CRYPTO_BUFFER_EXCEEDED` (RFC 9000 section 7.5 asks for
/// at least 4,096 bytes; a server's certificate chain arrives this way).
pub const MAX_CRYPTO_BUFFER: u64 = 65_536;

/// Bytes stored at their offset from the read position, with the ranges
/// received. Inserting costs the new bytes only, whatever their order.
#[derive(Clone, Debug, Default)]
struct Reassembly {
    read: u64,
    buf: VecDeque<u8>,
    got: RangeSet,
}

impl Reassembly {
    /// Stores `data` at `offset`. Bytes below the read position, and bytes
    /// already held, are skipped; a retransmission must carry the same bytes
    /// (RFC 9000 section 2.2), so the first copy is kept.
    fn insert(&mut self, offset: u64, data: &[u8]) -> Result<(), TransportErrorCode> {
        let end = offset.saturating_add(data.len() as u64);
        let start = offset.max(self.read);
        if end <= start || self.got.covers(start..end) {
            return Ok(());
        }
        if self.got.len_after_insert(&(start..end)) > MAX_FRAGMENTS {
            return Err(TransportErrorCode::PROTOCOL_VIOLATION);
        }
        // Copy only the gaps: what `got` does not hold yet.
        let Reassembly { read, buf, got } = self;
        let mut at = start;
        for held in got.iter_from(start) {
            if held.start >= end {
                break;
            }
            if held.start > at {
                fill(buf, *read, offset, data, at..held.start)?;
            }
            at = at.max(held.end);
        }
        if at < end {
            fill(buf, *read, offset, data, at..end)?;
        }
        self.got.insert(start..end);
        Ok(())
    }

    /// Contiguous bytes ready at the read position.
    fn readable(&self) -> usize {
        match self.got.first() {
            Some(r) if r.start == self.read => (r.end - r.start) as usize,
            _ => 0,
        }
    }

    fn read(&mut self, out: &mut [u8]) -> usize {
        let n = self.readable().min(out.len());
        let (a, b) = self.buf.as_slices();
        let na = a.len().min(n);
        out[..na].copy_from_slice(&a[..na]);
        out[na..n].copy_from_slice(&b[..n - na]);
        self.buf.drain(..n);
        self.read += n as u64;
        self.got.remove_below(self.read);
        n
    }

    fn clear(&mut self) {
        self.buf = VecDeque::new();
        self.got.clear();
    }

    /// Bytes held, read or not yet readable: the memory in use.
    fn held(&self) -> usize {
        self.buf.len()
    }
}

/// Stores the bytes of `data` (which starts at `offset`) for `gap` into
/// `buf`, which starts at `read`.
fn fill(
    buf: &mut VecDeque<u8>,
    read: u64,
    offset: u64,
    data: &[u8],
    gap: core::ops::Range<u64>,
) -> Result<(), TransportErrorCode> {
    let src = &data[(gap.start - offset) as usize..(gap.end - offset) as usize];
    let at = usize::try_from(gap.start - read).map_err(|_| TransportErrorCode::INTERNAL_ERROR)?;
    if at == buf.len() {
        // In order: append.
        buf.extend(src);
    } else {
        if at + src.len() > buf.len() {
            buf.resize(at + src.len(), 0);
        }
        write_at(buf, at, src);
    }
    Ok(())
}

/// Copies `src` into `buf` at `at`, across the deque's two slices.
fn write_at(buf: &mut VecDeque<u8>, at: usize, src: &[u8]) {
    let (a, b) = buf.as_mut_slices();
    let mut done = 0;
    if at < a.len() {
        done = (a.len() - at).min(src.len());
        a[at..at + done].copy_from_slice(&src[..done]);
    }
    if done < src.len() {
        let from = at + done - a.len();
        b[from..from + src.len() - done].copy_from_slice(&src[done..]);
    }
}

/// Where the receiving part of a stream stands (RFC 9000 section 3.2).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvState {
    /// Receiving; the final size is not known.
    Recv,
    /// The final size is known; data is missing.
    SizeKnown,
    /// Every byte up to the final size arrived; some is unread.
    DataRecvd,
    /// The application read everything.
    DataRead,
    /// The peer reset the stream with this error code.
    ResetRecvd(u64),
}

/// The receiving part of a stream.
///
/// ```
/// use quic_net::RecvStream;
/// let mut s = RecvStream::new(1 << 20);
/// s.on_stream(5, b" world", true)?;
/// s.on_stream(0, b"hello", false)?;
/// let mut out = [0u8; 32];
/// let n = s.read(&mut out);
/// assert_eq!(&out[..n], b"hello world");
/// assert!(s.is_finished());
/// # Ok::<(), quic_net::TransportErrorCode>(())
/// ```
#[derive(Clone, Debug)]
pub struct RecvStream {
    data: Reassembly,
    credit: RecvCredit,
    highest: u64,
    final_size: Option<u64>,
    state: RecvState,
    stopped: bool,
    unreported: u64,
}

impl RecvStream {
    /// A stream whose sender may run `window` bytes ahead of what the
    /// application has read (`initial_max_stream_data_*`).
    #[must_use]
    pub fn new(window: u64) -> RecvStream {
        RecvStream {
            data: Reassembly::default(),
            credit: RecvCredit::new(window),
            highest: 0,
            final_size: None,
            state: RecvState::Recv,
            stopped: false,
            unreported: 0,
        }
    }

    /// The final size checks of RFC 9000 section 4.5 and the stream's flow
    /// control, for data reaching `end`. Returns how far the highest
    /// offset grows: what the connection's flow control must count.
    fn reach(&mut self, end: u64, is_final: bool) -> Result<u64, TransportErrorCode> {
        if let Some(f) = self.final_size {
            if end > f || (is_final && end != f) {
                return Err(TransportErrorCode::FINAL_SIZE_ERROR);
            }
        }
        if is_final && end < self.highest {
            return Err(TransportErrorCode::FINAL_SIZE_ERROR);
        }
        self.credit.receive_to(end)?;
        if is_final {
            self.final_size = Some(end);
        }
        let growth = end.saturating_sub(self.highest);
        self.highest = self.highest.max(end);
        Ok(growth)
    }

    /// A `STREAM` frame. Returns how far the stream's highest offset grew,
    /// which the connection counts against its own limit
    /// ([`RecvCredit::receive_more`]).
    ///
    /// # Errors
    ///
    /// `FLOW_CONTROL_ERROR` past the stream's limit, `FINAL_SIZE_ERROR` for
    /// data past a known final size or a final size that changes, and
    /// `PROTOCOL_VIOLATION` past [`MAX_FRAGMENTS`].
    pub fn on_stream(
        &mut self,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<u64, TransportErrorCode> {
        let end = offset.saturating_add(data.len() as u64);
        let growth = self.reach(end, fin)?;
        match self.state {
            RecvState::Recv | RecvState::SizeKnown => {}
            // Late or repeated data after everything arrived, or after a
            // reset, changes nothing.
            _ => return Ok(growth),
        }
        if self.stopped {
            self.unreported += growth;
            self.credit.consumed(growth);
            self.data.read = self.highest;
        } else {
            self.data.insert(offset, data)?;
        }
        self.check_complete();
        Ok(growth)
    }

    /// Moves the state on once the final size is known: every byte
    /// arrived, or every byte was read (or dropped after a stop).
    fn check_complete(&mut self) {
        let Some(f) = self.final_size else {
            return;
        };
        if !matches!(
            self.state,
            RecvState::Recv | RecvState::SizeKnown | RecvState::DataRecvd
        ) {
            return;
        }
        self.state = if self.data.read == f {
            RecvState::DataRead
        } else if self.data.got.covers(self.data.read..f) {
            RecvState::DataRecvd
        } else {
            RecvState::SizeKnown
        };
    }

    /// A `RESET_STREAM` frame. Returns how far the highest offset grew. The
    /// unread data is dropped and counted as consumed. A reset after every
    /// byte arrived is ignored (RFC 9000 section 3.2 allows either).
    ///
    /// # Errors
    ///
    /// As [`on_stream`](Self::on_stream) for the final size.
    pub fn on_reset(
        &mut self,
        error_code: u64,
        final_size: u64,
    ) -> Result<u64, TransportErrorCode> {
        let growth = self.reach(final_size, true)?;
        if matches!(
            self.state,
            RecvState::DataRecvd | RecvState::DataRead | RecvState::ResetRecvd(_)
        ) {
            return Ok(growth);
        }
        let unread = final_size - self.data.read;
        self.data.clear();
        self.data.read = final_size;
        self.unreported += unread;
        self.credit.consumed(unread);
        self.state = RecvState::ResetRecvd(error_code);
        Ok(growth)
    }

    /// Reads contiguous data into `out`; 0 when none is ready.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        if !matches!(
            self.state,
            RecvState::Recv | RecvState::SizeKnown | RecvState::DataRecvd
        ) {
            return 0;
        }
        let n = self.data.read(out);
        self.credit.consumed(n as u64);
        self.unreported += n as u64;
        self.check_complete();
        n
    }

    /// Bytes ready to read.
    #[must_use]
    pub fn readable(&self) -> usize {
        self.data.readable()
    }

    /// The application wants no more data (and sends `STOP_SENDING`).
    /// What is held is dropped; what arrives later is counted and dropped.
    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        let held = self.highest - self.data.read;
        self.data.clear();
        self.data.read = self.highest;
        self.unreported += held;
        self.credit.consumed(held);
        self.check_complete();
    }

    /// Whether the application read up to the final size, or stopped and
    /// the final size is known.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.state == RecvState::DataRead
    }

    /// Where the stream stands.
    #[must_use]
    pub fn state(&self) -> RecvState {
        self.state
    }

    /// The final size, once known.
    #[must_use]
    pub fn final_size(&self) -> Option<u64> {
        self.final_size
    }

    /// A new limit for a `MAX_STREAM_DATA` frame, once the application has
    /// read half a window. None once the final size is known: the sender
    /// needs no more credit.
    pub fn update(&mut self) -> Option<u64> {
        if self.final_size.is_some() {
            return None;
        }
        self.credit.update()
    }

    /// Bytes read or dropped since the last call: what the connection's
    /// flow control counts as consumed ([`RecvCredit::consumed`]).
    pub fn take_consumed(&mut self) -> u64 {
        core::mem::take(&mut self.unreported)
    }

    /// Bytes held in memory.
    #[must_use]
    pub fn held(&self) -> usize {
        self.data.held()
    }
}

/// CRYPTO data of one encryption level, reassembled for TLS.
///
/// ```
/// use quic_net::CryptoRecv;
/// let mut c = CryptoRecv::new();
/// c.on_crypto(3, b"lo")?;
/// c.on_crypto(0, b"hel")?;
/// let mut out = [0u8; 8];
/// assert_eq!(c.read(&mut out), 5);
/// # Ok::<(), quic_net::TransportErrorCode>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct CryptoRecv {
    data: Reassembly,
}

impl CryptoRecv {
    /// Nothing received yet.
    #[must_use]
    pub fn new() -> CryptoRecv {
        CryptoRecv::default()
    }

    /// A `CRYPTO` frame.
    ///
    /// # Errors
    ///
    /// `CRYPTO_BUFFER_EXCEEDED` for data reaching more than
    /// [`MAX_CRYPTO_BUFFER`] past what TLS has read, or past
    /// [`MAX_FRAGMENTS`].
    pub fn on_crypto(&mut self, offset: u64, data: &[u8]) -> Result<(), TransportErrorCode> {
        let end = offset.saturating_add(data.len() as u64);
        if end.saturating_sub(self.data.read) > MAX_CRYPTO_BUFFER {
            return Err(TransportErrorCode::CRYPTO_BUFFER_EXCEEDED);
        }
        self.data
            .insert(offset, data)
            .map_err(|_| TransportErrorCode::CRYPTO_BUFFER_EXCEEDED)
    }

    /// Reads contiguous data for TLS into `out`.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        self.data.read(out)
    }

    /// Bytes ready to read.
    #[must_use]
    pub fn readable(&self) -> usize {
        self.data.readable()
    }

    /// The offset TLS has read up to.
    #[must_use]
    pub fn read_offset(&self) -> u64 {
        self.data.read
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(s: &mut RecvStream) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 7];
        loop {
            let n = s.read(&mut buf);
            if n == 0 {
                return out;
            }
            out.extend_from_slice(&buf[..n]);
        }
    }

    #[test]
    fn test_out_of_order_overlapping_and_duplicate() {
        let src: Vec<u8> = (0..200u8).collect();
        let mut s = RecvStream::new(1000);
        assert_eq!(s.on_stream(150, &src[150..], true).unwrap(), 200);
        assert_eq!(s.state(), RecvState::SizeKnown);
        s.on_stream(40, &src[40..120], false).unwrap();
        s.on_stream(100, &src[100..160], false).unwrap();
        s.on_stream(40, &src[40..120], false).unwrap();
        assert_eq!(s.readable(), 0);
        s.on_stream(0, &src[..50], false).unwrap();
        assert_eq!(s.state(), RecvState::DataRecvd);
        assert_eq!(read_all(&mut s), src);
        assert!(s.is_finished());
        assert_eq!(s.take_consumed(), 200);
        assert_eq!(s.held(), 0);
    }

    #[test]
    fn test_the_first_copy_of_a_byte_is_kept() {
        let mut s = RecvStream::new(100);
        s.on_stream(2, b"XY", false).unwrap();
        s.on_stream(0, b"abcdef", false).unwrap();
        assert_eq!(read_all(&mut s), b"abXYef");
    }

    #[test]
    fn test_final_size_rules() {
        let mut s = RecvStream::new(100);
        s.on_stream(0, b"abcdef", false).unwrap();
        assert_eq!(
            s.on_stream(0, b"abc", true),
            Err(TransportErrorCode::FINAL_SIZE_ERROR)
        );
        s.on_stream(6, b"g", true).unwrap();
        assert_eq!(s.final_size(), Some(7));
        assert_eq!(
            s.on_stream(7, b"h", false),
            Err(TransportErrorCode::FINAL_SIZE_ERROR)
        );
        assert_eq!(
            s.on_stream(0, b"abcdefgh", true),
            Err(TransportErrorCode::FINAL_SIZE_ERROR)
        );
        assert_eq!(s.on_reset(0, 8), Err(TransportErrorCode::FINAL_SIZE_ERROR));
        assert!(s.on_stream(0, b"abcdefg", true).is_ok());
        assert_eq!(s.update(), None);
    }

    #[test]
    fn test_flow_control() {
        let mut s = RecvStream::new(10);
        assert_eq!(
            s.on_stream(5, b"123456", false),
            Err(TransportErrorCode::FLOW_CONTROL_ERROR)
        );
        assert_eq!(s.on_stream(0, b"0123456789", false).unwrap(), 10);
        assert_eq!(s.on_stream(0, b"0123456789", false).unwrap(), 0);
        let mut out = [0u8; 5];
        assert_eq!(s.read(&mut out), 5);
        assert_eq!(s.update(), Some(15));
        assert!(s.on_stream(10, b"abcde", false).is_ok());
        assert_eq!(
            s.on_reset(0, 16),
            Err(TransportErrorCode::FLOW_CONTROL_ERROR)
        );
    }

    #[test]
    fn test_reset_drops_unread_data_and_counts_it() {
        let mut s = RecvStream::new(100);
        s.on_stream(0, b"abcdef", false).unwrap();
        let mut out = [0u8; 2];
        assert_eq!(s.read(&mut out), 2);
        assert_eq!(s.take_consumed(), 2);
        assert_eq!(s.on_reset(7, 10).unwrap(), 4);
        assert_eq!(s.state(), RecvState::ResetRecvd(7));
        assert_eq!(s.take_consumed(), 8);
        assert_eq!(s.read(&mut out), 0);
        assert_eq!(s.held(), 0);
        // Data after the reset changes nothing; a contradicting size fails.
        assert_eq!(s.on_stream(0, b"abcdef", false).unwrap(), 0);
        assert_eq!(s.on_reset(7, 11), Err(TransportErrorCode::FINAL_SIZE_ERROR));
    }

    #[test]
    fn test_reset_after_all_data_is_ignored() {
        let mut s = RecvStream::new(100);
        s.on_stream(0, b"abc", true).unwrap();
        assert_eq!(s.on_reset(1, 3).unwrap(), 0);
        assert_eq!(s.state(), RecvState::DataRecvd);
        assert_eq!(read_all(&mut s), b"abc");
    }

    #[test]
    fn test_stop_counts_everything_as_consumed() {
        let mut s = RecvStream::new(100);
        s.on_stream(10, b"later", false).unwrap();
        s.stop();
        assert_eq!(s.take_consumed(), 15);
        assert_eq!(s.on_stream(15, b"more", false).unwrap(), 4);
        assert_eq!(s.take_consumed(), 4);
        assert_eq!(s.held(), 0);
        s.on_stream(19, b"!", true).unwrap();
        assert!(s.is_finished());
    }

    #[test]
    fn test_fragments_are_bounded() {
        let mut s = RecvStream::new(1 << 20);
        for i in 0..MAX_FRAGMENTS as u64 {
            s.on_stream(1 + 2 * i, b"x", false).unwrap();
        }
        assert_eq!(
            s.on_stream(1 + 2 * MAX_FRAGMENTS as u64, b"x", false),
            Err(TransportErrorCode::PROTOCOL_VIOLATION)
        );
        // Extending a range keeps the count; filling a gap between two
        // ranges lowers it.
        s.on_stream(0, b"x", false).unwrap();
        assert!(
            s.on_stream(1 + 2 * MAX_FRAGMENTS as u64, b"x", false)
                .is_err()
        );
        s.on_stream(2, b"x", false).unwrap();
        s.on_stream(1 + 2 * MAX_FRAGMENTS as u64, b"x", false)
            .unwrap();
    }

    #[test]
    fn test_crypto_buffer() {
        let mut c = CryptoRecv::new();
        assert_eq!(
            c.on_crypto(MAX_CRYPTO_BUFFER, b"x"),
            Err(TransportErrorCode::CRYPTO_BUFFER_EXCEEDED)
        );
        c.on_crypto(MAX_CRYPTO_BUFFER - 1, b"x").unwrap();
        c.on_crypto(0, &[1; 10]).unwrap();
        let mut out = [0u8; 4];
        assert_eq!(c.read(&mut out), 4);
        assert_eq!(c.read_offset(), 4);
        assert_eq!(c.readable(), 6);
        c.on_crypto(MAX_CRYPTO_BUFFER + 3, b"x").unwrap();
    }
}
