//! Sending stream data: buffering, flow control, loss and retransmission,
//! acknowledgement, and reset (RFC 9000 sections 2.2, 3.1, 4, and 13.3).

use std::collections::VecDeque;

use crate::flow::SendCredit;
use crate::ranges::RangeSet;
use crate::stream::StreamId;
use crate::varint::put;

/// A piece of a stream to send in one `STREAM` frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunk {
    /// Its offset in the stream.
    pub offset: u64,
    /// Its length (0 for a frame that only carries the end of the stream).
    pub len: usize,
    /// Whether it ends the stream.
    pub fin: bool,
    /// How many bytes of it were never sent before: what it takes from the
    /// connection's credit ([`SendCredit::consume`]).
    pub new: u64,
}

impl Chunk {
    fn end(&self) -> u64 {
        self.offset + self.len as u64
    }
}

/// Where the sending part of a stream stands (RFC 9000 section 3.1).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendState {
    /// Nothing sent yet.
    Ready,
    /// Sending.
    Send,
    /// Every byte and the end of the stream were sent; some are not
    /// acknowledged.
    DataSent,
    /// Every byte and the end of the stream were acknowledged.
    DataRecvd,
    /// Reset; the `RESET_STREAM` is not acknowledged yet.
    ResetSent,
    /// Reset, and the peer acknowledged it.
    ResetRecvd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fin {
    None,
    Pending,
    Sent,
    Acked,
}

#[derive(Clone, Copy, Debug)]
struct Reset {
    code: u64,
    final_size: u64,
    acked: bool,
}

/// The sending part of a stream. Written bytes stay buffered until they are
/// acknowledged, so a lost packet's data can be sent again.
///
/// ```
/// use quic_net::{SendStream, StreamId, Side};
/// let mut s = SendStream::new(1000, 64 * 1024);
/// s.write(b"hello");
/// s.finish();
/// let chunk = s.next_chunk(1200, u64::MAX).unwrap();
/// assert_eq!((chunk.offset, chunk.len, chunk.fin), (0, 5, true));
/// let mut frame = Vec::new();
/// s.write_frame(StreamId::new(Side::Client, true, 0).unwrap(), &chunk, &mut frame);
/// s.on_lost(&chunk); // the packet was lost: it goes again
/// assert_eq!(s.next_chunk(1200, u64::MAX), Some(quic_net::Chunk { new: 0, ..chunk }));
/// s.on_acked(&chunk);
/// assert_eq!(s.state(), quic_net::SendState::DataRecvd);
/// ```
#[derive(Clone, Debug)]
pub struct SendStream {
    buf: VecDeque<u8>,
    base: u64,
    written: u64,
    sent_high: u64,
    pending: RangeSet,
    acked: RangeSet,
    credit: SendCredit,
    limit: usize,
    fin: Fin,
    reset: Option<Reset>,
}

impl SendStream {
    /// A stream the peer allows `max_stream_data` bytes on
    /// (`initial_max_stream_data_*`), buffering at most `buffer` bytes not
    /// yet acknowledged.
    #[must_use]
    pub fn new(max_stream_data: u64, buffer: usize) -> SendStream {
        SendStream {
            buf: VecDeque::new(),
            base: 0,
            written: 0,
            sent_high: 0,
            pending: RangeSet::new(),
            acked: RangeSet::new(),
            credit: SendCredit::new(max_stream_data),
            limit: buffer,
            fin: Fin::None,
            reset: None,
        }
    }

    /// Buffers as much of `data` as fits; returns how much. 0 once the
    /// stream is finished or reset, or while the buffer is full.
    pub fn write(&mut self, data: &[u8]) -> usize {
        if self.fin != Fin::None || self.reset.is_some() {
            return 0;
        }
        let n = self.writable().min(data.len());
        self.buf.extend(&data[..n]);
        self.pending.insert(self.written..self.written + n as u64);
        self.written += n as u64;
        n
    }

    /// Room in the buffer.
    #[must_use]
    pub fn writable(&self) -> usize {
        if self.fin != Fin::None || self.reset.is_some() {
            return 0;
        }
        self.limit.saturating_sub(self.buf.len())
    }

    /// No more data: the end of the stream goes with the last byte, or on
    /// its own.
    pub fn finish(&mut self) {
        if self.fin == Fin::None && self.reset.is_none() {
            self.fin = Fin::Pending;
        }
    }

    /// The next piece to send in a frame of at most `max_len` data bytes:
    /// lost data first, then new data within the stream's credit and
    /// `connection_credit`, the bytes the connection may still send. Data
    /// sent before needs no credit again.
    pub fn next_chunk(&mut self, max_len: usize, connection_credit: u64) -> Option<Chunk> {
        if self.reset.is_some() {
            return None;
        }
        if let Some(r) = self.pending.first().cloned() {
            let mut end = r.end.min(r.start.saturating_add(max_len as u64));
            if end > self.sent_high {
                let reach = self
                    .credit
                    .max()
                    .min(self.sent_high.saturating_add(connection_credit));
                end = end.min(reach.max(self.sent_high));
            }
            if end > r.start {
                self.pending.remove(r.start..end);
                let new = end.saturating_sub(self.sent_high);
                self.sent_high = self.sent_high.max(end);
                self.credit.consume(new);
                let fin = self.fin == Fin::Pending && end == self.written;
                if fin {
                    self.fin = Fin::Sent;
                }
                return Some(Chunk {
                    offset: r.start,
                    len: (end - r.start) as usize,
                    fin,
                    new,
                });
            }
        }
        if self.fin == Fin::Pending && self.sent_high == self.written {
            self.fin = Fin::Sent;
            return Some(Chunk {
                offset: self.written,
                len: 0,
                fin: true,
                new: 0,
            });
        }
        None
    }

    /// Writes the `STREAM` frame for `chunk`, which
    /// [`next_chunk`](Self::next_chunk) just returned, its data copied from
    /// the buffer.
    pub fn write_frame(&self, id: StreamId, chunk: &Chunk, out: &mut Vec<u8>) {
        let off = chunk.offset > 0;
        put(
            out,
            0x08 | 0x02 | if off { 0x04 } else { 0 } | u64::from(chunk.fin),
        );
        put(out, id.raw());
        if off {
            put(out, chunk.offset);
        }
        put(out, chunk.len as u64);
        self.copy_chunk(chunk, out);
    }

    /// Writes the `CRYPTO` frame for `chunk`, when the stream carries a
    /// level's handshake data.
    pub(crate) fn write_crypto_frame(&self, chunk: &Chunk, out: &mut Vec<u8>) {
        put(out, 0x06);
        put(out, chunk.offset);
        put(out, chunk.len as u64);
        self.copy_chunk(chunk, out);
    }

    fn copy_chunk(&self, chunk: &Chunk, out: &mut Vec<u8>) {
        let at = chunk.offset.saturating_sub(self.base) as usize;
        let (a, b) = self.buf.as_slices();
        let end = (at + chunk.len).min(a.len() + b.len());
        if at < a.len() {
            out.extend_from_slice(&a[at..end.min(a.len())]);
        }
        if end > a.len() {
            out.extend_from_slice(&b[at.saturating_sub(a.len())..end - a.len()]);
        }
    }

    /// The packet carrying `chunk` was acknowledged.
    pub fn on_acked(&mut self, chunk: &Chunk) {
        if self.reset.is_some() {
            return;
        }
        if chunk.fin {
            self.fin = Fin::Acked;
        }
        self.acked.insert(chunk.offset..chunk.end());
        // A chunk thought lost may arrive after all.
        self.pending.remove(chunk.offset..chunk.end());
        if let Some(r) = self.acked.first().cloned() {
            if r.start <= self.base && r.end > self.base {
                let n = (r.end - self.base) as usize;
                self.buf.drain(..n.min(self.buf.len()));
                self.base = r.end;
            }
        }
        self.acked.remove_below(self.base);
    }

    /// The packet carrying `chunk` was lost: what of it is not acknowledged
    /// goes again.
    pub fn on_lost(&mut self, chunk: &Chunk) {
        if self.reset.is_some() {
            return;
        }
        let start = chunk.offset.max(self.base);
        if start < chunk.end() {
            self.pending.insert(start..chunk.end());
            let acked: Vec<_> = self.acked.iter_from(start).cloned().collect();
            for a in acked {
                if a.start >= chunk.end() {
                    break;
                }
                self.pending.remove(a);
            }
        }
        if chunk.fin && self.fin == Fin::Sent {
            self.fin = Fin::Pending;
        }
    }

    /// A `MAX_STREAM_DATA` frame.
    pub fn raise(&mut self, max: u64) {
        self.credit.raise(max);
    }

    /// The limit for a `STREAM_DATA_BLOCKED` frame, once per limit, while
    /// new data waits for credit.
    pub fn blocked(&mut self) -> Option<u64> {
        let waiting = self.pending.iter().any(|r| r.end > self.sent_high);
        if waiting { self.credit.blocked() } else { None }
    }

    /// Resets the stream: returns the error code and final size for the
    /// `RESET_STREAM` frame. Buffered data is dropped. `None` when it is
    /// already reset or every byte was acknowledged.
    pub fn reset(&mut self, code: u64) -> Option<(u64, u64)> {
        if self.reset.is_some() || self.state() == SendState::DataRecvd {
            return None;
        }
        let final_size = self.sent_high;
        self.reset = Some(Reset {
            code,
            final_size,
            acked: false,
        });
        self.buf = VecDeque::new();
        self.pending.clear();
        self.acked.clear();
        Some((code, final_size))
    }

    /// A `STOP_SENDING` frame: the stream is reset with the peer's code
    /// (RFC 9000 section 3.5). Returns the `RESET_STREAM` to send.
    pub fn on_stop_sending(&mut self, code: u64) -> Option<(u64, u64)> {
        self.reset(code)
    }

    /// The `RESET_STREAM` was acknowledged.
    pub fn on_reset_acked(&mut self) {
        if let Some(r) = self.reset.as_mut() {
            r.acked = true;
        }
    }

    /// The `RESET_STREAM` was lost: returns it to send again.
    #[must_use]
    pub fn on_reset_lost(&self) -> Option<(u64, u64)> {
        self.reset
            .filter(|r| !r.acked)
            .map(|r| (r.code, r.final_size))
    }

    /// Where the stream stands.
    #[must_use]
    pub fn state(&self) -> SendState {
        if let Some(r) = self.reset {
            return if r.acked {
                SendState::ResetRecvd
            } else {
                SendState::ResetSent
            };
        }
        match self.fin {
            Fin::Acked if self.base == self.written => SendState::DataRecvd,
            Fin::Sent | Fin::Acked if self.pending.is_empty() => SendState::DataSent,
            _ if self.sent_high == 0 && self.fin != Fin::Sent => SendState::Ready,
            _ => SendState::Send,
        }
    }

    /// Bytes buffered, acknowledged or not: the memory in use.
    #[must_use]
    pub fn held(&self) -> usize {
        self.buf.len()
    }

    /// Whether data or the end of the stream waits to be sent.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.reset.is_none() && (!self.pending.is_empty() || self.fin == Fin::Pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Frame, PacketKind, Side, frames};

    fn id() -> StreamId {
        StreamId::new(Side::Client, true, 1).unwrap()
    }

    #[test]
    fn test_frames_decode_to_the_data() {
        let mut s = SendStream::new(1 << 20, 1 << 20);
        let data: Vec<u8> = (0..=255u8).cycle().take(3000).collect();
        assert_eq!(s.write(&data), 3000);
        s.finish();
        let mut got = Vec::new();
        while let Some(c) = s.next_chunk(1000, u64::MAX) {
            let mut f = Vec::new();
            s.write_frame(id(), &c, &mut f);
            let Some(Ok(Frame::Stream {
                stream_id,
                offset,
                data: d,
                fin,
            })) = frames(&f, PacketKind::OneRtt).next()
            else {
                panic!("{f:?}");
            };
            assert_eq!(
                (stream_id, offset, d.len(), fin),
                (id().raw(), c.offset, c.len, c.fin)
            );
            got.extend_from_slice(d);
        }
        assert_eq!(got, data);
        assert_eq!(s.state(), SendState::DataSent);
    }

    #[test]
    fn test_credit_limits_new_data_only() {
        let mut s = SendStream::new(10, 100);
        s.write(&[1; 30]);
        let a = s.next_chunk(100, 4).unwrap();
        assert_eq!((a.offset, a.len, a.new), (0, 4, 4));
        let b = s.next_chunk(100, 100).unwrap();
        assert_eq!((b.offset, b.len, b.new), (4, 6, 6));
        assert_eq!(s.next_chunk(100, 100), None);
        assert_eq!(s.blocked(), Some(10));
        assert_eq!(s.blocked(), None);
        // A lost chunk goes again without credit.
        s.on_lost(&a);
        let again = s.next_chunk(100, 0).unwrap();
        assert_eq!((again.offset, again.len, again.new), (0, 4, 0));
        s.raise(30);
        let c = s.next_chunk(100, 100).unwrap();
        assert_eq!((c.offset, c.len, c.new), (10, 20, 20));
    }

    #[test]
    fn test_acks_free_the_buffer_in_order() {
        let mut s = SendStream::new(100, 100);
        s.write(&[7; 30]);
        let a = s.next_chunk(10, 100).unwrap();
        let b = s.next_chunk(10, 100).unwrap();
        let c = s.next_chunk(10, 100).unwrap();
        s.on_acked(&c);
        s.on_acked(&b);
        assert_eq!(s.held(), 30);
        s.on_acked(&a);
        assert_eq!(s.held(), 0);
        assert_eq!(s.writable(), 100);
        // A late loss report changes nothing.
        s.on_lost(&b);
        assert!(!s.has_pending());
    }

    #[test]
    fn test_a_loss_skips_what_was_acknowledged() {
        let mut s = SendStream::new(100, 100);
        s.write(&[7; 30]);
        let all = s.next_chunk(30, 100).unwrap();
        let middle = Chunk {
            offset: 10,
            len: 10,
            fin: false,
            new: 0,
        };
        s.on_acked(&middle);
        s.on_lost(&all);
        let x = s.next_chunk(100, 0).unwrap();
        let y = s.next_chunk(100, 0).unwrap();
        assert_eq!((x.offset, x.len, y.offset, y.len), (0, 10, 20, 10));
        assert_eq!(s.next_chunk(100, 0), None);
    }

    #[test]
    fn test_fin_alone_and_its_loss() {
        let mut s = SendStream::new(100, 100);
        s.write(b"abc");
        let a = s.next_chunk(100, 100).unwrap();
        assert!(!a.fin);
        assert_eq!(s.state(), SendState::Send);
        s.finish();
        assert_eq!(s.write(b"x"), 0);
        let f = s.next_chunk(100, 100).unwrap();
        assert_eq!((f.offset, f.len, f.fin), (3, 0, true));
        s.on_lost(&f);
        assert_eq!(s.next_chunk(100, 100), Some(f));
        s.on_acked(&f);
        assert_eq!(s.state(), SendState::DataSent);
        s.on_acked(&a);
        assert_eq!(s.state(), SendState::DataRecvd);
        assert_eq!(s.reset(1), None);
    }

    #[test]
    fn test_reset() {
        let mut s = SendStream::new(100, 100);
        assert_eq!(s.state(), SendState::Ready);
        s.write(&[1; 50]);
        s.next_chunk(20, 100).unwrap();
        assert_eq!(s.on_stop_sending(9), Some((9, 20)));
        assert_eq!(s.reset(3), None);
        assert_eq!(s.state(), SendState::ResetSent);
        assert_eq!(s.held(), 0);
        assert_eq!(s.next_chunk(100, 100), None);
        assert_eq!(s.write(b"x"), 0);
        assert_eq!(s.on_reset_lost(), Some((9, 20)));
        s.on_reset_acked();
        assert_eq!(s.on_reset_lost(), None);
        assert_eq!(s.state(), SendState::ResetRecvd);
    }

    #[test]
    fn test_buffer_limit() {
        let mut s = SendStream::new(1000, 10);
        assert_eq!(s.write(&[0; 25]), 10);
        assert_eq!(s.write(&[0; 5]), 0);
        let c = s.next_chunk(4, 100).unwrap();
        s.on_acked(&c);
        assert_eq!(s.write(&[0; 5]), 4);
    }
}
