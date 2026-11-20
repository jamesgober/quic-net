//! Transport frames (RFC 9000 section 19): decoded without copying from a
//! packet's payload, checked against the rules of their fields and of the
//! packet type that carries them (section 12.4), and written back.

use std::ops::RangeInclusive;

use crate::cid::{ConnectionId, ResetToken};
use crate::error::DecodeError;
use crate::varint::{self, MAX_VARINT, Reader};

/// The most ACK ranges read from one ACK frame, beyond the first. A peer
/// acknowledging more scattered ranges than this is either broken or trying
/// to make the receiver walk them; the frame is refused (`PROTOCOL_VIOLATION`).
pub const MAX_ACK_RANGES: usize = 256;

/// The most streams of one direction a peer may open (2^60, RFC 9000 section 4.6).
pub const MAX_STREAMS: u64 = 1 << 60;

/// Which packet type carries a frame (RFC 9000 section 12.4, table 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PacketKind {
    /// Initial packets.
    Initial,
    /// Handshake packets.
    Handshake,
    /// 0-RTT packets.
    ZeroRtt,
    /// 1-RTT (short header) packets.
    OneRtt,
}

/// ECN counts of an ACK frame of type 0x03.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct EcnCounts {
    /// Packets received with ECT(0).
    pub ect0: u64,
    /// Packets received with ECT(1).
    pub ect1: u64,
    /// Packets received with CE.
    pub ce: u64,
}

/// An ACK frame. Its ranges were checked when it was decoded: every one lies
/// at or above packet number 0, and there are at most [`MAX_ACK_RANGES`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack<'a> {
    /// The largest packet number acknowledged.
    pub largest: u64,
    /// The ACK delay, scaled by the peer's `ack_delay_exponent`.
    pub delay: u64,
    first_range: u64,
    ranges: &'a [u8],
    range_count: usize,
    /// The ECN counts (frame type 0x03).
    pub ecn: Option<EcnCounts>,
}

impl<'a> Ack<'a> {
    /// The acknowledged packet numbers, as ranges from the largest down.
    pub fn ranges(&self) -> AckRanges<'a> {
        AckRanges {
            r: Reader::new(self.ranges),
            next: Some(self.largest - self.first_range..=self.largest),
            left: self.range_count,
        }
    }

    /// Writes an ACK frame for `ranges`, which must be sorted from the
    /// largest down and not touch (each at least 2 below the one before).
    /// Returns `false` (and writes nothing) when they are not.
    pub fn write(
        out: &mut Vec<u8>,
        ranges: &[RangeInclusive<u64>],
        delay: u64,
        ecn: Option<EcnCounts>,
    ) -> bool {
        let Some(first) = ranges.first() else {
            return false;
        };
        if first.start() > first.end() || *first.end() > MAX_VARINT {
            return false;
        }
        for w in ranges.windows(2) {
            if w[1].start() > w[1].end() || w[1].end().saturating_add(2) > *w[0].start() {
                return false;
            }
        }
        varint::put(out, if ecn.is_some() { 0x03 } else { 0x02 });
        varint::put(out, *first.end());
        varint::put(out, delay);
        varint::put(out, (ranges.len() - 1) as u64);
        varint::put(out, first.end() - first.start());
        for w in ranges.windows(2) {
            varint::put(out, w[0].start() - w[1].end() - 2);
            varint::put(out, w[1].end() - w[1].start());
        }
        if let Some(e) = ecn {
            varint::put(out, e.ect0);
            varint::put(out, e.ect1);
            varint::put(out, e.ce);
        }
        true
    }
}

/// The ranges of an [`Ack`], largest first.
#[derive(Clone, Debug)]
pub struct AckRanges<'a> {
    r: Reader<'a>,
    next: Option<RangeInclusive<u64>>,
    left: usize,
}

impl Iterator for AckRanges<'_> {
    type Item = RangeInclusive<u64>;
    fn next(&mut self) -> Option<RangeInclusive<u64>> {
        let current = self.next.take()?;
        if self.left > 0 {
            self.left -= 1;
            // Checked at decode: these reads succeed and nothing underflows.
            if let (Ok(gap), Ok(len)) = (self.r.varint(), self.r.varint()) {
                let largest = current.start() - gap - 2;
                self.next = Some(largest - len..=largest);
            }
        }
        Some(current)
    }
}

/// A transport frame, borrowing its data from the packet.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A run of PADDING bytes, counted.
    Padding {
        /// How many.
        len: usize,
    },
    /// PING.
    Ping,
    /// ACK.
    Ack(Ack<'a>),
    /// RESET_STREAM.
    ResetStream {
        /// The stream.
        stream_id: u64,
        /// The application's error code.
        error_code: u64,
        /// The stream's final size.
        final_size: u64,
    },
    /// STOP_SENDING.
    StopSending {
        /// The stream.
        stream_id: u64,
        /// The application's error code.
        error_code: u64,
    },
    /// CRYPTO: handshake bytes.
    Crypto {
        /// Where they start in the handshake stream of this level.
        offset: u64,
        /// The bytes.
        data: &'a [u8],
    },
    /// NEW_TOKEN, from a server.
    NewToken {
        /// The token (never empty).
        token: &'a [u8],
    },
    /// STREAM.
    Stream {
        /// The stream.
        stream_id: u64,
        /// Where the bytes start in the stream.
        offset: u64,
        /// The bytes.
        data: &'a [u8],
        /// The stream ends after them.
        fin: bool,
    },
    /// MAX_DATA.
    MaxData(u64),
    /// MAX_STREAM_DATA.
    MaxStreamData {
        /// The stream.
        stream_id: u64,
        /// The new limit.
        max: u64,
    },
    /// MAX_STREAMS.
    MaxStreams {
        /// Bidirectional (0x12) or unidirectional (0x13).
        bidi: bool,
        /// The new limit, at most 2^60.
        max: u64,
    },
    /// DATA_BLOCKED.
    DataBlocked(u64),
    /// STREAM_DATA_BLOCKED.
    StreamDataBlocked {
        /// The stream.
        stream_id: u64,
        /// The limit it is blocked at.
        limit: u64,
    },
    /// STREAMS_BLOCKED.
    StreamsBlocked {
        /// Bidirectional (0x16) or unidirectional (0x17).
        bidi: bool,
        /// The limit it is blocked at, at most 2^60.
        limit: u64,
    },
    /// NEW_CONNECTION_ID.
    NewConnectionId {
        /// Its sequence number.
        sequence: u64,
        /// Retire every ID with a lower sequence number.
        retire_prior_to: u64,
        /// The ID, 1 to 20 bytes.
        cid: ConnectionId,
        /// Its stateless reset token.
        reset_token: ResetToken,
    },
    /// RETIRE_CONNECTION_ID.
    RetireConnectionId {
        /// The sequence number retired.
        sequence: u64,
    },
    /// PATH_CHALLENGE.
    PathChallenge([u8; 8]),
    /// PATH_RESPONSE.
    PathResponse([u8; 8]),
    /// CONNECTION_CLOSE.
    ConnectionClose {
        /// The error code: a transport code (0x1c) or the application's (0x1d).
        error_code: u64,
        /// For 0x1c, the type of the frame that caused it (0 when unknown);
        /// `None` for 0x1d.
        frame_type: Option<u64>,
        /// The reason, meant to be UTF-8.
        reason: &'a [u8],
    },
    /// HANDSHAKE_DONE, from a server.
    HandshakeDone,
}

impl Frame<'_> {
    /// The frame's type (for a STREAM frame, as this crate writes it).
    #[must_use]
    pub fn frame_type(&self) -> u64 {
        match self {
            Frame::Padding { .. } => 0x00,
            Frame::Ping => 0x01,
            Frame::Ack(a) => {
                if a.ecn.is_some() {
                    0x03
                } else {
                    0x02
                }
            }
            Frame::ResetStream { .. } => 0x04,
            Frame::StopSending { .. } => 0x05,
            Frame::Crypto { .. } => 0x06,
            Frame::NewToken { .. } => 0x07,
            Frame::Stream { offset, fin, .. } => {
                0x08 | 0x02 | if *offset > 0 { 0x04 } else { 0 } | u64::from(*fin)
            }
            Frame::MaxData(_) => 0x10,
            Frame::MaxStreamData { .. } => 0x11,
            Frame::MaxStreams { bidi, .. } => 0x12 | u64::from(!*bidi),
            Frame::DataBlocked(_) => 0x14,
            Frame::StreamDataBlocked { .. } => 0x15,
            Frame::StreamsBlocked { bidi, .. } => 0x16 | u64::from(!*bidi),
            Frame::NewConnectionId { .. } => 0x18,
            Frame::RetireConnectionId { .. } => 0x19,
            Frame::PathChallenge(_) => 0x1a,
            Frame::PathResponse(_) => 0x1b,
            Frame::ConnectionClose { frame_type, .. } => {
                if frame_type.is_some() {
                    0x1c
                } else {
                    0x1d
                }
            }
            Frame::HandshakeDone => 0x1e,
        }
    }

    /// Whether a packet of `kind` may carry this frame (RFC 9000 section 12.4,
    /// table 3).
    #[must_use]
    pub fn allowed_in(&self, kind: PacketKind) -> bool {
        use PacketKind::{Handshake, Initial, OneRtt, ZeroRtt};
        match self {
            Frame::Padding { .. } | Frame::Ping => true,
            Frame::ConnectionClose {
                frame_type: Some(_),
                ..
            } => true,
            Frame::Ack(_) | Frame::Crypto { .. } => matches!(kind, Initial | Handshake | OneRtt),
            Frame::NewToken { .. } | Frame::PathResponse(_) | Frame::HandshakeDone => {
                kind == OneRtt
            }
            _ => matches!(kind, ZeroRtt | OneRtt),
        }
    }

    /// Whether receiving it calls for an acknowledgement: every frame but
    /// ACK, PADDING, and CONNECTION_CLOSE (RFC 9002 section 2).
    #[must_use]
    pub fn is_ack_eliciting(&self) -> bool {
        !matches!(
            self,
            Frame::Ack(_) | Frame::Padding { .. } | Frame::ConnectionClose { .. }
        )
    }

    /// Writes the frame.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let put = |out: &mut Vec<u8>, v: u64| varint::put(out, v);
        match self {
            Frame::Padding { len } => out.resize(out.len() + len, 0),
            Frame::Ping | Frame::HandshakeDone => put(out, self.frame_type()),
            Frame::Ack(a) => {
                put(out, self.frame_type());
                put(out, a.largest);
                put(out, a.delay);
                put(out, a.range_count as u64);
                put(out, a.first_range);
                out.extend_from_slice(a.ranges);
                if let Some(e) = a.ecn {
                    put(out, e.ect0);
                    put(out, e.ect1);
                    put(out, e.ce);
                }
            }
            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                put(out, 0x04);
                put(out, *stream_id);
                put(out, *error_code);
                put(out, *final_size);
            }
            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                put(out, 0x05);
                put(out, *stream_id);
                put(out, *error_code);
            }
            Frame::Crypto { offset, data } => {
                put(out, 0x06);
                put(out, *offset);
                put(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Frame::NewToken { token } => {
                put(out, 0x07);
                put(out, token.len() as u64);
                out.extend_from_slice(token);
            }
            Frame::Stream {
                stream_id,
                offset,
                data,
                ..
            } => {
                put(out, self.frame_type());
                put(out, *stream_id);
                if *offset > 0 {
                    put(out, *offset);
                }
                put(out, data.len() as u64);
                out.extend_from_slice(data);
            }
            Frame::MaxData(v) | Frame::DataBlocked(v) => {
                put(out, self.frame_type());
                put(out, *v);
            }
            Frame::MaxStreamData { stream_id, max: v }
            | Frame::StreamDataBlocked {
                stream_id,
                limit: v,
            } => {
                put(out, self.frame_type());
                put(out, *stream_id);
                put(out, *v);
            }
            Frame::MaxStreams { max: v, .. } | Frame::StreamsBlocked { limit: v, .. } => {
                put(out, self.frame_type());
                put(out, *v);
            }
            Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                cid,
                reset_token,
            } => {
                put(out, 0x18);
                put(out, *sequence);
                put(out, *retire_prior_to);
                out.push(cid.len() as u8);
                out.extend_from_slice(cid.as_slice());
                out.extend_from_slice(reset_token.as_bytes());
            }
            Frame::RetireConnectionId { sequence } => {
                put(out, 0x19);
                put(out, *sequence);
            }
            Frame::PathChallenge(d) | Frame::PathResponse(d) => {
                put(out, self.frame_type());
                out.extend_from_slice(d);
            }
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                put(out, self.frame_type());
                put(out, *error_code);
                if let Some(t) = frame_type {
                    put(out, *t);
                }
                put(out, reason.len() as u64);
                out.extend_from_slice(reason);
            }
        }
    }
}

/// Reads one frame from the front of `r`.
fn decode<'a>(r: &mut Reader<'a>) -> Result<Frame<'a>, DecodeError> {
    let (ty, n) = r.varint_len()?;
    // Frame types are written on the fewest bytes (RFC 9000 section 12.4).
    if n != varint::size(ty) {
        return Err(DecodeError::UnknownFrame { frame_type: ty });
    }
    let bad = DecodeError::BadFrame { frame_type: ty };
    let frame = match ty {
        0x00 => {
            let mut len = 1;
            while r.peek_u8() == Some(0) {
                r.u8()?;
                len += 1;
            }
            Frame::Padding { len }
        }
        0x01 => Frame::Ping,
        0x02 | 0x03 => {
            let largest = r.varint()?;
            let delay = r.varint()?;
            let count = r.varint()?;
            let first_range = r.varint()?;
            if count > MAX_ACK_RANGES as u64 {
                return Err(DecodeError::OverBudget);
            }
            let mut smallest = largest.checked_sub(first_range).ok_or(bad)?;
            // Walk the ranges on a copy, checking each, then take their bytes.
            let start = r.position();
            let mut walk = r.clone();
            for _ in 0..count {
                let gap = walk.varint()?;
                let len = walk.varint()?;
                let next_largest = smallest
                    .checked_sub(gap)
                    .and_then(|v| v.checked_sub(2))
                    .ok_or(bad)?;
                smallest = next_largest.checked_sub(len).ok_or(bad)?;
            }
            let raw = r.bytes(walk.position() - start)?;
            let ecn = if ty == 0x03 {
                Some(EcnCounts {
                    ect0: r.varint()?,
                    ect1: r.varint()?,
                    ce: r.varint()?,
                })
            } else {
                None
            };
            Frame::Ack(Ack {
                largest,
                delay,
                first_range,
                ranges: raw,
                range_count: count as usize,
                ecn,
            })
        }
        0x04 => Frame::ResetStream {
            stream_id: r.varint()?,
            error_code: r.varint()?,
            final_size: r.varint()?,
        },
        0x05 => Frame::StopSending {
            stream_id: r.varint()?,
            error_code: r.varint()?,
        },
        0x06 => {
            let offset = r.varint()?;
            let len = r.length()?;
            if offset + len as u64 > MAX_VARINT {
                return Err(DecodeError::TooLarge);
            }
            Frame::Crypto {
                offset,
                data: r.bytes(len)?,
            }
        }
        0x07 => {
            let len = r.length()?;
            if len == 0 {
                return Err(bad);
            }
            Frame::NewToken {
                token: r.bytes(len)?,
            }
        }
        0x08..=0x0f => {
            let stream_id = r.varint()?;
            let offset = if ty & 0x04 != 0 { r.varint()? } else { 0 };
            let data = if ty & 0x02 != 0 {
                let len = r.length()?;
                r.bytes(len)?
            } else {
                r.rest()
            };
            if offset + data.len() as u64 > MAX_VARINT {
                return Err(DecodeError::TooLarge);
            }
            Frame::Stream {
                stream_id,
                offset,
                data,
                fin: ty & 0x01 != 0,
            }
        }
        0x10 => Frame::MaxData(r.varint()?),
        0x11 => Frame::MaxStreamData {
            stream_id: r.varint()?,
            max: r.varint()?,
        },
        0x12 | 0x13 => {
            let max = r.varint()?;
            if max > MAX_STREAMS {
                return Err(DecodeError::TooLarge);
            }
            Frame::MaxStreams {
                bidi: ty == 0x12,
                max,
            }
        }
        0x14 => Frame::DataBlocked(r.varint()?),
        0x15 => Frame::StreamDataBlocked {
            stream_id: r.varint()?,
            limit: r.varint()?,
        },
        0x16 | 0x17 => {
            let limit = r.varint()?;
            if limit > MAX_STREAMS {
                return Err(DecodeError::TooLarge);
            }
            Frame::StreamsBlocked {
                bidi: ty == 0x16,
                limit,
            }
        }
        0x18 => {
            let sequence = r.varint()?;
            let retire_prior_to = r.varint()?;
            let len = usize::from(r.u8()?);
            if len == 0 || len > crate::cid::MAX_CID_LEN {
                return Err(bad);
            }
            if retire_prior_to > sequence {
                return Err(bad);
            }
            let cid = ConnectionId::new(r.bytes(len)?).map_err(|_| bad)?;
            Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                cid,
                reset_token: ResetToken::new(r.array()?),
            }
        }
        0x19 => Frame::RetireConnectionId {
            sequence: r.varint()?,
        },
        0x1a => Frame::PathChallenge(r.array()?),
        0x1b => Frame::PathResponse(r.array()?),
        0x1c | 0x1d => {
            let error_code = r.varint()?;
            let frame_type = if ty == 0x1c { Some(r.varint()?) } else { None };
            let len = r.length()?;
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason: r.bytes(len)?,
            }
        }
        0x1e => Frame::HandshakeDone,
        _ => return Err(DecodeError::UnknownFrame { frame_type: ty }),
    };
    Ok(frame)
}

/// Reads the frames of a packet payload of `kind`, in order. An empty payload,
/// a malformed frame, or a frame `kind` must not carry ends the iteration with
/// an error.
///
/// ```
/// use quic_net::{Frame, PacketKind, frames};
/// let mut payload = Vec::new();
/// Frame::Ping.encode(&mut payload);
/// Frame::Padding { len: 3 }.encode(&mut payload);
/// let got: Vec<_> = frames(&payload, PacketKind::Initial).collect::<Result<_, _>>()?;
/// assert_eq!(got, vec![Frame::Ping, Frame::Padding { len: 3 }]);
/// // HANDSHAKE_DONE in an Initial packet is a protocol violation.
/// let mut bad = Vec::new();
/// Frame::HandshakeDone.encode(&mut bad);
/// assert!(frames(&bad, PacketKind::Initial).next().unwrap().is_err());
/// # Ok::<(), quic_net::DecodeError>(())
/// ```
pub fn frames(payload: &[u8], kind: PacketKind) -> Frames<'_> {
    Frames {
        r: Reader::new(payload),
        kind,
        started: false,
        failed: false,
    }
}

/// The iterator of [`frames`].
#[derive(Debug)]
pub struct Frames<'a> {
    r: Reader<'a>,
    kind: PacketKind,
    started: bool,
    failed: bool,
}

impl<'a> Iterator for Frames<'a> {
    type Item = Result<Frame<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        if self.r.is_empty() {
            if self.started {
                return None;
            }
            // A packet with no frames (RFC 9000 section 12.4).
            self.failed = true;
            return Some(Err(DecodeError::BadPacket));
        }
        self.started = true;
        let result = decode(&mut self.r).and_then(|f| {
            if f.allowed_in(self.kind) {
                Ok(f)
            } else {
                Err(DecodeError::WrongPacketType {
                    frame_type: f.frame_type(),
                })
            }
        });
        if result.is_err() {
            self.failed = true;
        }
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(bytes: &[u8]) -> Result<Frame<'_>, DecodeError> {
        frames(bytes, PacketKind::OneRtt).next().unwrap()
    }

    fn round_trip(f: &Frame<'_>) {
        let mut out = Vec::new();
        f.encode(&mut out);
        assert_eq!(&one(&out).unwrap(), f, "{out:?}");
        for cut in 1..out.len() {
            // A cut frame is an error, or (for frames ending in data without
            // a length) a shorter frame; never a panic.
            let _ = frames(&out[..cut], PacketKind::OneRtt).count();
        }
    }

    #[test]
    fn every_frame_round_trips() {
        let cid = ConnectionId::new(&[1, 2, 3, 4]).unwrap();
        let mut ack_bytes = Vec::new();
        assert!(Ack::write(
            &mut ack_bytes,
            &[90..=100, 50..=80, 0..=10],
            7,
            None
        ));
        let ack = one(&ack_bytes).unwrap();
        let mut ecn_bytes = Vec::new();
        Ack::write(
            &mut ecn_bytes,
            &[RangeInclusive::new(5, 5)],
            0,
            Some(EcnCounts {
                ect0: 1,
                ect1: 2,
                ce: 3,
            }),
        );
        let ecn = one(&ecn_bytes).unwrap();
        let frames = [
            Frame::Padding { len: 1 },
            Frame::Ping,
            ack,
            ecn,
            Frame::ResetStream {
                stream_id: 4,
                error_code: 9,
                final_size: 1000,
            },
            Frame::StopSending {
                stream_id: 8,
                error_code: 1,
            },
            Frame::Crypto {
                offset: 100,
                data: b"hello",
            },
            Frame::NewToken { token: b"token" },
            Frame::Stream {
                stream_id: 0,
                offset: 0,
                data: b"abc",
                fin: false,
            },
            Frame::Stream {
                stream_id: 4,
                offset: 1 << 40,
                data: b"",
                fin: true,
            },
            Frame::MaxData(1 << 30),
            Frame::MaxStreamData {
                stream_id: 3,
                max: 77,
            },
            Frame::MaxStreams {
                bidi: true,
                max: MAX_STREAMS,
            },
            Frame::MaxStreams {
                bidi: false,
                max: 3,
            },
            Frame::DataBlocked(5),
            Frame::StreamDataBlocked {
                stream_id: 2,
                limit: 9,
            },
            Frame::StreamsBlocked {
                bidi: false,
                limit: 100,
            },
            Frame::NewConnectionId {
                sequence: 3,
                retire_prior_to: 1,
                cid,
                reset_token: ResetToken::new([7; 16]),
            },
            Frame::RetireConnectionId { sequence: 2 },
            Frame::PathChallenge([1; 8]),
            Frame::PathResponse([2; 8]),
            Frame::ConnectionClose {
                error_code: 0xa,
                frame_type: Some(0x06),
                reason: b"bad",
            },
            Frame::ConnectionClose {
                error_code: 42,
                frame_type: None,
                reason: b"",
            },
            Frame::HandshakeDone,
        ];
        for f in &frames {
            round_trip(f);
        }
    }

    #[test]
    fn ack_ranges() {
        let mut out = Vec::new();
        assert!(Ack::write(&mut out, &[90..=100, 50..=80, 0..=10], 7, None));
        let Frame::Ack(a) = one(&out).unwrap() else {
            panic!()
        };
        assert_eq!(
            a.ranges().collect::<Vec<_>>(),
            vec![90..=100, 50..=80, 0..=10]
        );
        // Ranges that touch, overlap, or are out of order are not written.
        assert!(!Ack::write(&mut Vec::new(), &[10..=20, 9..=9], 0, None));
        assert!(!Ack::write(&mut Vec::new(), &[10..=20, 30..=40], 0, None));
        assert!(!Ack::write(&mut Vec::new(), &[], 0, None));
        // A first range past zero.
        assert_eq!(
            one(&[0x02, 5, 0, 0, 6]),
            Err(DecodeError::BadFrame { frame_type: 2 })
        );
        // A gap past zero.
        assert_eq!(
            one(&[0x02, 10, 0, 1, 2, 9, 0]),
            Err(DecodeError::BadFrame { frame_type: 2 })
        );
        // More ranges than the budget.
        let mut many = vec![0x02];
        varint::put(&mut many, MAX_VARINT);
        many.push(0);
        varint::put(&mut many, MAX_ACK_RANGES as u64 + 1);
        many.push(0);
        assert_eq!(one(&many), Err(DecodeError::OverBudget));
    }

    #[test]
    fn field_rules() {
        // A frame type on more bytes than it needs.
        assert_eq!(
            one(&[0x40, 0x01]),
            Err(DecodeError::UnknownFrame { frame_type: 1 })
        );
        // Unknown types, including DATAGRAM before it is negotiated.
        assert_eq!(
            one(&[0x1f]),
            Err(DecodeError::UnknownFrame { frame_type: 0x1f })
        );
        assert_eq!(
            one(&[0x30, 0]),
            Err(DecodeError::UnknownFrame { frame_type: 0x30 })
        );
        // An empty NEW_TOKEN.
        assert_eq!(
            one(&[0x07, 0]),
            Err(DecodeError::BadFrame { frame_type: 7 })
        );
        // NEW_CONNECTION_ID with an empty or long ID, or retire_prior_to past sequence.
        let mut f = vec![0x18, 1, 0, 0];
        f.extend_from_slice(&[0; 16]);
        assert_eq!(one(&f), Err(DecodeError::BadFrame { frame_type: 0x18 }));
        let mut f = vec![0x18, 1, 2, 4, 1, 2, 3, 4];
        f.extend_from_slice(&[0; 16]);
        assert_eq!(one(&f), Err(DecodeError::BadFrame { frame_type: 0x18 }));
        let mut f = vec![0x18, 1, 0, 21];
        f.extend_from_slice(&[0; 37]);
        assert_eq!(one(&f), Err(DecodeError::BadFrame { frame_type: 0x18 }));
        // MAX_STREAMS over 2^60.
        let mut f = vec![0x12];
        varint::put(&mut f, MAX_STREAMS + 1);
        assert_eq!(one(&f), Err(DecodeError::TooLarge));
        // STREAM past 2^62 - 1.
        let mut f = vec![0x0e, 0];
        varint::put(&mut f, MAX_VARINT);
        f.extend_from_slice(&[2, 1, 1]);
        assert_eq!(one(&f), Err(DecodeError::TooLarge));
        // A STREAM frame without a length takes the rest of the packet.
        let Frame::Stream { data, .. } = one(&[0x08, 4, b'x', b'y']).unwrap() else {
            panic!()
        };
        assert_eq!(data, b"xy");
        // Padding runs collapse.
        assert_eq!(one(&[0; 9]).unwrap(), Frame::Padding { len: 9 });
    }

    #[test]
    fn packet_type_rules() {
        let check = |f: Frame<'_>, ok: &[PacketKind]| {
            for k in [
                PacketKind::Initial,
                PacketKind::Handshake,
                PacketKind::ZeroRtt,
                PacketKind::OneRtt,
            ] {
                assert_eq!(f.allowed_in(k), ok.contains(&k), "{f:?} in {k:?}");
            }
        };
        use PacketKind::*;
        check(Frame::Ping, &[Initial, Handshake, ZeroRtt, OneRtt]);
        check(
            Frame::Crypto {
                offset: 0,
                data: b"",
            },
            &[Initial, Handshake, OneRtt],
        );
        check(
            Frame::Stream {
                stream_id: 0,
                offset: 0,
                data: b"",
                fin: false,
            },
            &[ZeroRtt, OneRtt],
        );
        check(Frame::NewToken { token: b"t" }, &[OneRtt]);
        check(Frame::PathResponse([0; 8]), &[OneRtt]);
        check(Frame::PathChallenge([0; 8]), &[ZeroRtt, OneRtt]);
        check(Frame::HandshakeDone, &[OneRtt]);
        check(
            Frame::ConnectionClose {
                error_code: 0,
                frame_type: Some(0),
                reason: b"",
            },
            &[Initial, Handshake, ZeroRtt, OneRtt],
        );
        check(
            Frame::ConnectionClose {
                error_code: 0,
                frame_type: None,
                reason: b"",
            },
            &[ZeroRtt, OneRtt],
        );
        // An empty payload.
        assert_eq!(
            frames(&[], OneRtt).next(),
            Some(Err(DecodeError::BadPacket))
        );
        // Iteration stops after the first error.
        assert_eq!(frames(&[0x1f, 0x01], OneRtt).count(), 1);
        assert!(
            !Frame::Ack(match one(&[0x02, 0, 0, 0, 0]).unwrap() {
                Frame::Ack(a) => a,
                _ => panic!(),
            })
            .is_ack_eliciting()
        );
        assert!(Frame::Ping.is_ack_eliciting());
    }
}
