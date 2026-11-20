//! A stream sent over a channel that loses, duplicates, and reorders
//! packets and acknowledgements, with stream and connection flow control.
//! Every choice comes from the input bytes, so the CI test and the
//! `streams` fuzz target run the same model.
//!
//! Checked: the receiver reads exactly the bytes written, in order; the
//! sender ends with every byte and the end of the stream acknowledged and
//! its buffer empty; neither side's memory passes its limit; neither side
//! ever reports a transport error.

#![allow(dead_code)]

use quic_net::{
    Frame, PacketKind, RecvCredit, RecvStream, SendCredit, SendState, SendStream, Side, StreamId,
    frames,
};

/// Reads choices from the input; past its end, a fixed sequence keeps the
/// run going so it always finishes.
pub struct Choices<'a> {
    data: &'a [u8],
    seed: u64,
}

impl<'a> Choices<'a> {
    pub fn new(data: &'a [u8]) -> Choices<'a> {
        Choices {
            data,
            seed: 0x2545_f491_4f6c_dd1d,
        }
    }

    pub fn byte(&mut self) -> u8 {
        if let Some((b, rest)) = self.data.split_first() {
            self.data = rest;
            return *b;
        }
        self.seed ^= self.seed << 13;
        self.seed ^= self.seed >> 7;
        self.seed ^= self.seed << 17;
        self.seed as u8
    }

    pub fn below(&mut self, n: usize) -> usize {
        usize::from(self.byte()) % n.max(1)
    }

    /// What happens to a packet: from the input while it lasts, then
    /// delivered and acknowledged, so every run ends.
    pub fn fate(&mut self) -> u8 {
        if self.data.is_empty() {
            7
        } else {
            self.byte() % 8
        }
    }
}

pub struct Outcome {
    pub rounds: usize,
    pub packets: usize,
    pub lost: usize,
}

const STREAM_WINDOW: u64 = 4_000;
const CONN_WINDOW: u64 = 6_000;
const BUFFER: usize = 5_000;

pub fn run(input: &[u8], len: usize) -> Result<Outcome, String> {
    let mut c = Choices::new(input);
    let source: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
    let id = StreamId::new(Side::Client, true, 0).ok_or("id")?;

    let mut send = SendStream::new(STREAM_WINDOW, BUFFER);
    let mut conn_send = SendCredit::new(CONN_WINDOW);
    let mut recv = RecvStream::new(STREAM_WINDOW);
    let mut conn_recv = RecvCredit::new(CONN_WINDOW);

    let mut written = 0usize;
    let mut got = Vec::with_capacity(len);
    // Packets in flight: the chunk and its encoded frame.
    let mut flight: Vec<(quic_net::Chunk, Vec<u8>)> = Vec::new();
    let mut out = Outcome {
        rounds: 0,
        packets: 0,
        lost: 0,
    };

    while !(recv.is_finished() && send.state() == SendState::DataRecvd) {
        out.rounds += 1;
        if out.rounds > 200_000 {
            return Err(format!(
                "no progress: read {} of {len}, sender {:?}",
                got.len(),
                send.state()
            ));
        }
        // The application writes what fits, then finishes.
        if written < len {
            let n = 1 + c.below(3000);
            written += send.write(&source[written..len.min(written + n)]);
        }
        if written == len {
            send.finish();
        }
        // The sender fills a few packets.
        for _ in 0..1 + c.below(4) {
            let max = 1 + c.below(1400);
            let Some(chunk) = send.next_chunk(max, conn_send.available()) else {
                break;
            };
            conn_send.consume(chunk.new);
            let mut frame = Vec::new();
            send.write_frame(id, &chunk, &mut frame);
            flight.push((chunk, frame));
            out.packets += 1;
        }
        // The channel delivers some of what is in flight, in any order.
        let deliver = c.below(flight.len() + 1);
        for _ in 0..deliver {
            let i = c.below(flight.len());
            let (chunk, frame) = flight.swap_remove(i);
            match c.fate() {
                // Lost: the sender learns of it and sends it again.
                0 => {
                    out.lost += 1;
                    send.on_lost(&chunk);
                }
                fate => {
                    let Some(Ok(Frame::Stream {
                        offset, data, fin, ..
                    })) = frames(&frame, PacketKind::OneRtt).next()
                    else {
                        return Err(format!("frame does not decode: {frame:?}"));
                    };
                    let copies = if fate == 1 { 2 } else { 1 };
                    for _ in 0..copies {
                        let growth = recv
                            .on_stream(offset, data, fin)
                            .map_err(|e| format!("receiver refused: {e:?}"))?;
                        conn_recv
                            .receive_more(growth)
                            .map_err(|e| format!("connection refused: {e:?}"))?;
                    }
                    // The acknowledgement may be lost: the sender then
                    // thinks the packet lost, and sends it again.
                    if fate == 2 {
                        send.on_lost(&chunk);
                    } else {
                        send.on_acked(&chunk);
                    }
                }
            }
        }
        // The application reads some.
        let mut buf = vec![0u8; c.below(5000)];
        let n = recv.read(&mut buf);
        got.extend_from_slice(&buf[..n]);
        conn_recv.consumed(recv.take_consumed());
        // Credit updates reach the sender.
        if let Some(max) = recv.update() {
            send.raise(max);
        }
        if let Some(max) = conn_recv.update() {
            conn_send.raise(max);
        }
        if send.held() > BUFFER || recv.held() as u64 > STREAM_WINDOW {
            return Err(format!(
                "memory over the limit: sender {} receiver {}",
                send.held(),
                recv.held()
            ));
        }
        if got.len() > len || got[..] != source[..got.len()] {
            return Err(format!("read bytes differ at {}", got.len()));
        }
    }
    if got != source {
        return Err(format!("read {} of {len}", got.len()));
    }
    if send.held() != 0 {
        return Err("the sender still holds data".into());
    }
    Ok(out)
}
