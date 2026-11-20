//! Streams. Two oracles on one input:
//!
//! - A receive stream under arbitrary frames, resets, stops, and reads:
//!   no panic; every byte read is the source's byte at that offset; memory
//!   never passes the window; nothing is accepted past the stream's limit.
//! - A stream sent over a channel whose losses, duplicates, reordering, and
//!   lost acknowledgements come from the input (`tests/support/channel.rs`):
//!   the bytes arrive exactly, and both sides end clean.
#![no_main]

#[path = "../../tests/support/channel.rs"]
mod channel;

use libfuzzer_sys::fuzz_target;
use quic_net::{RecvState, RecvStream};

const WINDOW: u64 = 3000;

fn source(offset: u64) -> u8 {
    (offset.wrapping_mul(131) % 251) as u8
}

fn receive(data: &[u8]) {
    let mut s = RecvStream::new(WINDOW);
    let mut read_at = 0u64;
    let mut ok_end = 0u64;
    let mut advertised = WINDOW;
    let mut it = data.chunks_exact(5);
    for op in &mut it {
        let offset = u64::from(u16::from_le_bytes([op[1], op[2]])) % 4000;
        let len = u64::from(op[3]) * 8 % 600;
        let bytes: Vec<u8> = (offset..offset + len).map(source).collect();
        match op[0] % 8 {
            0..=3 => {
                if s.on_stream(offset, &bytes, op[4] & 1 == 1).is_ok() {
                    assert!(offset + len <= s.final_size().unwrap_or(u64::MAX));
                    ok_end = ok_end.max(offset + len);
                }
            }
            4 => {
                let _ = s.on_reset(u64::from(op[4]), offset);
            }
            5 => s.stop(),
            _ => {
                let mut buf = vec![0u8; usize::from(op[4]) * 4];
                let n = s.read(&mut buf);
                for (i, b) in buf[..n].iter().enumerate() {
                    assert_eq!(*b, source(read_at + i as u64), "byte {}", read_at + i as u64);
                }
                read_at += n as u64;
            }
        }
        let _ = s.take_consumed();
        assert!(ok_end <= advertised, "{ok_end} past {advertised}");
        if let Some(max) = s.update() {
            assert!(max > advertised);
            advertised = max;
        }
        assert!(s.held() as u64 <= WINDOW);
        if let RecvState::ResetRecvd(_) = s.state() {
            assert_eq!(s.readable(), 0);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let (first, rest) = data.split_at(data.len() / 2);
    receive(first);
    let len = rest.first().map_or(0, |b| usize::from(*b) * 97);
    if let Err(e) = channel::run(rest.get(1..).unwrap_or(&[]), len) {
        panic!("{e}");
    }
});
