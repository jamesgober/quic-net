//! Frames: no panic, and every frame decoded writes back to bytes that
//! decode to the same frame.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quic_net::{Frame, PacketKind, frames};

fuzz_target!(|data: &[u8]| {
    let kinds = [PacketKind::Initial, PacketKind::Handshake, PacketKind::ZeroRtt, PacketKind::OneRtt];
    let Some((&k, payload)) = data.split_first() else {
        return;
    };
    let kind = kinds[usize::from(k % 4)];
    for f in frames(payload, kind) {
        let Ok(f) = f else { break };
        assert!(f.allowed_in(kind));
        let mut out = Vec::new();
        f.encode(&mut out);
        let again: Vec<_> = frames(&out, kind).collect();
        assert_eq!(again.len(), 1, "{f:?}");
        assert_eq!(again[0].as_ref(), Ok(&f));
        if let Frame::Ack(a) = &f {
            let ranges: Vec<_> = a.ranges().collect();
            assert!(ranges.len() <= quic_net::MAX_ACK_RANGES + 1);
            assert!(ranges.windows(2).all(|w| w[1].end() + 2 <= *w[0].start()));
        }
    }
});
