//! Packet headers and coalescing: no panic, every packet inside the
//! datagram, the packet number offset inside the packet, and at most
//! MAX_COALESCED packets.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quic_net::{MAX_COALESCED, coalesced, parse_packet};

fuzz_target!(|data: &[u8]| {
    let Some((&len, datagram)) = data.split_first() else {
        return;
    };
    let short = usize::from(len % 21);
    if let Ok(p) = parse_packet(datagram, short) {
        assert!(p.bytes.len() <= datagram.len());
        assert!(p.pn_offset <= p.bytes.len());
        let _ = p.header.versions().count();
    }
    let mut total = 0;
    for (i, p) in coalesced(datagram, short).enumerate() {
        assert!(i < MAX_COALESCED);
        if let Ok(p) = p {
            total += p.bytes.len();
        }
    }
    assert!(total <= datagram.len());
});
