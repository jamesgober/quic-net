//! Packet protection. Two oracles on one input:
//!
//! - Received bytes: every packet of the datagram goes through header
//!   protection removal and opening under the Initial keys of a fixed
//!   connection ID. No panic, and anything that opens has its payload
//!   inside the packet.
//! - A round trip: a long or short header with the input's packet number,
//!   its length, and payload is sealed, parsed, and opened again, and must
//!   come back exactly.
#![no_main]

#[path = "../../tests/support/ciphers.rs"]
mod ciphers;

use std::sync::OnceLock;

use ciphers::{Hp, Key};
use libfuzzer_sys::fuzz_target;
use quic_net::{
    ConnectionId, InitialSecrets, LongHeader, LongType, TAG_LEN, coalesced, open_payload,
    parse_packet, remove_header_protection, seal_packet, write_short,
};

struct Keys {
    key: Key,
    hp: Hp,
}

fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    K.get_or_init(|| {
        let dcid = ConnectionId::new(&[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]).unwrap();
        let s = InitialSecrets::new(&dcid).unwrap();
        let m = s.client.key_material(16).unwrap();
        Keys {
            key: Key::aes(&m),
            hp: Hp::aes(&m),
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let k = keys();
    let Some((&control, rest)) = data.split_first() else {
        return;
    };

    // Received bytes.
    let mut datagram = rest.to_vec();
    let spans: Vec<(usize, usize, usize)> = coalesced(rest, 8)
        .filter_map(Result::ok)
        .map(|p| {
            let start = p.bytes.as_ptr() as usize - rest.as_ptr() as usize;
            (start, start + p.bytes.len(), p.pn_offset)
        })
        .collect();
    for (start, end, pn_offset) in spans {
        if pn_offset == 0 {
            continue;
        }
        let packet = &mut datagram[start..end];
        let largest = (control & 1 == 1).then_some(u64::from(control) << 20);
        if let Ok(u) = remove_header_protection(packet, pn_offset, largest, &k.hp) {
            assert!((1..=4).contains(&u.pn_len));
            if let Ok(r) = open_payload(packet, &u, &k.key) {
                assert!(r.end + TAG_LEN == packet.len());
            }
        }
    }

    // A round trip.
    if rest.len() < 4 {
        return;
    }
    let pn_len = usize::from(control & 0x03) + 1;
    let pn = u64::from(u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]))
        & ((1u64 << (8 * pn_len)) - 1);
    let mut payload = rest[4..].to_vec();
    // Enough payload to sample.
    payload.resize(payload.len().max(4), 0);
    let dcid = ConnectionId::new(&[7; 8]).unwrap();
    let mut packet = Vec::new();
    let pn_offset = if control & 0x04 == 0 {
        write_short(&mut packet, &dcid, control & 0x08 != 0, control & 0x10 != 0, pn, pn_len)
    } else {
        let ty = if control & 0x08 == 0 {
            LongType::Initial
        } else {
            LongType::Handshake
        };
        let h = LongHeader {
            ty,
            dcid,
            scid: ConnectionId::EMPTY,
            token: &[],
        };
        h.encode(&mut packet, pn, pn_len, payload.len() + TAG_LEN)
    };
    let header_len = packet.len();
    packet.extend_from_slice(&payload);
    packet.extend_from_slice(&[0; TAG_LEN]);
    let plain = packet.clone();
    seal_packet(&mut packet, pn_offset, pn, &k.key, &k.hp).expect("seal");
    let parsed = parse_packet(&packet, 8).expect("a sealed packet parses");
    assert_eq!(parsed.pn_offset, pn_offset);
    assert_eq!(parsed.bytes.len(), packet.len());
    let largest = pn.checked_sub(1);
    let u = remove_header_protection(&mut packet, pn_offset, largest, &k.hp).expect("header");
    assert_eq!((u.pn, u.pn_len, u.header_len()), (pn, pn_len, header_len));
    let r = open_payload(&mut packet, &u, &k.key).expect("opens");
    assert_eq!(&packet[r], &payload[..]);
    assert_eq!(packet[..header_len], plain[..header_len]);
});
