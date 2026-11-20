//! Connection ID bookkeeping driven by arbitrary frames: no panic, never
//! more active IDs than the limit, and every retirement a sequence number
//! that was seen.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quic_net::{ConnectionId, LocalCids, PeerCids, ResetKey, ResetToken};

fuzz_target!(|data: &[u8]| {
    let Some((&limit, ops)) = data.split_first() else {
        return;
    };
    let limit = u64::from(limit % 8).max(2);
    let mut peer = PeerCids::new(ConnectionId::new(&[0xAA]).unwrap(), limit);
    let mut local = LocalCids::new(ConnectionId::new(&[0xBB; 8]).unwrap());
    local.set_peer_limit(limit);
    let key = ResetKey::new([7; 32]);
    let mut max_seq = 0u64;
    for op in ops.chunks(4) {
        if op.len() < 4 {
            break;
        }
        let (seq, rpt, id) = (u64::from(op[1] % 32), u64::from(op[2] % 32), op[3]);
        match op[0] % 3 {
            0 => {
                let cid = ConnectionId::new(&[id; 4]).unwrap();
                match peer.on_new_connection_id(seq, rpt, cid, ResetToken::new([id; 16])) {
                    Ok(retired) => {
                        max_seq = max_seq.max(seq);
                        assert!(retired.iter().all(|&s| s <= max_seq));
                    }
                    Err(_) => return,
                }
                assert!(peer.active().count() as u64 <= limit);
            }
            1 => {
                let _ = local.issue(ConnectionId::new(&[id; 8]).unwrap(), &key);
                assert!(local.active_count() as u64 <= limit);
            }
            _ => {
                let _ = local.on_retire(seq, &ConnectionId::new(&[id; 8]).unwrap());
            }
        }
    }
});
