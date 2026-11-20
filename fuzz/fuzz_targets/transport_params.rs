//! Transport parameters: no panic, and what decodes encodes back to the
//! same parameters, from either side.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quic_net::{Side, TransportParameters};

fuzz_target!(|data: &[u8]| {
    for side in [Side::Client, Side::Server] {
        if let Ok(p) = TransportParameters::decode(data, side) {
            let mut out = Vec::new();
            p.encode(&mut out);
            assert_eq!(TransportParameters::decode(&out, side), Ok(p));
        }
    }
});
