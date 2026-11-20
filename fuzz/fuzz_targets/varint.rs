//! Variable-length integers: no panic, and a decoded value encodes back to
//! the shortest form, which decodes to the same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use quic_net::VarInt;

fuzz_target!(|data: &[u8]| {
    if let Ok((v, n)) = VarInt::decode(data) {
        assert!(n <= data.len() && v.get() <= quic_net::MAX_VARINT);
        let mut out = Vec::new();
        v.encode(&mut out);
        assert!(out.len() <= n);
        assert_eq!(VarInt::decode(&out), Ok((v, out.len())));
    }
});
