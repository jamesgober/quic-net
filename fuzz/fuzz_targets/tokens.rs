//! Address validation. Three oracles on one input:
//!
//! - Arbitrary bytes checked as a token, from any address at any time: no
//!   panic, and never valid (a forgery would have to break the AEAD).
//! - Tokens issued for the input's addresses, IDs, and times: valid exactly
//!   when checked from the same address (and port, for Retry) within the
//!   lifetime, and then carrying the same IDs.
//! - The amplification limit: a sender that keeps to the allowance never
//!   sends more than three times what it received.
#![no_main]

use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use quic_net::{Amplification, ConnectionId, TokenCheck, Tokens};

fn tokens() -> &'static Tokens {
    static T: OnceLock<Tokens> = OnceLock::new();
    T.get_or_init(|| Tokens::new([0x5a; 32]).unwrap())
}

struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((b, rest)) => {
                self.0 = rest;
                *b
            }
            None => 0,
        }
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.byte()).collect()
    }
    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.bytes(8).try_into().unwrap())
    }
    fn addr(&mut self) -> SocketAddr {
        let ip = if self.byte() & 1 == 0 {
            IpAddr::from(<[u8; 4]>::try_from(self.bytes(4)).unwrap())
        } else {
            IpAddr::from(<[u8; 16]>::try_from(self.bytes(16)).unwrap())
        };
        SocketAddr::new(ip, u16::from_be_bytes([self.byte(), self.byte()]))
    }
    fn cid(&mut self) -> ConnectionId {
        let n = usize::from(self.byte()) % 21;
        ConnectionId::new(&self.bytes(n)).unwrap()
    }
}

fuzz_target!(|data: &[u8]| {
    let t = tokens();
    let mut i = Input(data);
    let split = usize::from(i.byte());
    let (raw, rest) = data.split_at(split.min(data.len()));

    // Arbitrary bytes.
    let mut j = Input(rest);
    let from = j.addr();
    let now = Duration::from_secs(j.u64() >> 2);
    assert!(!t.check(raw, from, now).is_valid());

    // Issued tokens.
    let client = j.addr();
    let other = j.addr();
    let issued = Duration::from_secs(j.u64() >> 4);
    let later = issued + Duration::from_secs(u64::from(j.byte()) * 400);
    let (odcid, scid) = (j.cid(), j.cid());
    let retry = t.retry_token(client, &odcid, &scid, issued).unwrap();
    let in_time = later.as_secs() - issued.as_secs() <= 10;
    let got = t.check(&retry, client, later);
    if in_time {
        assert_eq!(
            got,
            TokenCheck::Retry {
                original_dcid: odcid,
                retry_scid: scid
            }
        );
    } else {
        assert_eq!(got, TokenCheck::InvalidRetry);
    }
    if other != client {
        assert_eq!(t.check(&retry, other, issued), TokenCheck::InvalidRetry);
    }
    let nt = t.new_token(client.ip(), issued).unwrap();
    let got = t.check(&nt, SocketAddr::new(client.ip(), other.port()), later);
    assert_eq!(got.is_valid(), later.as_secs() - issued.as_secs() <= 24 * 3600);
    if other.ip() != client.ip() {
        assert_eq!(t.check(&nt, other, issued), TokenCheck::Unusable);
    }

    // The amplification limit.
    let mut a = Amplification::new();
    let (mut received, mut sent) = (0u64, 0u64);
    for _ in 0..32 {
        let n = usize::from(j.byte()) * 9;
        if j.byte() & 1 == 0 {
            a.on_received(n);
            received += n as u64;
        } else {
            let allowed = a.allowance().min(n as u64) as usize;
            a.on_sent(allowed);
            sent += allowed as u64;
        }
        assert!(sent <= received * 3);
    }
});
