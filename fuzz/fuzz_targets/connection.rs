//! A client and a server connection handshaking through tls-net, with the
//! input deciding what happens to every datagram: delivered, dropped,
//! delivered twice, or with one byte changed. Oracle: no panic, no
//! datagram over 1,500 bytes, and a run with no changed bytes and at most
//! four drops ends with both sides established.
#![no_main]

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use quic_net::{Config, Connection, ConnectionId, Header, parse_packet};
use tls_net::{Alpn, KeySource, TlsClient, TlsServer, TrustAnchors};

fn tls() -> &'static (TlsClient, TlsServer) {
    static T: OnceLock<(TlsClient, TlsServer)> = OnceLock::new();
    T.get_or_init(|| {
        let h3 = Alpn::new(b"h3").unwrap();
        let server = TlsServer::builder()
            .certificate(
                include_bytes!("../../tests/data/site.pem"),
                KeySource::Pem(include_bytes!("../../tests/data/site.key")),
            )
            .unwrap()
            .alpn(&[h3.clone()])
            .build()
            .unwrap();
        let client = TlsClient::builder()
            .trust(TrustAnchors::from_pem(include_bytes!("../../tests/data/ca.pem")).unwrap())
            .alpn(&[h3])
            .build()
            .unwrap();
        (client, server)
    })
}

fn cid(b: u8) -> ConnectionId {
    ConnectionId::new(&[b; 8]).unwrap()
}

fuzz_target!(|data: &[u8]| {
    let (client_tls, server_tls) = tls();
    let mut input = data.iter().copied();
    let mut now = Instant::now();
    let mut client =
        Connection::client(client_tls, "localhost", Config::default(), cid(1), cid(2), now).unwrap();
    let mut buf = Vec::new();
    assert!(client.poll_transmit(now, &mut buf));
    let first = buf.clone();
    let Ok(p) = parse_packet(&first, 8) else {
        panic!("the first Initial does not parse");
    };
    let Header::Long { dcid, scid, .. } = p.header else {
        panic!("not a long header");
    };
    let mut server =
        Connection::server(server_tls, Config::default(), cid(3), dcid, scid, None, false, now).unwrap();
    let mut to_server = vec![first];
    let mut to_client: Vec<Vec<u8>> = Vec::new();
    let mut changed = false;
    let mut drops = 0usize;
    let deliver = |d: &mut Vec<u8>,
                   out: &mut Vec<Vec<u8>>,
                   input: &mut dyn Iterator<Item = u8>,
                   changed: &mut bool,
                   drops: &mut usize| {
        let Some(b) = input.next() else {
            out.push(d.clone());
            return;
        };
        match b % 8 {
            0 => *drops += 1,
            1 => {
                out.push(d.clone());
                out.push(d.clone());
            }
            2 => {
                let at = usize::from(input.next().unwrap_or(0)) * 7 % d.len().max(1);
                let x = input.next().unwrap_or(1) | 1;
                if let Some(byte) = d.get_mut(at) {
                    *byte ^= x;
                    *changed = true;
                }
                out.push(d.clone());
            }
            _ => out.push(d.clone()),
        }
    };
    for _ in 0..200 {
        let mut moved = false;
        for mut d in core::mem::take(&mut to_server) {
            server.handle_datagram(now, &mut d);
            moved = true;
        }
        for mut d in core::mem::take(&mut to_client) {
            client.handle_datagram(now, &mut d);
            moved = true;
        }
        while client.poll_transmit(now, &mut buf) {
            assert!(buf.len() <= 1500);
            deliver(&mut buf, &mut to_server, &mut input, &mut changed, &mut drops);
            moved = true;
        }
        while server.poll_transmit(now, &mut buf) {
            assert!(buf.len() <= 1500);
            deliver(&mut buf, &mut to_client, &mut input, &mut changed, &mut drops);
            moved = true;
        }
        while client.poll_event().is_some() {}
        while server.poll_event().is_some() {}
        if client.is_established() && server.is_established() && to_client.is_empty() && to_server.is_empty() {
            break;
        }
        if !moved {
            let next = [client.poll_timeout(), server.poll_timeout()].into_iter().flatten().min();
            match next {
                Some(t) => {
                    now = now.max(t);
                    client.handle_timeout(now);
                    server.handle_timeout(now);
                }
                None => break,
            }
            if now.duration_since(Instant::now()) > Duration::from_secs(25) {
                break;
            }
        }
    }
    if !changed && drops <= 4 {
        assert!(client.is_established() && server.is_established(), "clean run did not finish");
    }
});
