//! A client and a server connection handshaking through tls-net and
//! carrying streams, over an in-memory channel that can lose datagrams.
//! The certificates in `tests/data` are tls-net's test PKI (valid to 2099).

#![cfg(feature = "tls")]

use std::time::{Duration, Instant};

use quic_net::{
    Close, Config, Connection, ConnectionId, Event, Header, Side, TlsRetry, TokenCheck, Tokens,
    parse_packet, retry_tag, write_retry,
};
use tls_net::{Alpn, KeySource, TlsClient, TlsServer, TrustAnchors};

fn data(f: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{f}", env!("CARGO_MANIFEST_DIR"))).expect("test data")
}

fn tls() -> (TlsClient, TlsServer) {
    let h3 = Alpn::new(b"h3").unwrap();
    let server = TlsServer::builder()
        .certificate(&data("site.pem"), KeySource::Pem(&data("site.key")))
        .unwrap()
        .alpn(std::slice::from_ref(&h3))
        .build()
        .unwrap();
    let client = TlsClient::builder()
        .trust(TrustAnchors::from_pem(&data("ca.pem")).unwrap())
        .alpn(&[h3])
        .build()
        .unwrap();
    (client, server)
}

fn cid(b: u8) -> ConnectionId {
    ConnectionId::new(&[b; 8]).unwrap()
}

/// A client, and a server made from the client's first Initial.
struct Pair {
    client: Connection,
    server: Connection,
    now: Instant,
    to_server: Vec<Vec<u8>>,
    to_client: Vec<Vec<u8>>,
    sent: usize,
}

fn first_initial(client: &mut Connection, now: Instant) -> Vec<u8> {
    let mut d = Vec::new();
    assert!(client.poll_transmit(now, &mut d));
    assert!(d.len() >= 1200, "{}", d.len());
    d
}

fn server_for(server_tls: &TlsServer, d: &[u8], now: Instant) -> Connection {
    let p = parse_packet(d, 8).unwrap();
    let Header::Long { dcid, scid, .. } = p.header else {
        panic!("{:?}", p.header);
    };
    Connection::server(
        server_tls,
        Config::default(),
        cid(0x5e),
        dcid,
        scid,
        None,
        false,
        now,
    )
    .unwrap()
}

impl Pair {
    fn new() -> Pair {
        let (client_tls, server_tls) = tls();
        Pair::with(&client_tls, &server_tls)
    }

    fn with(client_tls: &TlsClient, server_tls: &TlsServer) -> Pair {
        let now = Instant::now();
        let mut client = Connection::client(
            client_tls,
            "localhost",
            Config::default(),
            cid(0xc1),
            cid(0xd1),
            now,
        )
        .unwrap();
        let first = first_initial(&mut client, now);
        let server = server_for(server_tls, &first, now);
        Pair {
            client,
            server,
            now,
            to_server: vec![first],
            to_client: Vec::new(),
            sent: 0,
        }
    }

    /// Moves datagrams both ways until neither side has anything to send,
    /// then runs timers; `keep` decides each datagram's fate.
    fn run(&mut self, rounds: usize, keep: &mut dyn FnMut(usize) -> bool) {
        for _ in 0..rounds {
            let mut moved = false;
            for d in core::mem::take(&mut self.to_server) {
                let mut d = d;
                self.server.handle_datagram(self.now, &mut d);
                moved = true;
            }
            for d in core::mem::take(&mut self.to_client) {
                let mut d = d;
                self.client.handle_datagram(self.now, &mut d);
                moved = true;
            }
            let mut buf = Vec::new();
            while self.client.poll_transmit(self.now, &mut buf) {
                self.sent += 1;
                if keep(self.sent) {
                    self.to_server.push(buf.clone());
                }
                moved = true;
            }
            while self.server.poll_transmit(self.now, &mut buf) {
                self.sent += 1;
                if keep(self.sent) {
                    self.to_client.push(buf.clone());
                }
                moved = true;
            }
            if !moved {
                // Quiet: jump to the next timer.
                let next = [self.client.poll_timeout(), self.server.poll_timeout()]
                    .into_iter()
                    .flatten()
                    .min();
                match next {
                    // Only the idle timer is left: the exchange is over.
                    Some(t) if t > self.now + Duration::from_secs(20) => return,
                    Some(t) => {
                        self.now = self.now.max(t);
                        self.client.handle_timeout(self.now);
                        self.server.handle_timeout(self.now);
                    }
                    None => return,
                }
            }
            if self.client.is_closed() && self.server.is_closed() {
                return;
            }
        }
    }

    fn events(c: &mut Connection) -> Vec<Event> {
        core::iter::from_fn(|| c.poll_event()).collect()
    }
}

#[test]
fn test_handshake() {
    let mut p = Pair::new();
    p.run(50, &mut |_| true);
    assert!(p.client.is_established(), "client {:?}", p.client);
    assert!(p.server.is_established(), "server {:?}", p.server);
    assert_eq!(p.client.alpn(), Some(&b"h3"[..]));
    assert!(Pair::events(&mut p.client).contains(&Event::Connected));
    assert!(Pair::events(&mut p.server).contains(&Event::Connected));
    let params = p.client.peer_params().unwrap();
    assert_eq!(params.original_destination_connection_id, Some(cid(0xd1)));
    assert_eq!(params.initial_source_connection_id, Some(cid(0x5e)));
    assert_eq!(p.client.side(), Side::Client);
}

#[test]
fn test_a_resumed_session() {
    // The second connection on the same client resumes the first's TLS
    // session. rustls then offers the previous session's transport
    // parameters before the handshake; the connection must wait for the
    // new ones.
    let (client_tls, server_tls) = tls();
    for _ in 0..3 {
        let mut p = Pair::with(&client_tls, &server_tls);
        p.run(50, &mut |_| true);
        assert!(p.client.is_established(), "{:?}", p.client.close_reason());
        assert!(p.server.is_established(), "{:?}", p.server.close_reason());
    }
}

fn echo(p: &mut Pair, len: usize, keep: &mut dyn FnMut(usize) -> bool) {
    let payload: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
    p.run(200, keep);
    assert!(p.client.is_established() && p.server.is_established());
    let id = p.client.open_stream(true).unwrap();
    let mut written = 0;
    let mut got_server = Vec::new();
    let mut got_client = Vec::new();
    let mut server_id = None;
    let mut buf = vec![0u8; 4096];
    for _ in 0..20_000 {
        if written < payload.len() {
            written += p.client.stream_write(id, &payload[written..]).unwrap();
            if written == payload.len() {
                p.client.stream_finish(id).unwrap();
            }
        }
        p.run(1, keep);
        for e in Pair::events(&mut p.server) {
            if let Event::StreamOpened(sid) = e {
                server_id = Some(sid);
            }
        }
        if let Some(sid) = server_id {
            loop {
                let n = p.server.stream_read(sid, &mut buf).unwrap();
                if n == 0 {
                    break;
                }
                got_server.extend_from_slice(&buf[..n]);
                // Echo it back on the same stream.
                let mut at = 0;
                while at < n {
                    let w = p.server.stream_write(sid, &buf[at..n]).unwrap();
                    assert!(w > 0, "the server's buffer is full");
                    at += w;
                }
            }
            if p.server.stream_is_finished(sid) && got_server.len() == payload.len() {
                p.server.stream_finish(sid).unwrap();
            }
        }
        loop {
            let n = p.client.stream_read(id, &mut buf).unwrap();
            if n == 0 {
                break;
            }
            got_client.extend_from_slice(&buf[..n]);
        }
        if p.client.stream_is_finished(id) {
            break;
        }
    }
    assert_eq!(got_server.len(), payload.len());
    assert!(got_server == payload, "the server read different bytes");
    assert!(
        got_client == payload,
        "the echo differs ({} bytes)",
        got_client.len()
    );
}

#[test]
fn test_stream_echo() {
    let mut p = Pair::new();
    echo(&mut p, 100_000, &mut |_| true);
}

#[test]
fn test_a_lossy_channel() {
    for every in [3, 5, 7] {
        let mut p = Pair::new();
        echo(&mut p, 30_000, &mut |n| n % every != 0);
    }
}

#[test]
fn test_close() {
    let mut p = Pair::new();
    p.run(50, &mut |_| true);
    let _ = Pair::events(&mut p.server);
    p.client.close(p.now, 42, b"done");
    p.run(50, &mut |_| true);
    let closed = Pair::events(&mut p.server)
        .into_iter()
        .find_map(|e| match e {
            Event::Closed(c) => Some(c),
            _ => None,
        });
    assert_eq!(
        closed,
        Some(Close {
            code: 42,
            application: true,
            reason: b"done".to_vec(),
            remote: true
        })
    );
    p.run(50, &mut |_| true);
    assert!(p.client.is_closed() && p.server.is_closed());
}

#[test]
fn test_retry() {
    let (client_tls, server_tls) = tls();
    let tokens = Tokens::new([3; 32]).unwrap();
    let addr = "192.0.2.1:4433".parse().unwrap();
    let unix = Duration::from_secs(1_800_000_000);
    let now = Instant::now();
    let mut client = Connection::client(
        &client_tls,
        "localhost",
        Config::default(),
        cid(0xc1),
        cid(0xd1),
        now,
    )
    .unwrap();
    let first = first_initial(&mut client, now);
    // The server answers the first Initial with a Retry.
    let p = parse_packet(&first, 8).unwrap();
    let Header::Long {
        dcid, scid, token, ..
    } = p.header
    else {
        panic!();
    };
    assert!(token.is_empty());
    let retry_scid = cid(0x77);
    let token = tokens.retry_token(addr, &dcid, &retry_scid, unix).unwrap();
    let mut retry = Vec::new();
    write_retry(&mut retry, &scid, &retry_scid, &token, &[0; 16], 0);
    retry.truncate(retry.len() - 16);
    let tag = retry_tag(&dcid, &retry, &TlsRetry).unwrap();
    retry.extend_from_slice(&tag);
    client.handle_datagram(now, &mut retry);
    // The client comes back with the token, to the new ID.
    let second = first_initial(&mut client, now);
    let p = parse_packet(&second, 8).unwrap();
    let Header::Long {
        dcid, scid, token, ..
    } = p.header
    else {
        panic!();
    };
    assert_eq!(dcid, retry_scid);
    let TokenCheck::Retry {
        original_dcid,
        retry_scid,
    } = tokens.check(token, addr, unix)
    else {
        panic!("the token does not check out");
    };
    let server = Connection::server(
        &server_tls,
        Config::default(),
        cid(0x5e),
        dcid,
        scid,
        Some((original_dcid, retry_scid)),
        true,
        now,
    )
    .unwrap();
    let mut p = Pair {
        client,
        server,
        now,
        to_server: vec![second],
        to_client: Vec::new(),
        sent: 0,
    };
    p.run(50, &mut |_| true);
    assert!(p.client.is_established() && p.server.is_established());
    let params = p.client.peer_params().unwrap();
    assert_eq!(params.retry_source_connection_id, Some(cid(0x77)));
    assert_eq!(params.original_destination_connection_id, Some(cid(0xd1)));
}

#[test]
fn test_the_server_keeps_to_the_amplification_limit() {
    let (client_tls, server_tls) = tls();
    let now = Instant::now();
    let mut client = Connection::client(
        &client_tls,
        "localhost",
        Config::default(),
        cid(0xc1),
        cid(0xd1),
        now,
    )
    .unwrap();
    let mut first = first_initial(&mut client, now);
    let received = first.len();
    let mut server = server_for(&server_tls, &first, now);
    server.handle_datagram(now, &mut first);
    let mut sent = 0;
    let mut buf = Vec::new();
    while server.poll_transmit(now, &mut buf) {
        sent += buf.len();
    }
    assert!(sent > 0);
    assert!(sent <= 3 * received, "{sent} sent for {received} received");
}
