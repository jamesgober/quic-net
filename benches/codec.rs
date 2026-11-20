//! Costs of the wire layer's hot paths, measured with the standard library's
//! clock: a short header, a 1-RTT payload of ACK and STREAM frames, writing
//! those frames, transport parameters, packet protection with the test
//! ciphers (`tests/support/ciphers.rs`), and stream data both ways.
//!
//! `cargo bench --bench codec`

#[path = "../tests/support/ciphers.rs"]
mod ciphers;

use std::hint::black_box;
use std::time::{Duration, Instant};

use quic_net::{
    Ack, ConnectionId, Frame, InitialSecrets, PacketKind, RecvStream, SendStream, Side, StreamId,
    TAG_LEN, TransportParameters, VarInt, frames, open_payload, parse_packet,
    remove_header_protection, seal_packet, write_short,
};

fn time<F: FnMut()>(label: &str, mut f: F) {
    for _ in 0..10_000 {
        f();
    }
    let n = 500_000u32;
    let best = (0..5)
        .map(|_| {
            let t = Instant::now();
            for _ in 0..n {
                f();
            }
            t.elapsed()
        })
        .min()
        .unwrap_or(Duration::ZERO);
    println!(
        "{label:<48} {:>8.1} ns",
        best.as_nanos() as f64 / f64::from(n)
    );
}

fn main() {
    let dcid = ConnectionId::new(&[7; 8]).unwrap();
    let mut packet = Vec::new();
    let at = write_short(&mut packet, &dcid, false, false, 1234, 2);
    packet.resize(at + 2 + 1200, 0);
    time("parse a short header (1,200-byte packet)", || {
        black_box(parse_packet(black_box(&packet), 8).unwrap());
    });

    let mut payload = Vec::new();
    Ack::write(&mut payload, &[900..=1000, 700..=880, 0..=650], 25, None);
    let data = vec![0xAB; 1100];
    Frame::Stream {
        stream_id: 4,
        offset: 1 << 20,
        data: &data,
        fin: false,
    }
    .encode(&mut payload);
    time("read an ACK (3 ranges) and a STREAM frame", || {
        for f in frames(black_box(&payload), PacketKind::OneRtt) {
            black_box(f.unwrap());
        }
    });
    let decoded: Vec<Frame<'_>> = frames(&payload, PacketKind::OneRtt)
        .map(|f| f.unwrap())
        .collect();
    let mut out = Vec::with_capacity(2048);
    time("write them back", || {
        out.clear();
        for f in &decoded {
            f.encode(&mut out);
        }
        black_box(&out);
    });

    let params = TransportParameters {
        original_destination_connection_id: Some(dcid),
        initial_source_connection_id: Some(dcid),
        initial_max_data: 10 << 20,
        initial_max_stream_data_bidi_local: 1 << 20,
        initial_max_stream_data_bidi_remote: 1 << 20,
        initial_max_streams_bidi: 100,
        max_idle_timeout: Duration::from_secs(30),
        ..TransportParameters::default()
    };
    let mut wire = Vec::new();
    params.encode(&mut wire);
    time("decode transport parameters (7 set)", || {
        black_box(TransportParameters::decode(black_box(&wire), Side::Server).unwrap());
    });
    let secrets = InitialSecrets::new(&dcid).unwrap();
    let m = secrets.client.key_material(16).unwrap();
    let (key, hp) = (ciphers::Key::aes(&m), ciphers::Hp::aes(&m));
    let mut plain = Vec::new();
    let at = write_short(&mut plain, &dcid, false, false, 1234, 2);
    plain.resize(at + 2 + 1200 + TAG_LEN, 0x11);
    let mut buf = plain.clone();
    time("seal a 1,200-byte payload (AES-128-GCM)", || {
        buf.copy_from_slice(&plain);
        seal_packet(&mut buf, at, 1234, &key, &hp).unwrap();
    });
    let sealed = buf.clone();
    time("open it", || {
        buf.copy_from_slice(&sealed);
        let u = remove_header_protection(&mut buf, at, Some(1233), &hp).unwrap();
        black_box(open_payload(&mut buf, &u, &key).unwrap());
    });
    let mut copy_only = plain.clone();
    time("  of which copying the packet", || {
        copy_only.copy_from_slice(black_box(&sealed));
        black_box(&copy_only);
    });
    time("derive Initial keys for both directions", || {
        let s = InitialSecrets::new(black_box(&dcid)).unwrap();
        black_box(s.client.key_material(16).unwrap());
        black_box(s.server.key_material(16).unwrap());
    });

    // Stream data: 1,200-byte frames, written, sent, and acknowledged on
    // one side; received in order and read on the other.
    let id = StreamId::new(Side::Client, true, 0).unwrap();
    let block = vec![0x42u8; 1200];
    let mut send = SendStream::new(u64::MAX >> 2, 1 << 20);
    let mut frame = Vec::with_capacity(1300);
    time("send a 1,200-byte chunk (write, frame, ack)", || {
        send.write(&block);
        let c = send.next_chunk(1200, u64::MAX).unwrap();
        frame.clear();
        send.write_frame(id, &c, &mut frame);
        send.on_acked(&c);
        black_box(&frame);
    });
    let mut recv = RecvStream::new(u64::MAX >> 2);
    let mut at = 0u64;
    let mut out = vec![0u8; 1200];
    time("receive a 1,200-byte chunk in order and read it", || {
        recv.on_stream(at, &block, false).unwrap();
        at += 1200;
        black_box(recv.read(&mut out));
        black_box(recv.take_consumed());
    });
    let mut recv = RecvStream::new(u64::MAX >> 2);
    let mut base = 0u64;
    time("receive two chunks out of order, then read", || {
        recv.on_stream(base + 1200, &block, false).unwrap();
        recv.on_stream(base, &block, false).unwrap();
        base += 2400;
        black_box(recv.read(&mut out));
        black_box(recv.read(&mut out));
    });

    let bytes = [0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c];
    time("decode an 8-byte varint", || {
        black_box(VarInt::decode(black_box(&bytes)).unwrap());
    });
}
