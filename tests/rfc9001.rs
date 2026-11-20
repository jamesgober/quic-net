//! RFC 9001 appendix A: the Initial key schedule, a client and a server
//! Initial packet, a Retry, and a ChaCha20-Poly1305 short header packet,
//! each protected and opened again. The vectors are the RFC's, byte for
//! byte; the ciphers are in `support/ciphers.rs`.

#[path = "support/ciphers.rs"]
mod ciphers;

use ciphers::{Hp, Key, Retry};
use quic_net::{
    ConnectionId, Header, InitialSecrets, LongHeader, LongType, ProtectError, Secret, Side,
    TAG_LEN, open_payload, parse_packet, remove_header_protection, retry_tag, seal_packet,
    verify_retry, write_retry, write_short,
};

fn h(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "{s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn hs(parts: &[&str]) -> Vec<u8> {
    h(&parts.concat())
}

fn dcid() -> ConnectionId {
    ConnectionId::new(&h("8394c8f03e515708")).expect("cid")
}

fn server_scid() -> ConnectionId {
    ConnectionId::new(&h("f067a5502a4262b5")).expect("cid")
}

#[test]
fn test_a1_initial_keys() {
    let s = InitialSecrets::new(&dcid()).expect("secrets");
    assert_eq!(
        s.client.as_bytes()[..],
        h("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
    );
    assert_eq!(
        s.server.as_bytes()[..],
        h("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
    );
    let c = s.client.key_material(16).expect("keys");
    assert_eq!(c.key(), h("1f369613dd76d5467730efcbe3b1a22d"));
    assert_eq!(c.iv()[..], h("fa044b2f42a3fd3b46fb255c"));
    assert_eq!(c.hp(), h("9f50449e04a0e810283a1e9933adedd2"));
    let v = s.server.key_material(16).expect("keys");
    assert_eq!(v.key(), h("cf3a5331653c364c88f0f379b6067e37"));
    assert_eq!(v.iv()[..], h("0ac1493ca1905853b0bba03e"));
    assert_eq!(v.hp(), h("c206b8d9b9f0f37644430b490eeaa314"));
    assert_eq!(
        s.local(Side::Client).as_bytes(),
        s.remote(Side::Server).as_bytes()
    );
}

/// Seals `plain` (header, payload, room for the tag) as `side` would,
/// checks it against `want`, then opens it as the peer would.
fn seal_and_open(side: Side, plain: Vec<u8>, pn: u64, want: &[u8], short_dcid_len: usize) {
    let s = InitialSecrets::new(&dcid()).expect("secrets");
    let local = s.local(side).key_material(16).expect("keys");
    let mut packet = plain.clone();
    let pn_offset = parse_packet(&packet, 0).expect("parses").pn_offset;
    seal_packet(
        &mut packet,
        pn_offset,
        pn,
        &Key::aes(&local),
        &Hp::aes(&local),
    )
    .expect("seal");
    assert_eq!(packet, want);

    // The peer: the header parses before protection is removed.
    let peer = match side {
        Side::Client => Side::Server,
        Side::Server => Side::Client,
    };
    let remote = s.remote(peer).key_material(16).expect("keys");
    let pn_offset = {
        let p = parse_packet(&packet, short_dcid_len).expect("parses");
        assert!(matches!(
            p.header,
            Header::Long {
                ty: LongType::Initial,
                ..
            }
        ));
        assert_eq!(p.bytes.len(), packet.len());
        p.pn_offset
    };
    let u =
        remove_header_protection(&mut packet, pn_offset, None, &Hp::aes(&remote)).expect("header");
    assert_eq!(u.pn, pn);
    let range = open_payload(&mut packet, &u, &Key::aes(&remote)).expect("open");
    assert_eq!(packet[range.clone()], plain[range.clone()]);
    assert_eq!(packet[..range.start], plain[..range.start]);
}

#[test]
fn test_a2_client_initial() {
    let mut plain = Vec::new();
    let header = LongHeader {
        ty: LongType::Initial,
        dcid: dcid(),
        scid: ConnectionId::EMPTY,
        token: &[],
    };
    header.encode(&mut plain, 2, 4, 1162 + TAG_LEN);
    assert_eq!(plain, h("c300000001088394c8f03e5157080000449e00000002"));
    plain.extend_from_slice(&hs(CLIENT_CRYPTO));
    plain.resize(plain.len() + (1162 - 245), 0);
    plain.extend_from_slice(&[0; TAG_LEN]);
    seal_and_open(Side::Client, plain, 2, &hs(CLIENT_PACKET), 8);
}

#[test]
fn test_a3_server_initial() {
    let mut plain = Vec::new();
    let header = LongHeader {
        ty: LongType::Initial,
        dcid: ConnectionId::EMPTY,
        scid: server_scid(),
        token: &[],
    };
    header.encode(&mut plain, 1, 2, 99 + TAG_LEN);
    assert_eq!(plain, h("c1000000010008f067a5502a4262b50040750001"));
    plain.extend_from_slice(&hs(SERVER_PAYLOAD));
    plain.extend_from_slice(&[0; TAG_LEN]);
    seal_and_open(Side::Server, plain, 1, &hs(SERVER_PACKET), 0);
}

#[test]
fn test_a4_retry() {
    let want = hs(RETRY_PACKET);
    let retry = Retry::new();
    let mut body = Vec::new();
    // The tag is computed over the packet without it, then appended.
    write_retry(
        &mut body,
        &ConnectionId::EMPTY,
        &server_scid(),
        b"token",
        &[0; 16],
        0x0f,
    );
    body.truncate(body.len() - 16);
    let tag = retry_tag(&dcid(), &body, &retry).expect("tag");
    let mut packet = Vec::new();
    write_retry(
        &mut packet,
        &ConnectionId::EMPTY,
        &server_scid(),
        b"token",
        &tag,
        0x0f,
    );
    assert_eq!(packet, want);
    let p = parse_packet(&packet, 0).expect("parses");
    assert!(matches!(p.header, Header::Retry { integrity_tag, .. } if integrity_tag == tag));

    assert!(verify_retry(&dcid(), &packet, &retry));
    let other = ConnectionId::new(&h("8394c8f03e515709")).expect("cid");
    assert!(!verify_retry(&other, &packet, &retry));
    for i in 0..packet.len() {
        let mut bad = packet.clone();
        bad[i] ^= 0x10;
        assert!(!verify_retry(&dcid(), &bad, &retry), "byte {i}");
    }
    assert!(!verify_retry(&dcid(), &packet[..15], &retry));
}

#[test]
fn test_a5_chacha20_short_header() {
    let secret = Secret::new(
        h("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
            .try_into()
            .expect("32 bytes"),
    );
    let m = secret.key_material(32).expect("keys");
    assert_eq!(
        m.key(),
        h("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
    );
    assert_eq!(m.iv()[..], h("e0459b3474bdd0e44a41c144"));
    assert_eq!(
        m.hp(),
        h("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
    );
    assert_eq!(
        secret.next().expect("ku").as_bytes()[..],
        h("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
    );

    let pn = 654_360_564;
    let mut packet = Vec::new();
    let pn_offset = write_short(&mut packet, &ConnectionId::EMPTY, false, false, pn, 3);
    assert_eq!(packet, h("4200bff4"));
    packet.push(0x01);
    packet.extend_from_slice(&[0; TAG_LEN]);
    let (key, hp) = (Key::chacha(&m), Hp::chacha(&m));
    seal_packet(&mut packet, pn_offset, pn, &key, &hp).expect("seal");
    assert_eq!(packet, h("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));

    let pn_offset = parse_packet(&packet, 0).expect("parses").pn_offset;
    let u = remove_header_protection(&mut packet, pn_offset, Some(pn - 1), &hp).expect("header");
    assert_eq!((u.pn, u.pn_len, u.key_phase), (pn, 3, false));
    let range = open_payload(&mut packet, &u, &key).expect("open");
    assert_eq!(packet[range], [0x01]);
}

#[test]
fn test_the_wrong_keys_never_open_a_packet() {
    let s = InitialSecrets::new(&dcid()).expect("secrets");
    let client = s.client.key_material(16).expect("keys");
    let server = s.server.key_material(16).expect("keys");
    let mut packet = hs(CLIENT_PACKET);
    // The client's own key opens it; the server's sealing key does not.
    let mut copy = packet.clone();
    let u = remove_header_protection(&mut copy, 18, None, &Hp::aes(&client)).expect("header");
    assert!(open_payload(&mut copy, &u, &Key::aes(&client)).is_ok());
    let u = remove_header_protection(&mut packet, 18, None, &Hp::aes(&server)).expect("header");
    assert_eq!(
        open_payload(&mut packet, &u, &Key::aes(&server)),
        Err(ProtectError::Authentication)
    );
}

const CLIENT_CRYPTO: &[&str] = &[
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69",
    "484c00000413011302010000c000000010000e00000b6578616d706c652e636f6dff01000100000a",
    "00080006001d0017001800100007000504616c706e000500050100000000003300260024001d0020",
    "9370b2c9caa47fbabaf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400",
    "0d0010000e0403050306030203080408050806002d00020101001c00024001003900320408ffffff",
    "ffffffffff05048000ffff07048000ffff0801100104800075300901100f088394c8f03e51570806",
    "048000ffff",
];
const CLIENT_PACKET: &[&str] = &[
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11d242b123dc9bd8ba",
    "b936b47d92ec356c0bab7df5976d27cd449f63300099f3991c260ec4c60d17b31f8429157bb35a12",
    "82a643a8d2262cad67500cadb8e7378c8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6",
    "005f80fcb7df621230c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c2084dce25ff9b06cde5",
    "35d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec4e15daf8500a6ef69ec4e3feb6b1d98e",
    "610ac8b7ec3faf6ad760b7bad1db4ba3485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e3",
    "0c5c4287e53805db059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f89937f5a67258bf63",
    "ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556be52afe3f565636ad1b17d508b73d874",
    "3eeb524be22b3dcbc2c7468d54119c7468449a13d8e3b95811a198f3491de3e7fe942b330407abf8",
    "2a4ed7c1b311663ac69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632291d6a418211cc29",
    "62e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe5896425c5bac4aee82e57a85aaf4e2513e4f0",
    "5796b07ba2ee47d80506f8d2c25e50fd14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c",
    "1f28ff18f58891ffef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009ddc324044e847a4f4a",
    "0ab34f719595de37252d6235365e9b84392b061085349d73203a4a13e96f5432ec0fd4a1ee65accd",
    "d5e3904df54c1da510b0ff20dcc0c77fcb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de3",
    "54270123cb11450efc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e72404790a2181014f3b94a",
    "4e97d117b438130368cc39dbb2d198065ae3986547926cd2162f40a29f0c3c8745c0f50fba3852e5",
    "66d44575c29d39a03f0cda721984b6f440591f355e12d439ff150aab7613499dbd49adabc8676eef",
    "023b15b65bfc5ca06948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0be79e2fb8f5d5fbb",
    "e2e30ecadd220723c8c0aea8078cdfcb3868263ff8f0940054da48781893a7e49ad5aff4af300cd8",
    "04a6b6279ab3ff3afb64491c85194aab760d58a606654f9f4400e8b38591356fbf6425aca26dc852",
    "44259ff2b19c41b9f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd46840647e78bfe706ca4cf5",
    "e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241e221af44860018ab0856972e194cd934",
];
const SERVER_PAYLOAD: &[&str] = &[
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566d",
    "c5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d10",
    "81287c834d5311bcf32bb9da1a002b00020304",
];
const SERVER_PACKET: &[&str] = &[
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a5816b6394100f37a",
    "1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3dbcba3f6ea46c5b7684df3548e7ddeb9",
    "c3bf9c73cc3f3bded74b562bfb19fb84022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d",
    "20398c276456cbc42158407dd074ee",
];
const RETRY_PACKET: &[&str] =
    &["ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"];
