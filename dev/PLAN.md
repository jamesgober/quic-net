# quic-net - Project Plan

> The design, strategy, and decision record for `quic-net`. A living document: every design decision, idea, or open question about quic-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Status:** `0.2.0` in progress: the sans-IO wire layer that needs no TLS (started 2026-11-20, D-001). The largest crate in the network family.

---

## 1. Purpose

QUIC (RFC 9000) on net-io's UDP socket: encrypted, multiplexed streams with their own loss recovery and congestion control, and connections that survive a client changing networks. HTTP/3 (an `h3` engine, name open) builds on it.

## 2. Why it is its own crate

QUIC builds TLS 1.3 into the transport: the handshake runs inside QUIC packets, and packet protection uses keys from it. Together with loss recovery, congestion control, streams, and migration, it is a transport stack of its own, not a feature of net-io (net-io decision D-002).

## 3. Scope

- Packet formats, header protection, packet protection (keys from the TLS 1.3 handshake through tls-net; rustls has a QUIC interface).
- Connection IDs, version negotiation, retry and address validation.
- Streams and flow control.
- Loss detection and congestion control (RFC 9002), with pacing.
- Connection migration and path validation.
- Datagrams (RFC 9221) as a later option.

## 3a. Design of the wire layer (0.2)

The first milestone is everything on the wire that needs no keys. It is sans-IO, works on borrowed bytes, and has one dependency (crypt-io, for stateless reset tokens):

- **Variable-length integers** (RFC 9000 section 16). Values may use a longer encoding than they need, but frame types must not (section 12.4).
- **Packet headers** (section 17, RFC 8999). Long headers (Initial, 0-RTT, Handshake, Retry), short headers, and version negotiation are read before header protection is removed: a parsed header says where the protected packet number starts and where the packet ends.
  - A version other than 1 is reported with its connection IDs (up to 255 bytes, as the invariants allow), so a server can answer with version negotiation.
  - A datagram's coalesced packets are split by their Length fields, at most 8 of them. Packets whose destination ID differs from the first are dropped (section 12.2).
  - Packet numbers encode and decode as in appendix A.
- **Frames** (section 19). All 21 types of version 1 are decoded without copying and written back. DATAGRAM (RFC 9221) is not decoded until it is negotiated.
- **Transport parameters** (section 18). Every version 1 parameter is supported, with its range and the side allowed to send it. GREASE is ignored.
- **Connection IDs** (sections 5.1, 10.3, 19.15, 19.16). The peer's IDs are kept within our `active_connection_id_limit`, and `retire_prior_to` is applied. Our IDs are issued within the peer's limit, and retirements are checked.
  - Stateless reset tokens are derived from a static key with keyed BLAKE3, so a server that lost its state can still compute them (section 10.3.2), and are compared in constant time.

### Budgets

| What | Bound | Why |
|---|---|---|
| ACK ranges in one frame | 256 beyond the first | each is walked; a scattered ACK past this is refused as a protocol violation |
| packets in one datagram | 8 | a datagram of tiny packets costs one parse each |
| transport parameters | 128, GREASE included | version 1 defines 17 |
| protected packet length | at least 20 bytes from the packet number | header protection samples 16 bytes 4 past it (RFC 9001 section 5.4.2) |
| peer connection IDs | our `active_connection_id_limit`; retirements waiting at most twice that | per-peer state stays bounded (DIRECTIVES section 4) |
| offsets, counts | offset plus length at most 2^62 - 1; stream counts at most 2^60 | the limits of sections 4.6 and 19 |

### Costs

`benches/codec.rs`, Linux, Rust 1.99, release build, at a load average of about 10, so upper bounds:

| Path | Cost |
|---|---|
| parse a short header | 9 ns |
| read an ACK with 3 ranges and a 1,100-byte STREAM frame | 31 ns |
| write them back | 20 ns |
| decode transport parameters (7 set) | 39 ns |
| decode an 8-byte varint | 2 ns |

Each stateless reset check compares every token of the connection in constant time: 16 byte XORs per token.

## 4. Threats

| Threat | Defence |
|---|---|
| amplification (spoofed source addresses) | at most three times the received bytes before address validation; retry tokens |
| connection ID exhaustion, state floods | budgets per peer; bouncer strikes |
| spoofed migration | path validation before trusting a new address |
| handshake floods | stateless retry under load |
| malformed or oversized input | strict decoding, every length checked before it is read, the budgets of section 3a | none measurable (section 3a costs) |
| connection ID floods | the peer's IDs bounded by our limit, retirements bounded; NEW_CONNECTION_ID contradictions refused (`PROTOCOL_VIOLATION`) | a map of at most the limit's entries per connection |
| stateless reset forgery or probing | tokens are keyed BLAKE3 of the ID under a secret key; comparisons in constant time; datagrams under 21 bytes are never resets | one BLAKE3 per issued ID; 16 XORs per token checked |

## 5. Prerequisites

net-io UDP (with the no-amplification rule), tls-net, the reactor driver for many connections per thread.

### What net-io 0.8.1's UDP has, and what QUIC still needs from it

Checked against net-io 0.8.1 on 2026-11-20.

| Need | net-io 0.8.1 | Gap |
|---|---|---|
| batched receive and send | `recv_batch` and `send_batch`: one `recvmmsg` or `sendmmsg` per 64 datagrams on Linux, a loop of single calls on macOS and Windows | no batching on macOS or Windows; `recv_batch` reports no packet info |
| segmentation offload (GSO, `UDP_SEGMENT`; Windows USO) | none | send a train of equal-size datagrams in one call; the largest saving for bulk sends on Linux |
| receive coalescing (GRO, `UDP_GRO`; Windows URO) | none | receive coalesced datagrams with their segment size |
| ECN (RFC 9000 section 13.4) | none | set ECT(0) on sends (`IP_TOS`, `IPV6_TCLASS`) and read the ECN bits of each received datagram (`IP_RECVTOS`, `IPV6_RECVTCLASS`), on every platform; without it QUIC runs with ECN disabled, which is allowed but loses early congestion signals |
| no IP fragmentation (RFC 9000 section 14) | not set | the don't-fragment bit (`IP_MTU_DISCOVER` with `IP_PMTUDISC_PROBE` on Linux, `IP_DONTFRAG` on macOS, `IP_DONTFRAGMENT` on Windows), so path MTU probing works |
| the local address of each datagram, for multi-homed servers and migration | packet info on Unix only (`recv_from`); refused on Windows | Windows packet info (`WSARecvMsg` with `IP_PKTINFO`), packet info in batches, and sending from a chosen local address |
| socket buffer sizes | TCP only | `SO_RCVBUF` and `SO_SNDBUF` in `UdpOptions`; QUIC servers need several MiB to avoid drops in bursts |
| anti-amplification, three times the received bytes before validation (RFC 9000 section 8) | the guard limits sends to an unverified address to at most 3 times what it received, and `mark_verified` lifts it once the address is validated | the allowance is counted per IP, while QUIC counts per path (address and port), so a second port of the same IP shares the first port's allowance; received bytes age out after the window (10 s by default, up to 1 hour), so a slow handshake with backed-off retransmits can lose its allowance: QUIC should set the window to at least the handshake timeout |
| many connections per thread | one thread per UDP listener, which suits a single socket | to spread one port over several threads, `SO_REUSEPORT` with steering by connection ID (Linux), or a dispatch from one receiving thread |
| a client sending first | a destination never heard from gets nothing until `mark_verified` | none: a QUIC client marks the server verified before its first Initial |

None of these blocks a first QUIC client or a single-threaded server on Linux. ECN, the don't-fragment bit, and Windows packet info are needed before a release that claims full RFC 9000 behaviour; GSO and GRO are for throughput.

### What tls-net must expose for QUIC

Checked against tls-net 0.10 on 2026-11-20. It has no QUIC interface yet (its plan lists "QUIC handshake integration" as not scheduled). rustls has one (`rustls::quic`), and quic-net needs tls-net to wrap it:

| Need | RFC | From rustls |
|---|---|---|
| a QUIC client and server session: handshake bytes in and out per encryption level, with no TLS records (QUIC carries them in CRYPTO frames) | RFC 9001 section 4 | `quic::ClientConnection`, `quic::ServerConnection`: `read_hs`, `write_hs` |
| the keys of each level as they become available: packet protection (AEAD) and header protection, for Initial, Handshake, 0-RTT, and 1-RTT | RFC 9001 section 5 | `KeyChange` from `write_hs`, `quic::Keys`, `PacketKey`, `HeaderProtectionKey` |
| Initial keys from the client's first destination ID | RFC 9001 section 5.2 | `quic::Keys::initial` |
| key updates for 1-RTT | RFC 9001 section 6 | `next_1rtt_keys` |
| transport parameters sent and received in the TLS extension | RFC 9001 section 8.2 | the `params` argument of the session constructors, `quic_transport_parameters` |
| ALPN required (a handshake without it fails) | RFC 9001 section 8.1 | the config's ALPN list, `alpn_protocol` |
| TLS alerts surfaced as codes, so the connection closes with `CRYPTO_ERROR` (0x100 plus the alert) | RFC 9001 section 4.8 | `alert` |
| TLS 1.3 only, no middlebox compatibility mode, no `end_of_early_data` | RFC 9001 sections 4.2 and 8.3 | `quic::Version::V1` and the QUIC config |
| 0-RTT keys and the server's decision on early data (later) | RFC 9001 section 4.6 | `zero_rtt_keys`, `max_early_data_size` |
| the Retry integrity tag: AES-128-GCM under a fixed key | RFC 9001 section 5.8 | the provider's AEAD, or crypt-io |

tls-net is not changed from here. These go to its session as a request.

## 6. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | Own crate, scheduled later; started 2026-11-20 | a full transport stack; not needed while the front end handles HTTP/3. On 2026-11-20 the wire layer started, as the part that needs neither TLS nor sockets |
| D-002 | 2026-11-20 | The UDP prerequisites from net-io are listed in section 5 | checked against net-io 0.8.1: batching exists on Linux only; GSO, GRO, ECN, the don't-fragment bit, UDP buffer sizes and Windows packet info are missing; the amplification guard counts per IP rather than per path |
| D-003 | 2026-11-20 | 0.2.0 is the sans-IO wire layer (varints, headers, version negotiation, frames, transport parameters, connection IDs, reset tokens); the connection API and TLS come after | these need no keys and no sockets, carry most of the parsing risk, and can be fuzzed alone; the connection API depends on what tls-net exposes (section 5) |
| D-004 | 2026-11-20 | Frames decode as borrowed views; a STREAM frame is always written with its length; DATAGRAM is refused until negotiated | no copy on the hot path; a frame with its length can be followed by others; an unnegotiated frame type is a `FRAME_ENCODING_ERROR` (RFC 9221 section 3) |
| D-005 | 2026-11-20 | Budgets: 256 ACK ranges, 8 packets per datagram, 128 transport parameters, at least 20 bytes from the packet number | each bound sits far above what a real peer sends and caps the work a hostile one can cause (section 3a) |
| D-006 | 2026-11-20 | Stateless reset tokens are keyed BLAKE3 of the connection ID through crypt-io; compared in constant time | a token must be computable without connection state and unforgeable without the key (RFC 9000 section 10.3.2); crypt-io is the allowed crypto dependency |
| D-007 | 2026-11-20 | Headers are parsed before header protection is removed and report where the packet number starts; unprotecting is the next layer's | the protected bits cannot be read without keys; splitting the work keeps this layer free of crypto |
| D-008 | 2026-11-20 | The prerequisites from tls-net are listed in section 5; tls-net is not changed from this repository | its QUIC wrapper is its own work and decision |
