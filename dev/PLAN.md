# quic-net - Project Plan

> The design, strategy, and decision record for `quic-net`. A living document: every design decision, idea, or open question about quic-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Status:** `0.4.0`: the sans-IO wire layer (0.2), packet protection over key traits (0.3), and streams with flow control (0.4). Next: the connection API and the handshake on tls-net's QUIC interface. The largest crate in the network family.

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

## 3b. Design of packet protection (0.3)

RFC 9001 section 5, without a cipher of its own:

- **Two key traits.** `PacketKey` seals and opens a payload in place under the nonce made from the packet number, with the header as associated data; `HeaderKey` turns a 16-byte sample into the mask. A TLS session implements them. rustls's `quic::PacketKey` and `quic::HeaderProtectionKey` have the same shape, so tls-net's wrapper can implement them directly (section 5).
- **Framing here.** Where the sample is, which first-byte bits the mask covers (4 in a long header, 5 in a short one), the packet number's length and full value, the tag's place, and the reserved bits.
- **Opening in two steps.** Header protection comes off first and reveals the key phase; the caller picks the key and opens the payload. The reserved bits are checked only after the payload authenticates, as RFC 9000 section 17.2 requires, so a forged packet cannot provoke a connection error.
- **Initial keys here.** `InitialSecrets` runs HKDF-Extract and HKDF-Expand-Label over crypt-io's HMAC-SHA256, and `Secret::key_material` gives the key, IV, and header key bytes for any version 1 suite with a SHA-256 secret. Secrets and key material are zeroed on drop.
- **Limits.** `AeadUsage` counts packets sealed under the current key against the confidentiality limit, and packets failing authentication under any key against the integrity limit, which closes the connection with `AEAD_LIMIT_REACHED`.
- **Retry.** The integrity tag over the pseudo-packet, compared in constant time.

Measured with the test ciphers (RustCrypto AES-128-GCM, `benches/codec.rs`, Linux, Rust 1.99, release build, at a load average of 7, so upper bounds):

| Path | Cost |
|---|---|
| seal a 1,200-byte payload | 713 ns |
| open it (header protection, then the payload) | 740 ns |
| derive the Initial keys of both directions | 1.2 us, once per connection |

The cipher is nearly all of it; the framing is a few nanoseconds. A TLS provider's AEAD (ring or aws-lc through rustls) is the one that will run in practice.

## 3c. Design of streams and flow control (0.4)

Each part does one job and returns what the connection must do next (a frame to send, a credit to count, an error to close with); the connection that ties them together comes with the handshake (D-013).

- **Stream IDs and limits** (sections 2.1, 3.2, 4.6). `RemoteStreams` refuses a peer's stream past the limit we advertised (`STREAM_LIMIT_ERROR`), opens every lower stream of the type with it, and moves the limit by half a window as streams close. `LocalStreams` opens ours within the peer's limit and reports `STREAMS_BLOCKED` once per limit. `StreamId::can_send` and `can_receive` give the `STREAM_STATE_ERROR` checks.
- **Flow control** (section 4). `RecvCredit` refuses data past the limit we advertised and moves the limit a window past what the application consumed, once half a window was consumed, so updates are not sent per read. `SendCredit` ignores a lower limit and reports a blocked frame once per limit.
- **Receiving** (sections 2.2, 3.2, 4.5). Bytes are stored at their offset from the read position in a ring buffer, with a range set of what arrived: inserting costs the new bytes only, in any order, and no byte is copied twice before it is read (D-014). The first copy of a byte is kept. Every frame is checked against the final size and the stream's limit before any byte is stored; a reset drops unread data and counts it as consumed, so the connection's credit moves on; a reset after every byte arrived is ignored. `stop()` drops what is held and counts later data as consumed without storing it.
- **Sending** (sections 2.2, 3.1, 13.3). Written bytes stay buffered until acknowledged (at most the stream's buffer). `next_chunk` sends lost data first; only bytes never sent before take credit. Acknowledgements may arrive in any order, and a chunk reported lost after it was acknowledged is not sent again.
- **CRYPTO** (section 7.5). The same reassembly, without flow control but limited to 64 KiB past what TLS has read (D-016).

### Budgets

| What | Bound | Why |
|---|---|---|
| a stream's unread data held | its flow control window | the peer cannot send past the limit we advertised |
| all streams' data held | the connection's window | the growth of every stream's highest offset is counted against it |
| separate pieces of a stream's unread data | 1,024 (`MAX_FRAGMENTS`); more is `PROTOCOL_VIOLATION` | bounds the range set each insert walks (D-015) |
| CRYPTO data past what TLS read | 64 KiB per level (`MAX_CRYPTO_BUFFER`); more is `CRYPTO_BUFFER_EXCEEDED` | a server's certificate chain fits; RFC 9000 asks for at least 4,096 bytes (D-016) |
| a send stream's buffer | set by the caller | written data stays until acknowledged |

### Costs

`benches/codec.rs`, Linux, Rust 1.99, release build, at a load average of 17, so upper bounds:

| Path | Cost |
|---|---|
| send 1,200 bytes (write, chunk, frame, acknowledge) | 34 ns |
| receive 1,200 bytes in order and read them | 21 ns |
| receive two 1,200-byte chunks out of order and read them | 64 ns |

## 4. Threats

| Threat | Defence |
|---|---|
| amplification (spoofed source addresses) | at most three times the received bytes before address validation; retry tokens |
| connection ID exhaustion, state floods | budgets per peer; bouncer strikes |
| spoofed migration | path validation before trusting a new address |
| handshake floods | stateless retry under load |
| malformed or oversized input | strict decoding, every length checked before it is read, the budgets of section 3a | none measurable (section 3a costs) |
| connection ID floods | the peer's IDs bounded by our limit, retirements bounded; NEW_CONNECTION_ID contradictions refused (`PROTOCOL_VIOLATION`) | a map of at most the limit's entries per connection |
| forged or altered packets | every packet is authenticated (AEAD) before anything in it is used; the reserved bits and the frames are read only after | one AEAD open per packet, about 0.7 us per 1,200 bytes with the test ciphers |
| forgery by brute force against the AEAD | packets failing authentication counted across all keys; at the integrity limit the connection closes with `AEAD_LIMIT_REACHED` (RFC 9001 section 6.6) | one counter |
| key wear | packets sealed per key counted; at the confidentiality limit the keys must be updated | one counter |
| key material left in memory | secrets and key material zeroed on drop | a write of 32 to 76 bytes per drop |
| reading Initial packets | none possible: Initial keys come from the client's destination ID, which is on the wire, so they guard against tampering by anyone who does not see the packet, not against observers (RFC 9001 section 5.2) | none |
| memory exhaustion through stream data | a stream holds at most its window, the connection at most its window across streams; data past either limit closes the connection (`FLOW_CONTROL_ERROR`) | none beyond the bookkeeping: the window is memory the receiver offered |
| stream fragmentation (many small pieces with gaps) | at most 1,024 separate pieces per stream, then `PROTOCOL_VIOLATION`; data stored at its offset, so a hostile order never costs more copying than an in-order one | one range-set walk per frame, at most 1,024 entries |
| stream ID floods | the peer's streams past our limit are a `STREAM_LIMIT_ERROR`; the limit moves only as streams close | one counter per stream type |
| CRYPTO buffering (a handshake that never completes) | 64 KiB per level past what TLS has read, then `CRYPTO_BUFFER_EXCEEDED` | at most 64 KiB per level per connection |
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

Since 0.3, quic-net takes keys through two traits, `PacketKey` and `HeaderKey`, whose methods match rustls's `quic::PacketKey` (`encrypt_in_place`, `decrypt_in_place`, the AEAD limits) and `quic::HeaderProtectionKey` (the mask from a sample). tls-net can wrap rustls's keys in a type of its own and implement them, without depending on quic-net, if quic-net implements the traits for tls-net's types instead; which side holds the impls is decided with tls-net's QUIC interface.

Another way to the Initial keys, which need no handshake: crypt-io with AES-128-GCM under a caller's nonce, a single AES block, and the ChaCha20 keystream. crypt-io 1.6 has none of the three (its AEAD makes its own random nonce, and its AES-GCM is AES-256).

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
| D-009 | 2026-11-20 | Packet protection is a layer over two key traits, `PacketKey` and `HeaderKey`; the ciphers come from a TLS session; the Initial key schedule is here, over crypt-io's HMAC-SHA256 | crypt-io 1.6 has no AES-128-GCM under a caller's nonce, no raw AES block, and no ChaCha20 keystream, and tls-net has no QUIC interface yet; the framing (sample, mask bits, packet numbers, reserved bits, limits) is the transport's either way and can be finished and fuzzed now |
| D-010 | 2026-11-20 | Opening takes two steps (header protection, then the payload), and the reserved bits are checked only after the payload authenticates | the key phase revealed by the first step picks the key for the second (RFC 9001 section 6); RFC 9000 section 17.2 makes nonzero reserved bits an error only after both protections are removed, so a forged packet is dropped, never a connection error |
| D-011 | 2026-11-20 | RustCrypto `aes`, `aes-gcm`, `chacha20`, and `chacha20poly1305` are dev-dependencies (and fuzz-crate dependencies) for the RFC 9001 appendix A vectors | test-only, at the versions crypt-io already brings in, so no new crate enters the lock file; the library has no cipher of its own |
| D-012 | 2026-11-20 | The connection, stream, and configuration APIs move from 0.3 to 0.4, with the handshake | the connection API is shaped by how the handshake gets keys and CRYPTO data from tls-net, whose QUIC interface does not exist yet; locking it before then would be a guess. 0.3 ships what does not depend on it |
| D-013 | 2026-11-20 | 0.4 is streams and flow control; the connection API, keys from tls-net, the handshake, and address validation move to 0.5, recovery and migration to 0.6 | streams, flow control, and CRYPTO reassembly need no TLS and can be finished and fuzzed now; the connection that ties them together still waits on tls-net's QUIC interface (section 5) |
| D-014 | 2026-11-20 | Received stream data is stored at its offset in a ring buffer, with a range set of what arrived | inserting into a map of chunks and merging touching ones lets a peer send data in an order that copies earlier bytes again on every frame (quadratic work); at its offset, every byte is copied once on arrival and once when read. The ring holds up to the window even for one byte at its end, which flow control allows anyway |
| D-015 | 2026-11-20 | At most 1,024 separate pieces of unread data per stream; more is `PROTOCOL_VIOLATION` | each insert walks the range set; bounding it bounds the work per frame. RFC 9000 names no error for this; dropping the data would stall the stream, because the packet that carried it was already acknowledged |
| D-016 | 2026-11-20 | CRYPTO data may reach 64 KiB past what TLS has read | a server's certificate chain arrives in CRYPTO frames and may be tens of kilobytes; RFC 9000 section 7.5 asks for at least 4,096 bytes |
