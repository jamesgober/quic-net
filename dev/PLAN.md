# quic-net - Project Plan

> The design, strategy, and decision record for `quic-net`. A living document: every design decision, idea, or open question about quic-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Status:** `0.7.0`: a working connection with congestion control and migration (0.5 to 0.7) over everything below. `0.4.0`: the sans-IO wire layer (0.2), packet protection over key traits (0.3), and streams with flow control (0.4). Next: the connection API and the handshake on tls-net's QUIC interface. The largest crate in the network family.

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

## 3d. Design of address validation (0.5)

RFC 9000 section 8, without a connection yet:

- **Tokens** are sealed with XChaCha20-Poly1305 through crypt-io, under a server key, with a two-byte clear header: the kind (Retry or `NEW_TOKEN`) and the key's ID. The contents are hidden as well as authenticated: a `NEW_TOKEN` token travels in clear in a later connection's Initial, and an observer must not be able to link the two connections through it (section 8.1.3). The 192-bit random nonce never repeats under one key, however many tokens a busy server issues (D-018).
- **A Retry token** holds the issue time, the client's address and port, the original destination ID, and the Retry's source ID, so the server recovers what its transport parameters must carry without keeping state. Valid for 10 seconds by default. An invalid one that claims to be a Retry token is `INVALID_TOKEN` (section 8.1.2).
- **A `NEW_TOKEN` token** holds the issue time and the client's IP address, not its port, which changes with every connection. Valid for 24 hours by default. An invalid one is treated as no token (section 8.1.3).
- **Key rotation** keeps one previous key, so tokens issued just before a rotation still validate (D-019).
- **The amplification limit** is counted per path, as RFC 9000 asks (net-io's guard counts per IP; section 5). Every datagram attributed to the connection counts, including ones whose packets were all dropped (D-020).

Replay: a `NEW_TOKEN` token can be replayed from the same IP address within its lifetime. That only proves an address the replayer already sends from, and a server wanting more can keep a filter of tokens seen; the crate does not, to stay stateless.

`benches/codec.rs`, Linux, at a load average of 2:

| Path | Cost |
|---|---|
| issue a Retry token | 1.2 us |
| check one | 1.1 us |
| refuse an altered one | 0.9 us |

Next to the Initial packet it arrives in (an AEAD open, then TLS), a token check is small.

## 3e. Design of the connection (0.5)

`Connection` is sans-IO: datagrams in, datagrams out, a timer, events. It owns no socket and reads no clock; the caller passes `now`.

- **The handshake** runs through tls-net 0.11 (`TlsClient::connect_quic`, `TlsServer::accept_quic`). CRYPTO data is reassembled per level (`CryptoRecv`) and fed to `read_handshake`; what `write_handshake` produces goes into a per-level send buffer (`SendStream`, so it is retransmitted like stream data), and each `KeyChange` installs the next level's keys.
- **Packet number spaces**: Initial, Handshake, and 1-RTT, each with its keys, its packet numbers, the ranges received (the last 32 kept for ACKs), and the packets sent and not yet acknowledged.
- **Datagrams** coalesce one packet per level, in order. A client pads every datagram with an Initial to 1,200 bytes, a server those with an ack-eliciting Initial; ACK-only server Initials are not padded, so they spend none of the amplification allowance.
- **Loss detection** follows RFC 9002 sections 5 and 6: RTT from ACKs (ack delay only in 1-RTT), packet threshold 3, time threshold 9/8 RTT, and the probe timeout with backoff. A client does not reset its backoff on Initial ACKs, and probes without packets in flight only until one of its Handshake packets is acknowledged (D-024).
- **Keys** are discarded as RFC 9001 section 4.9 says: the client's Initial keys when it first sends a Handshake packet, the server's when it first opens one; Handshake keys when the handshake is confirmed (`HANDSHAKE_DONE`, or completion on the server).
- **Transport parameters** are checked against the connection IDs seen (section 7.3). A client takes the server's only once its handshake is complete (D-025).
- **Streams** use 0.4's parts; a peer's stream is forgotten once both its parts are done, which raises `MAX_STREAMS`. A forgotten stream reads as finished.
- **Closing**: `CONNECTION_CLOSE` in each level with keys (an application close before 1-RTT as a transport `APPLICATION_ERROR`), then 3 PTOs of closing; a peer's close drains. The idle timeout is the smaller of the two advertised, at least 3 PTOs.

Not in 0.5 (roadmap 0.6): congestion control and pacing, migration and path validation, more connection IDs, initiating key updates, 0-RTT. Until congestion control lands, a sender is limited only by flow control: fine on a local network or behind a rate limit, not on a shared path.

## 3f. Design of congestion control (0.6)

NewReno (RFC 9002 section 7 and appendix B), in `cc.rs`, apart from the connection so it can be tested alone:

- **Bytes in flight**: every packet that is ack-eliciting or padded, in any packet number space, from when it is sent until it is acknowledged, declared lost, or its keys are discarded. Packets a probe timeout re-sends leave the count without a congestion reaction: a probe timeout is not a loss (RFC 9002 section 6.2).
- **The window**: 10 datagrams to start (within 14,720 bytes, at least 2 datagrams), doubling per round trip in slow start, one datagram per window after the first loss, halved once per recovery period (losses of packets sent before the reduction do not halve it again), at least 2 datagrams. Persistent congestion (losses spanning three probe timeouts, with an RTT sample) drops it to the minimum.
- **What it holds back**: packets that would be in flight. ACK-only packets always go; probes and closes may pass the window (section 7.5). A datagram goes while the window has any room, so it may pass the window by less than one datagram, as is usual.
- **Pacing** (section 7.7): 1.25 times the window per smoothed round trip, with bursts of up to ten datagrams. `poll_timeout` includes the pacing timer; `Config::pacing` turns it off.

Persistent congestion is judged on one batch of losses at a time: the first and last lost packets must be more than three probe timeouts apart. The RFC also requires that nothing between them was acknowledged; a batch of losses found together has nothing acknowledged between them by construction, but losses found in separate batches are not combined, so persistent congestion may be found later than the RFC allows. That errs on the side of a larger window for one more round trip.

Cost, an estimate not yet benchmarked: a few integer operations per packet sent, acknowledged, or lost, and a few floating point ones per datagram for the pacer.

## 3g. Design of migration (0.7)

RFC 9000 sections 8 and 9. The connection now knows the peer's address: `handle_datagram` takes where a datagram came from, and `poll_transmit` says where to send.

- **A path** is the peer's address, its amplification limit (until the address is proved), and a path challenge in progress. A client hears only from the server it chose.
- **The server follows** a client whose non-probing packet with the largest packet number comes from a new address (section 9.3). It sends there at once, within three times what it receives from that address, challenges it, and keeps the previous validated path until the challenge is answered; if it is not answered within three probe timeouts (at least three initial RTTs), the server returns to the previous path, or ends the connection when there is none. A packet replayed from another address carries a packet number already seen, so it moves nothing.
- **Congestion**: a new IP address resets the controller and the pacer (section 9.4); a port change alone, the usual NAT rebinding, keeps them.
- **Probing**: a `PATH_CHALLENGE` from an address other than the path's is answered there, in a datagram of its own, within three times the datagram that asked (section 8.2.2). Datagrams carrying a challenge are padded to 1,200 bytes when the limit allows.
- **Connection IDs**: once the handshake completes, each side issues IDs up to the peer's `active_connection_id_limit` (at most 4 active), with stateless reset tokens from the configured reset key (or a random one per connection), and replaces each the peer retires. The caller learns of them through `LocalCidIssued` and `LocalCidRetired`, to route datagrams.
- **A client's migration** (`migrate`): after its socket changed, the client moves to a fresh connection ID of the server's, retires the old one, resets its congestion state, and challenges the path. It is refused before the handshake is confirmed, when the server set `disable_active_migration`, or without a spare ID.

Random challenge data and connection IDs come from the operating system through mod-rand, which crypt-io already brings in.

## 3h. HTTP/3

HTTP/3 and QPACK go in an engine of their own on top of quic-net, planned in [`H3.md`](./H3.md) until the crate is named. quic-net's part is the transport; what the engine needs from it (a writable event, send order, bulk reads) is listed there and in the roadmap.

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
| forged or altered address validation tokens | AEAD under a server key: a token that does not authenticate, has expired, or names another address validates nothing | about 1 us per token checked |
| linking connections through `NEW_TOKEN` tokens | the token's contents are encrypted, and a fresh nonce makes every token different | none beyond the AEAD |
| amplification through an unvalidated address | at most three times the bytes received on the path until it is validated, counted per path | two counters per path |
| a 1-RTT packet before the client is authenticated | the server processes none until tls-net says the handshake is complete (RFC 9001 section 5.7) | none |
| forged packets wearing down the AEAD | every packet that fails to open counts toward the integrity limit; at the limit, `AEAD_LIMIT_REACHED` | one counter |
| a stale peer configuration on resumption | the client ignores the previous session's transport parameters and waits for the server's new ones | none |
| a peer slowing its ACKs to make this endpoint flood a path | the window grows only on acknowledged bytes, and losses halve it; pacing spreads each window over the round trip | none beyond the bookkeeping |
| redirecting a connection with spoofed source addresses | the server moves only on a non-probing packet with a new largest packet number, which an off-path attacker cannot make; sends to the new address within three times what it received from it until a path challenge is answered; returns to the previous path if it is not | one challenge per migration |
| linking a client's paths | a migrating client moves to a fresh connection ID and retires the old one | none |
| replaying a packet from another address | a duplicate packet number moves nothing | none |
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

tls-net is not changed from here; the interface below is what quic-net asks of it.

### The interface requested from tls-net (2026-11-20)

Checked against rustls 0.23.46. A `quic` module in tls-net, behind a `quic` feature, with owned wrappers so neither crate's API carries rustls types and tls-net does not depend on quic-net. quic-net implements its own `PacketKey` and `HeaderKey` traits for tls-net's key types (D-017).

| Item | What it does | Wraps |
|---|---|---|
| `TlsClient::connect_quic(server_name, transport_params)`, `TlsServer::accept_quic(transport_params)` | a QUIC handshake with our encoded transport parameters, on the configs tls-net already builds; refused at construction without TLS 1.3 only, without ALPN, or with a server early-data limit other than 0 or 2^32 - 1; the ClientHello hook, host scoping, limits, and observer apply as for TCP | `quic::ClientConnection::new`, `quic::ServerConnection::new` (`Version::V1`) |
| `QuicSession::read_handshake(data)`, `write_handshake(out) -> Option<KeyChange>` | CRYPTO bytes in, in order; CRYPTO bytes out at the current level, with the key change that ends it | `read_hs`, `write_hs` |
| `peer_transport_parameters()`, `alert()`, `alpn()`, `is_handshaking()`, `server_name()`, `peer_certificates()`, `negotiated_suite()` | the peer's parameters, the alert for `CRYPTO_ERROR`, what was agreed | `quic_transport_parameters`, `alert`, and the common connection accessors |
| `KeyChange { Handshake { keys }, OneRtt { keys, next } }`, `Keys { local, remote }`, `DirectionalKeys { packet, header }` | the keys of each level as they become available | the same rustls types |
| `PacketKey::{seal, open, tag_len, confidentiality_limit, integrity_limit}` | AEAD in place; `open` takes the payload and its tag as one slice | `quic::PacketKey` |
| `HeaderKey::mask(sample) -> [u8; 5]` | the header protection mask | `quic::HeaderProtectionKey::encrypt_in_place` on a short header with a 4-byte packet number of zeros, which yields every mask bit QUIC uses |
| `Secrets::next_packet_keys() -> PacketKeySet { local, remote }` | key updates | `quic::Secrets` |
| `initial_keys(client_dcid, side) -> Keys` | Initial keys before any session exists | `quic::Keys::initial` with the provider's AES-128-GCM QUIC suite |
| `retry_tag(pseudo_packet) -> [u8; 16]` | the Retry integrity tag | the provider's AES-128-GCM (rustls does not expose it) |

Later, not needed for the first handshake: `zero_rtt_keys`, `is_early_data_accepted`, `reject_early_data`. Not needed: QUIC version 2 and multipath.

Tests asked for with it: the RFC 9001 appendix A Initial and Retry vectors; a client and a server handshaking in memory to 1-RTT keys with each other's transport parameters and ALPN; refusal without ALPN and the `no_application_protocol` alert on a mismatch; the A.5 key update chain; both providers tls-net ships.

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
| D-017 | 2026-11-20 | Keys come from a `quic` module in tls-net with owned wrappers around rustls's QUIC types (section 5); quic-net implements its `PacketKey` and `HeaderKey` traits for them, and `PacketKey::open` changes in 0.5 to take the payload and tag as one slice | neither crate's API then carries rustls types, tls-net does not depend on quic-net, and the orphan rule allows the impls in quic-net, which owns the traits; the payload and tag are contiguous in a packet, and rustls opens them that way |
| D-018 | 2026-11-20 | Address validation tokens are sealed with XChaCha20-Poly1305 through crypt-io, not only authenticated | a `NEW_TOKEN` token is sent in clear on a later connection; with a MAC alone, the address it was issued to would be readable and would link the two connections (RFC 9000 section 8.1.3). The 192-bit random nonce makes a nonce collision under one key impossible in practice, at one extra ChaCha20 block per token |
| D-019 | 2026-11-20 | Token keys rotate with one previous key kept; the key ID is a clear byte of the token | a rotation must not void every outstanding `NEW_TOKEN` token at once; one previous key covers a rotation period longer than a token's lifetime |
| D-020 | 2026-11-20 | The amplification limit is counted per path in quic-net, not taken from net-io's guard | net-io counts per IP address and ages received bytes out after its window; RFC 9000 counts per path (address and port) until the path is validated. With net-io's guard, a second port of the same IP would share the first port's allowance, and a slow handshake could lose its allowance |
| D-021 | 2026-11-25 | `Connection` is one sans-IO type for both sides: `handle_datagram`, `poll_transmit`, `poll_timeout` / `handle_timeout`, `poll_event`, and stream calls by ID; the caller supplies connection IDs and `now` | the crate stays without I/O and without a clock, so it runs on any driver (net-io's reactor, a test harness, a simulation) and every behaviour is reproducible; IDs come from the caller because only it knows its routing scheme (and its random source) |
| D-022 | 2026-11-25 | The connection depends on tls-net 0.11 with the ring provider and the Mozilla roots, behind a default `tls` feature | QUIC without TLS is only the wire layer; keeping that layer usable without rustls costs one feature; ring needs no build tools, as in dns-net (D-021 there) |
| D-023 | 2026-11-25 | Loss detection and the probe timeout come with 0.5; congestion control waits for 0.6 | a handshake that loses a datagram must recover, so RFC 9002's detection and PTO are needed now; congestion control is its own design (and benchmarks) |
| D-024 | 2026-11-25 | A client keeps its PTO backoff across Initial ACKs and probes without packets in flight only until a Handshake packet of its own is acknowledged | RFC 9002 section 6.2.1 and 6.2.2.1; found by the `connection` fuzz target: with the backoff reset and the probes unconditional, a client whose server lost its flight probed every PTO (1 ms on a fast path) until the server's own timer fired |
| D-025 | 2026-11-25 | A client applies the server's transport parameters only once its handshake is complete | on resumption rustls returns the previous session's parameters before the handshake (for 0-RTT); applying them failed the connection IDs check. Found by the `connection` fuzz target |
| D-026 | 2026-11-25 | 0.6 is congestion control and pacing; migration, more connection IDs, initiating key updates, and 0-RTT move to 0.7 | congestion control is what a public crate needed next: without it a sender is limited only by flow control. Migration and 0-RTT are their own designs and do not change what 0.6 delivers |
| D-027 | 2026-11-25 | NewReno, the controller RFC 9002 specifies, behind a small internal interface (sent, acknowledged, lost, discarded, persistent congestion) | it is the one the RFC describes in full, so it can be checked against the text; the interface leaves room for CUBIC or BBR later without touching the connection |
| D-028 | 2026-11-25 | The pacer accepts a budget within one byte of a datagram and never waits less than 1 us | its refill is floating point; a timer set to the exact moment could find the budget a hair short and wait zero nanoseconds, so a caller woken at that time would spin without sending |
| D-029 | 2026-11-25 | 0.7 is migration: paths, path validation, the server following a client, issuing connection IDs, and a client's migration. Initiating key updates and 0-RTT move to 0.8 | a connection without a notion of the peer's address sends to a rebound client's new address without proving it, which RFC 9000 section 9 forbids; that was a gap in what 0.5 and 0.6 published. Key updates and 0-RTT do not change what 0.7 delivers |
| D-030 | 2026-11-25 | `handle_datagram` takes the sender's address and `poll_transmit` returns the destination; the constructors take the peer's address | sans-IO still: the caller owns the socket, and the connection decides where each datagram goes. A breaking change, made at 0.x |
| D-031 | 2026-11-25 | Challenge data and issued connection IDs come from mod-rand's operating system source; an issued ID has the length of the handshake's ID; at most 4 are active | mod-rand is first-party and already in the tree through crypt-io; a fixed length keeps short-header parsing working for every ID of the connection; 4 is enough to migrate and keep spares without holding many |
| D-032 | 2026-11-25 | HTTP/3 and QPACK are planned as an engine of their own (`H3.md`), depending on quic-net, h2-net (Huffman and the bounded field list), and http-net (the request types and the strict mapping), not as a part of quic-net | QUIC is a transport other protocols use too; HTTP/3 shares semantics with HTTP/1.1 and HTTP/2, so it maps through the same rules, and QPACK reuses HPACK's Huffman table, which h2-net already has. The name is James's call |
