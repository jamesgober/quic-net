# quic-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - The wire layer (started 2026-11-20)
- [x] Variable-length integers, long and short headers, version negotiation, Retry, coalesced packets, packet numbers.
- [x] All 21 transport frame types of version 1, with the packet-type table and budgets.
- [x] Transport parameters.
- [x] Connection IDs both ways, and stateless reset tokens.
- [x] A fuzz target for every decoder; benchmarks of the hot paths.
- [x] Prerequisites from net-io and tls-net listed in PLAN section 5.

## v0.3.0 - Packet protection (2026-11-20)
- [x] Header protection and packet protection over key traits (`PacketKey`, `HeaderKey`), opened in two steps; the reserved bits checked after authentication (D-009, D-010).
- [x] The Initial key schedule, key material, and key update secrets; secrets zeroed on drop.
- [x] AEAD limits (RFC 9001 section 6.6) and the Retry integrity tag.
- [x] The RFC 9001 appendix A vectors byte for byte (D-011); fuzz target `protection`; benchmarks.
- Moved to 0.4, with the reason in PLAN D-012: the connection, stream, and configuration APIs.

## v0.4.0 - Streams and flow control (2026-11-20)
- [x] Stream IDs and stream limits both ways.
- [x] Flow control credit both ways, for streams and the connection.
- [x] Receive streams: reassembly, final size, reset, stop; CRYPTO reassembly with its limit (D-014 to D-016).
- [x] Send streams: buffering, credit, loss and retransmission, acknowledgement, reset.
- [x] An end-to-end test over a hostile channel; fuzz target `streams`; benchmarks.
- Moved to 0.5, with the reason in PLAN D-013: the connection API, keys from tls-net, the handshake, and address validation.

## v0.5.0 - Design lock and handshake (2026-11-25)
- [x] Connection, stream, and configuration APIs (moved from 0.3, D-012, and 0.4, D-013; D-021).
- [x] Keys from tls-net 0.11's QUIC interface behind `PacketKey` and `HeaderKey` (D-017, D-022).
- [x] The handshake, with RFC 9002's loss detection and probe timeout; Retry; the peer's key updates (D-023 to D-025).
- [x] Tests: handshake, stream echo, lossy channels, resumption, Retry, close, amplification; fuzz target `connection`.
- [x] Address validation tokens (Retry and `NEW_TOKEN`) and the anti-amplification limit of a path (D-018 to D-020).

## v0.6.0 - Congestion control (2026-11-25)
- [x] NewReno with pacing (RFC 9002 section 7); loss detection and the probe timeout came with 0.5 (D-026 to D-028).
- [x] A bottleneck test: the window bounds what is in flight and shrinks on loss.
- Moved to 0.7, with the reason in PLAN D-026: migration and path validation, more connection IDs, initiating key updates, 0-RTT.

## v0.7.0 - Migration
- [ ] Migration and path validation; issuing more connection IDs; initiating key updates (moved from 0.6, D-026).
- [ ] 0-RTT (moved from 0.6, D-026).

## v1.0.0 - Stable
- [ ] Frozen after an HTTP/3 engine has used it end to end.
