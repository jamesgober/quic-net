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

## v0.4.0 - Design lock, handshake, and streams
- [ ] Connection, stream, and configuration APIs (moved from 0.3, D-012).
- [ ] Keys from tls-net's QUIC interface behind `PacketKey` and `HeaderKey` (PLAN section 5).
- [ ] Handshake, streams, flow control, address validation.

## v0.5.0 - Recovery and migration
- [ ] Loss detection, congestion control, pacing, migration and path validation.

## v1.0.0 - Stable
- [ ] Frozen after an HTTP/3 engine has used it end to end.
