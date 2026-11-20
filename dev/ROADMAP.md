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

## v0.3.0 - Design lock and packet protection
- [ ] Connection, stream, and configuration APIs.
- [ ] Packet protection and header protection, the Retry integrity tag, on tls-net's QUIC interface (once it has one; PLAN section 5).

## v0.4.0 - Handshake and streams
- [ ] Handshake, streams, flow control, address validation.

## v0.5.0 - Recovery and migration
- [ ] Loss detection, congestion control, pacing, migration and path validation.

## v1.0.0 - Stable
- [ ] Frozen after an HTTP/3 engine has used it end to end.
