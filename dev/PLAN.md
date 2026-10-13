# quic-net - Project Plan

> The design, strategy, and decision record for `quic-net`. A living document: every design decision, idea, or open question about quic-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Status:** scaffold, `0.1.0`. **Scheduled later** (see `_strategy/WEB-STACK-DELIVERABLES.md`); the largest crate in the network family.

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

## 4. Threats

| Threat | Defence |
|---|---|
| amplification (spoofed source addresses) | at most three times the received bytes before address validation; retry tokens |
| connection ID exhaustion, state floods | budgets per peer; bouncer strikes |
| spoofed migration | path validation before trusting a new address |
| handshake floods | stateless retry under load |

## 5. Prerequisites

net-io UDP (with the no-amplification rule), tls-net, the reactor driver for many connections per thread.

## 6. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | Own crate, scheduled later | a full transport stack; not needed while the front end handles HTTP/3 |
