# quic-net - Project Plan

> The design, strategy, and decision record for `quic-net`. A living document: every design decision, idea, or open question about quic-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Status:** scaffold, `0.1.0`. **Scheduled later**; the largest crate in the network family.

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

## 6. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | Own crate, scheduled later | a full transport stack; not needed while the front end handles HTTP/3 |
| D-002 | 2026-11-20 | The UDP prerequisites from net-io are listed in section 5 | checked against net-io 0.8.1: batching exists on Linux only; GSO, GRO, ECN, the don't-fragment bit, UDP buffer sizes and Windows packet info are missing; the amplification guard counts per IP rather than per path |
