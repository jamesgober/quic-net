<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>quic-net</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.4.0] - 2026-11-20

Streams and flow control: the parts of RFC 9000 sections 2 to 4 that need
no handshake.

### Added

- `StreamId`, `LocalStreams`, `RemoteStreams`: stream IDs and stream limits
  both ways, with the checks for frames on the wrong kind of stream.
- `RecvCredit` and `SendCredit`: flow control for streams and connections,
  both ways.
- `RecvStream`: reassembly at any order, the final size rules, reset, and
  stop. Data is stored at its offset, so inserting costs only the new bytes.
  At most 1,024 separate pieces of unread data (`MAX_FRAGMENTS`).
- `SendStream` and `Chunk`: buffering until acknowledged, credit for new
  data only, lost data sent again, acknowledgement in any order, reset.
- `CryptoRecv`: CRYPTO reassembly with a 64 KiB limit (`MAX_CRYPTO_BUFFER`).
- A test sending streams over a channel that loses, duplicates, and
  reorders packets and acknowledgements; a `streams` fuzz target; stream
  costs in `benches/codec.rs`.

## [0.3.0] - 2026-11-20

Packet protection: everything RFC 9001 section 5 asks of the transport,
over key traits a TLS session implements.

### Added

- `PacketKey` and `HeaderKey`: the AEAD and header protection keys of one
  direction and level, implemented by whatever provides the ciphers.
- `seal_packet`, `remove_header_protection`, `open_payload`: protecting and
  opening a packet in place around the wire layer's headers. Opening takes
  two steps so the key phase can pick the key; the reserved bits are
  checked only after the payload authenticates.
- `InitialSecrets`, `Secret`, `KeyMaterial`: the Initial key schedule, key
  material for 16- and 32-byte keys, and the next secret of a key update.
  Secrets and key material are zeroed on drop.
- `AeadLimits` and `AeadUsage`: the confidentiality and integrity limits of
  RFC 9001 section 6.6.
- `retry_tag`, `verify_retry`, `RetryIntegrity`: the Retry integrity tag,
  checked in constant time.
- The RFC 9001 appendix A vectors as tests, byte for byte; a `protection`
  fuzz target; protection costs in `benches/codec.rs`.

### Changed

- crypt-io's `mac-hmac` feature, for HKDF in the Initial key schedule.

## [0.2.0] - 2026-11-20

The wire layer: everything on the wire that needs no keys.

### Added

- `VarInt`: variable-length integers (RFC 9000 section 16).
- `parse_packet`, `coalesced`, `LongHeader`, `write_short`,
  `write_version_negotiation`, `write_retry`, `packet_number_len`,
  `decode_packet_number`: packet headers read before header protection,
  version negotiation, Retry, a datagram's coalesced packets, and packet
  number encoding (section 17, appendix A).
- `Frame` and `frames`: all 21 transport frame types of version 1, decoded
  without copying, checked against the packet type that carries them, and
  written back; `Ack::write` for ACK frames.
- `TransportParameters`: every version 1 parameter, with its range and the
  side that may send it (section 18).
- `ConnectionId`, `PeerCids`, `LocalCids`: connection IDs both ways
  (sections 5.1, 19.15, 19.16). `ResetKey`, `ResetToken`,
  `is_stateless_reset`: stateless reset tokens from keyed BLAKE3, compared in
  constant time (section 10.3).
- `DecodeError` and `TransportErrorCode`.
- Fuzz targets for every decoder, and benchmarks.

---

## [0.1.0] - 2026-10-13

The scaffold and the plan. No functional code yet.

### Added

- Crate manifest (edition 2024, MSRV 1.85, no dependencies), `Apache-2.0 OR MIT`
  license, README, REPS, CI (Linux, macOS, Windows on stable and 1.85; audit
  and deny), `deny.toml`, `clippy.toml`, `rustfmt.toml`, `.gitattributes`.
- `dev/PLAN.md` (purpose, scope, architecture, threats, ecosystem, open
  decisions, decision log), `dev/DIRECTIVES.md`, and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/quic-net/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jamesgober/quic-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/quic-net/releases/tag/v0.1.0
