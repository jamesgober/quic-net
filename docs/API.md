# quic-net - API Reference

> Every public item of `quic-net` `0.3.0`: the wire layer and packet protection. The rustdoc on docs.rs has the full signatures.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Integers](#integers): `VarInt`, `MAX_VARINT`
- [Packets](#packets): `parse_packet`, `Packet`, `Header`, `LongType`, `coalesced`, `Coalesced`, `LongHeader`, `write_short`, `write_version_negotiation`, `write_retry`, `packet_number_len`, `decode_packet_number`, `VERSION_1`, `MIN_INITIAL_SIZE`, `MAX_COALESCED`, `MIN_PROTECTED`
- [Frames](#frames): `Frame`, `frames`, `Frames`, `PacketKind`, `Ack`, `AckRanges`, `EcnCounts`, `MAX_ACK_RANGES`, `MAX_STREAMS`
- [Transport parameters](#transport-parameters): `TransportParameters`, `PreferredAddress`, `Side`, `MAX_PARAMETERS`
- [Connection IDs](#connection-ids): `ConnectionId`, `CidError`, `MAX_CID_LEN`, `PeerCids`, `PeerCid`, `LocalCids`, `ResetKey`, `ResetToken`, `is_stateless_reset`, `MIN_STATELESS_RESET`
- [Packet protection](#packet-protection): `PacketKey`, `HeaderKey`, `seal_packet`, `remove_header_protection`, `open_payload`, `Unprotected`, `ProtectError`, `CryptoError`, `nonce`, `AeadLimits`, `AeadUsage`, `Secret`, `KeyMaterial`, `InitialSecrets`, `RetryIntegrity`, `retry_tag`, `verify_retry`, `TAG_LEN`, `SAMPLE_LEN`, `INITIAL_SALT_V1`, `RETRY_KEY_V1`, `RETRY_NONCE_V1`
- [Errors](#errors): `DecodeError`, `TransportErrorCode`
- [`VERSION`](#version)

## Integers

`VarInt::new(u64) -> Option<VarInt>` (at most 2^62 - 1), `VarInt::decode(&[u8]) -> Result<(VarInt, usize), DecodeError>`, `encode(&mut Vec<u8>)` (shortest form), `get`, `size`.

```rust
let mut out = Vec::new();
quic_net::VarInt::new(494_878_333).unwrap().encode(&mut out);
assert_eq!(out, [0x9d, 0x7f, 0x3e, 0x7d]);
```

## Packets

`parse_packet(datagram, short_dcid_len) -> Result<Packet, DecodeError>` reads the first packet of a datagram before header protection is removed. `Packet { header, pn_offset, bytes }`: where the protected packet number starts, and the packet's bytes (a long header packet ends at its Length; others take the rest of the datagram).

`Header` variants:

| Variant | Fields |
|---|---|
| `Long` | `ty` (`Initial`, `ZeroRtt`, `Handshake`), `version`, `dcid`, `scid`, `token` |
| `Retry` | `version`, `dcid`, `scid`, `token`, `integrity_tag` |
| `Short` | `dcid`, `spin` |
| `VersionNegotiation` | `dcid`, `scid`, `versions` (and `Header::versions()`) |
| `Unsupported` | `version`, `dcid`, `scid` (up to 255 bytes each), to answer with version negotiation |

Refused: the fixed bit clear, a version 1 connection ID over 20 bytes, a Length past the datagram, a protected packet under `MIN_PROTECTED` (20) bytes from its packet number, a version list that is not whole versions.

`coalesced(datagram, short_dcid_len)` iterates a datagram's packets: at most `MAX_COALESCED` (8), stopping at a packet whose destination ID differs from the first.

Writing: `LongHeader { ty, dcid, scid, token }.encode(out, pn, pn_len, payload_len) -> pn_offset`, `write_short(out, dcid, spin, key_phase, pn, pn_len) -> pn_offset`, `write_version_negotiation(out, dcid, scid, versions, unused)`, `write_retry(out, dcid, scid, token, tag, unused)`. `packet_number_len(pn, largest_acked)` and `decode_packet_number(largest, truncated, pn_len)` follow RFC 9000 appendix A.

## Frames

`frames(payload, kind) -> Frames` iterates a packet payload's frames, refusing an empty payload, a malformed frame, and a frame the packet type must not carry (`PacketKind`: `Initial`, `Handshake`, `ZeroRtt`, `OneRtt`; RFC 9000 table 3). Iteration stops at the first error.

`Frame` variants: `Padding { len }`, `Ping`, `Ack(Ack)`, `ResetStream`, `StopSending`, `Crypto { offset, data }`, `NewToken { token }`, `Stream { stream_id, offset, data, fin }`, `MaxData`, `MaxStreamData`, `MaxStreams { bidi, max }`, `DataBlocked`, `StreamDataBlocked`, `StreamsBlocked { bidi, limit }`, `NewConnectionId`, `RetireConnectionId`, `PathChallenge`, `PathResponse`, `ConnectionClose { error_code, frame_type, reason }`, `HandshakeDone`. Methods: `encode`, `frame_type`, `allowed_in`, `is_ack_eliciting`.

`Ack { largest, delay, ecn }` and `Ack::ranges()` (largest first; checked at decode, at most `MAX_ACK_RANGES` + 1). `Ack::write(out, ranges, delay, ecn) -> bool` refuses ranges that touch or are out of order.

```rust
use quic_net::{Ack, Frame, PacketKind, frames};
let mut out = Vec::new();
assert!(Ack::write(&mut out, &[10..=20, 0..=5], 0, None));
let Some(Ok(Frame::Ack(ack))) = frames(&out, PacketKind::OneRtt).next() else { panic!() };
assert_eq!(ack.ranges().collect::<Vec<_>>(), vec![10..=20, 0..=5]);
```

## Transport parameters

`TransportParameters` holds every version 1 parameter with RFC 9000's defaults. `decode(bytes, sender: Side)` refuses a malformed, out-of-range, or repeated parameter, a server-only parameter from a client, a missing `initial_source_connection_id` (or `original_destination_connection_id` from a server), and more than `MAX_PARAMETERS` (128). `encode(out)` writes what differs from the defaults.

## Connection IDs

`ConnectionId::new(&[u8])` (0 to 20 bytes). `PeerCids::new(initial, our_limit)` keeps the peer's IDs: `on_new_connection_id(sequence, retire_prior_to, cid, token) -> Result<Vec<u64>, TransportErrorCode>` returns the sequence numbers to retire. `LocalCids::new(initial)` keeps ours: `issue(cid, &key)` (within the peer's limit), `on_retire(sequence, packet_dcid)`.

`ResetKey::new([u8; 32]).token(&cid)` derives a stateless reset token; `is_stateless_reset(datagram, tokens)` checks a datagram's last 16 bytes against every token in constant time.

## Packet protection

The ciphers are behind two traits; a TLS session implements them (quic-net has no cipher of its own):

- `PacketKey`: `seal(pn, header, payload) -> Result<[u8; 16], CryptoError>` encrypts in place and returns the tag; `open(pn, header, payload, tag)` checks and decrypts in place; `limits() -> AeadLimits`. The nonce is the IV with the packet number XORed in (`nonce(iv, pn)`), and the header is the associated data.
- `HeaderKey`: `mask(sample) -> Result<[u8; 5], CryptoError>`.

Sealing: write the header with `LongHeader::encode` or `write_short` (a long header's length counts the tag), append the payload and `TAG_LEN` (16) bytes, then `seal_packet(packet, pn_offset, pn, key, hp)`. With the packet number, the payload must be at least 4 bytes, so the 16-byte sample fits.

Opening is two steps, so the key phase can pick the key: `remove_header_protection(packet, pn_offset, largest_pn, hp) -> Unprotected { pn, pn_len, key_phase }`, then `open_payload(packet, &unprotected, key) -> Range<usize>` (where the frames are). `ProtectError`: `TooShort`, `Crypto`, `Authentication`, `ReservedBits` (checked only after the payload authenticates; `code()` is `PROTOCOL_VIOLATION`), `PacketNumber` (sealing with a number the header does not hold).

```rust
use quic_net::{open_payload, remove_header_protection, parse_packet};
let pn_offset = parse_packet(&datagram, 8)?.pn_offset;
let unprotected = remove_header_protection(&mut datagram, pn_offset, largest_pn, &hp)?;
let frames_at = open_payload(&mut datagram, &unprotected, &key)?;
```

Keys: `InitialSecrets::new(&dcid)` gives the client and server Initial secrets (`local(side)`, `remote(side)`). `Secret::key_material(key_len) -> KeyMaterial` (`key()`, `iv()`, `hp()`), `Secret::next()` for a key update (`quic ku`), `Secret::expand_label`. Secrets and key material are zeroed on drop.

Limits: `AeadLimits::{AES_GCM, CHACHA20_POLY1305, AES_CCM}` (RFC 9001 section 6.6). `AeadUsage` counts packets sealed under the current key (`may_seal`, `sealed`, `key_updated`) and forged packets received under any key (`failed` returns `AEAD_LIMIT_REACHED` at the limit).

Retry: `retry_tag(original_dcid, retry_without_tag, aead)` and `verify_retry(original_dcid, packet, aead)` (constant time), with `RetryIntegrity` the AES-128-GCM under `RETRY_KEY_V1` and `RETRY_NONCE_V1`.

## Errors

`DecodeError` says what was refused; `DecodeError::code()` is the `TransportErrorCode` to close with. `TransportErrorCode` has the codes of RFC 9000 section 20 and `TransportErrorCode::crypto(alert)`.

## `VERSION`

```rust
println!("quic-net {}", quic_net::VERSION);
```
