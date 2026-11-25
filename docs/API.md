# quic-net - API Reference

> Every public item of `quic-net` `0.6.0`: the wire layer, packet protection, streams, address validation, and the connection. The rustdoc on docs.rs has the full signatures.

<sub>Copyright &copy; 2026 <strong>James Gober</strong>.</sub>

## Table of contents

- [Integers](#integers): `VarInt`, `MAX_VARINT`
- [Packets](#packets): `parse_packet`, `Packet`, `Header`, `LongType`, `coalesced`, `Coalesced`, `LongHeader`, `write_short`, `write_version_negotiation`, `write_retry`, `packet_number_len`, `decode_packet_number`, `VERSION_1`, `MIN_INITIAL_SIZE`, `MAX_COALESCED`, `MIN_PROTECTED`
- [Frames](#frames): `Frame`, `frames`, `Frames`, `PacketKind`, `Ack`, `AckRanges`, `EcnCounts`, `MAX_ACK_RANGES`, `MAX_STREAMS`
- [Transport parameters](#transport-parameters): `TransportParameters`, `PreferredAddress`, `Side`, `MAX_PARAMETERS`
- [Connection IDs](#connection-ids): `ConnectionId`, `CidError`, `MAX_CID_LEN`, `PeerCids`, `PeerCid`, `LocalCids`, `ResetKey`, `ResetToken`, `is_stateless_reset`, `MIN_STATELESS_RESET`
- [Packet protection](#packet-protection): `PacketKey`, `HeaderKey`, `seal_packet`, `remove_header_protection`, `open_payload`, `Unprotected`, `ProtectError`, `CryptoError`, `nonce`, `AeadLimits`, `AeadUsage`, `Secret`, `KeyMaterial`, `InitialSecrets`, `RetryIntegrity`, `retry_tag`, `verify_retry`, `TAG_LEN`, `SAMPLE_LEN`, `INITIAL_SALT_V1`, `RETRY_KEY_V1`, `RETRY_NONCE_V1`
- [Streams and flow control](#streams-and-flow-control): `StreamId`, `LocalStreams`, `RemoteStreams`, `RecvCredit`, `SendCredit`, `RecvStream`, `RecvState`, `SendStream`, `SendState`, `Chunk`, `CryptoRecv`, `MAX_FRAGMENTS`, `MAX_CRYPTO_BUFFER`
- [Address validation](#address-validation): `Tokens`, `TokenCheck`, `MAX_TOKEN_LEN`, `Amplification`
- [Connection](#connection) (feature `tls`): `Connection`, `Config`, `Event`, `Close`, `ConnectError`, `StreamError`, `CongestionState`, `TlsRetry`
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

## Streams and flow control

Each piece does one job and reports what the connection must do next; a connection ties them together (0.5).

- `StreamId::new(initiator, bidi, index)`, `from_raw`, `raw`, `initiator`, `is_bidi`, `index`, and `can_send(local)` / `can_receive(local)` for the `STREAM_STATE_ERROR` checks.
- `LocalStreams::new(peer_limit)`: `open() -> Option<index>`, `raise(max)` on `MAX_STREAMS`, `blocked()` for `STREAMS_BLOCKED` (once per limit), `is_opened(index)`.
- `RemoteStreams::new(window)`: `on_frame(index) -> Result<Range<u64>, _>` (the indexes a frame opens; `STREAM_LIMIT_ERROR` past the limit), `on_closed()`, `update()` for `MAX_STREAMS` once half the window has closed.
- `RecvCredit::new(window)`: `receive_to(end)` for a stream, `receive_more(n)` for a connection (`FLOW_CONTROL_ERROR` past the limit), `consumed(n)`, `update()` for `MAX_DATA` / `MAX_STREAM_DATA` once half the window is read.
- `SendCredit::new(peer_max)`: `available()`, `consume(n)`, `raise(max)` (a lower limit is ignored), `blocked()` for `DATA_BLOCKED` (once per limit).

`RecvStream::new(window)`:
- `on_stream(offset, data, fin) -> Result<growth, _>`: the growth of the highest offset goes to the connection's `receive_more`.
- `on_reset(code, final_size)`.
- `read(out)`, `readable()`, `stop()` (then send `STOP_SENDING`), `update()`.
- `take_consumed()` for the connection's `consumed`.
- `state() -> RecvState` (`Recv`, `SizeKnown`, `DataRecvd`, `DataRead`, `ResetRecvd(code)`), `is_finished()`, `final_size()`, `held()`.

Errors: `FLOW_CONTROL_ERROR`, `FINAL_SIZE_ERROR`, and `PROTOCOL_VIOLATION` past `MAX_FRAGMENTS` (1,024) separate pieces of unread data. The first copy of a byte is kept.

`SendStream::new(peer_max_stream_data, buffer)`:
- `write(data) -> usize` (what fits), `writable()`, `finish()`.
- `next_chunk(max_len, connection_credit) -> Option<Chunk { offset, len, fin, new }>`: lost data first, new data within both credits; `new` is what to `consume` from the connection's credit.
- `write_frame(id, &chunk, out)`.
- `on_acked(&chunk)`, `on_lost(&chunk)`, `raise(max)`, `blocked()`.
- `reset(code)`, `on_stop_sending(code)`, `on_reset_acked()`, `on_reset_lost()`.
- `state() -> SendState`, `held()`, `has_pending()`.

`CryptoRecv`: `on_crypto(offset, data)` (`CRYPTO_BUFFER_EXCEEDED` for data reaching past `MAX_CRYPTO_BUFFER`, 64 KiB, beyond what TLS has read), `read`, `readable`, `read_offset`.

```rust
use quic_net::{RecvCredit, RecvStream};
let mut conn = RecvCredit::new(1 << 20);
let mut stream = RecvStream::new(256 * 1024);
let growth = stream.on_stream(0, b"hello", true)?;
conn.receive_more(growth)?;
let mut out = [0u8; 16];
let n = stream.read(&mut out);
conn.consumed(stream.take_consumed());
# Ok::<(), quic_net::TransportErrorCode>(())
```

## Address validation

`Tokens::new(key)` issues and checks address validation tokens under a 32-byte secret key, sealed with XChaCha20-Poly1305 through crypt-io (hidden and authenticated). `rotate(key)` moves to a new key and keeps the previous one; `retry_lifetime` (10 s by default) and `new_token_lifetime` (24 h).

- `retry_token(client, original_dcid, retry_scid, now)`: for a Retry; bound to the client's address and port.
- `new_token(client_ip, now)`: for a `NEW_TOKEN` frame; bound to the IP address only.
- `check(token, client, now) -> TokenCheck`: `Retry { original_dcid, retry_scid }` or `NewToken` (the address is validated), `InvalidRetry` (close with `code()`, `INVALID_TOKEN`), or `Unusable` (treat as no token). Tokens over `MAX_TOKEN_LEN` (160) bytes are not decrypted.

`now` is the time since the Unix epoch; the caller supplies it, so the crate does no I/O.

`Amplification` (one per path): `new()` for an unvalidated address, `validated()` for a client's view of its server; `on_received(len)` for every datagram attributed to the connection, `on_sent(len)`, `allowance()` (three times received, less sent), `is_blocked()`, `validate()`.

## Connection

Feature `tls` (on by default): a QUIC connection, sans-IO, with its handshake through tls-net 0.11.

- `Connection::client(tls, server_name, config, local_cid, initial_dcid, now)`, or `client_with_token(.., token, now)` with a `NEW_TOKEN` token from an earlier connection.
- `Connection::server(tls, config, local_cid, client_dcid, client_scid, retry, validated, now)` for a client's first Initial: `retry` is `Some((original_dcid, retry_scid))` from a checked Retry token, `validated` whether a token proved the address.
- The loop: `handle_datagram(now, &mut datagram)` for each datagram from the peer; `poll_transmit(now, &mut out) -> bool` until it returns `false`, sending each datagram; `poll_timeout()` and `handle_timeout(now)`; `poll_event() -> Option<Event>`.
- `Event`: `Connected`, `StreamOpened(id)`, `StreamReadable(id)`, `StreamReset { id, code }`, `StreamStopped { id, code }`, `NewToken(token)`, `Closed(Close { code, application, reason, remote })`.
- Streams: `open_stream(bidi)`, `stream_write(id, data) -> usize`, `stream_finish(id)`, `stream_reset(id, code)`, `stream_read(id, out) -> usize` (0 when nothing is ready), `stream_is_finished(id)`, `stream_stop(id, code)`.
- `close(now, code, reason)`, `is_established()`, `is_closed()`, `close_reason()`, `alpn()`, `peer_params()`, `rtt()`, `local_cid()`, `side()`.
- Congestion: `congestion_window()`, `bytes_in_flight()`, `congestion_state() -> CongestionState` (`SlowStart`, `CongestionAvoidance`, `Recovery`). NewReno (RFC 9002 section 7) with pacing; `poll_timeout` includes the pacing timer.
- `Config`: `params` (the transport parameters to send; the connection fills in the IDs and the reset token), `max_datagram`, `send_buffer`, `reset_key`, `pacing` (on by default). The default: 10 MiB of connection credit, 1 MiB per stream, 100 streams of each type, a 30-second idle timeout.
- `TlsRetry` computes the Retry integrity tag through tls-net, for `retry_tag` and `verify_retry`.

```rust
let mut conn = quic_net::Connection::client(&tls, "example.com", Config::default(), my_cid, random_dcid, Instant::now())?;
let mut out = Vec::new();
while conn.poll_transmit(Instant::now(), &mut out) {
    socket.send(&out)?;
}
```

Not yet: 0-RTT, migration, issuing more connection IDs, initiating key updates (the peer's are followed).

## Errors

`DecodeError` says what was refused; `DecodeError::code()` is the `TransportErrorCode` to close with. `TransportErrorCode` has the codes of RFC 9000 section 20 and `TransportErrorCode::crypto(alert)`.

## `VERSION`

```rust
println!("quic-net {}", quic_net::VERSION);
```
