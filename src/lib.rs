//! # quic_net
//!
//! QUIC (RFC 9000) for Rust, built up from its parts. This release has the
//! sans-IO wire layer: variable-length integers, packet headers and version
//! negotiation, every transport frame, transport parameters, and connection
//! IDs with their stateless reset tokens. Every decoder works on borrowed
//! bytes, checks lengths before it reads, and keeps counts within fixed
//! budgets.
//!
//! Packet protection (RFC 9001 section 5) sits on top: [`seal_packet`],
//! [`remove_header_protection`], and [`open_payload`] do the framing around
//! two key traits, [`PacketKey`] and [`HeaderKey`], which a TLS session
//! implements. [`InitialSecrets`] derives the Initial keys' bytes, and
//! [`AeadUsage`] counts against the AEAD limits.
//!
//! Streams (RFC 9000 sections 2 to 4): [`StreamId`], stream limits both ways
//! ([`LocalStreams`], [`RemoteStreams`]), flow control credit both ways
//! ([`RecvCredit`], [`SendCredit`]), [`RecvStream`] for reassembly, final
//! size, and reset, [`SendStream`] for buffering, loss, and retransmission,
//! and [`CryptoRecv`] for the handshake's CRYPTO data.
//!
//! Address validation (RFC 9000 section 8): [`Tokens`] issues and checks
//! Retry and `NEW_TOKEN` tokens, sealed with crypt-io's XChaCha20-Poly1305,
//! and [`Amplification`] keeps a server within three times what it
//! received until the client's address is validated.
//!
//! With the `tls` feature (on by default), `Connection` puts it together:
//! a client or server connection, sans-IO, whose handshake runs through
//! tls-net. The caller passes it datagrams, sends what it produces, and
//! runs its timers. Its congestion control is NewReno with pacing (RFC 9002
//! section 7), and it follows a client that changes address once the new
//! address answers a path challenge (RFC 9000 section 9).
//!
//! ## Read the frames of a packet
//!
//! ```
//! use quic_net::{Frame, PacketKind, frames};
//!
//! let mut payload = Vec::new();
//! Frame::Crypto { offset: 0, data: b"client hello" }.encode(&mut payload);
//! Frame::Padding { len: 10 }.encode(&mut payload);
//! for frame in frames(&payload, PacketKind::Initial) {
//!     match frame? {
//!         Frame::Crypto { data, .. } => assert_eq!(data, b"client hello"),
//!         Frame::Padding { len } => assert_eq!(len, 10),
//!         other => panic!("{other:?}"),
//!     }
//! }
//! # Ok::<(), quic_net::DecodeError>(())
//! ```
//!
//! The design, its threats, and its decisions are in `dev/PLAN.md` in the
//! [repository](https://github.com/jamesgober/quic-net).

#![doc(html_root_url = "https://docs.rs/quic-net")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::dbg_macro,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

mod address;
#[cfg(feature = "tls")]
mod cc;
mod cid;
#[cfg(feature = "tls")]
mod conn;
mod error;
mod flow;
mod frame;
mod packet;
mod params;
mod protect;
mod ranges;
mod recv;
mod send;
mod stream;
#[cfg(feature = "tls")]
mod tls;
mod varint;

pub use address::{Amplification, MAX_TOKEN_LEN, TokenCheck, Tokens};
#[cfg(feature = "tls")]
pub use cc::CongestionState;
pub use cid::{
    CidError, ConnectionId, LocalCids, MAX_CID_LEN, MIN_STATELESS_RESET, PeerCid, PeerCids,
    ResetKey, ResetToken, is_stateless_reset,
};
#[cfg(feature = "tls")]
pub use conn::{Close, Config, ConnectError, Connection, Event, MigrateError, StreamError};
pub use error::{DecodeError, TransportErrorCode};
pub use flow::{RecvCredit, SendCredit};
pub use frame::{
    Ack, AckRanges, EcnCounts, Frame, Frames, MAX_ACK_RANGES, MAX_STREAMS, PacketKind, frames,
};
pub use packet::{
    Coalesced, Header, LongHeader, LongType, MAX_COALESCED, MIN_INITIAL_SIZE, MIN_PROTECTED,
    Packet, VERSION_1, coalesced, decode_packet_number, packet_number_len, parse_packet,
    write_retry, write_short, write_version_negotiation,
};
pub use params::{MAX_PARAMETERS, PreferredAddress, Side, TransportParameters};
pub use protect::{
    AeadLimits, AeadUsage, CryptoError, HeaderKey, INITIAL_SALT_V1, InitialSecrets, KeyMaterial,
    PacketKey, ProtectError, RETRY_KEY_V1, RETRY_NONCE_V1, RetryIntegrity, SAMPLE_LEN, Secret,
    TAG_LEN, Unprotected, nonce, open_payload, remove_header_protection, retry_tag, seal_packet,
    verify_retry,
};
pub use recv::{CryptoRecv, MAX_CRYPTO_BUFFER, MAX_FRAGMENTS, RecvState, RecvStream};
pub use send::{Chunk, SendState, SendStream};
pub use stream::{LocalStreams, RemoteStreams, StreamId};
#[cfg(feature = "tls")]
pub use tls::TlsRetry;
pub use varint::{MAX_VARINT, VarInt};

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_matches_manifest() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(VERSION.split('.').count(), 3, "expected MAJOR.MINOR.PATCH");
    }
}
