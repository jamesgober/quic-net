//! # quic_net
//!
//! QUIC (RFC 9000) for Rust, built up from its parts. This release has the
//! sans-IO wire layer that needs no TLS: variable-length integers, packet
//! headers and version negotiation, every transport frame, transport
//! parameters, and connection IDs with their stateless reset tokens. Every
//! decoder works on borrowed bytes, checks lengths before it reads, and
//! keeps counts within fixed budgets.
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

mod cid;
mod error;
mod frame;
mod packet;
mod params;
mod varint;

pub use cid::{
    CidError, ConnectionId, LocalCids, MAX_CID_LEN, MIN_STATELESS_RESET, PeerCid, PeerCids,
    ResetKey, ResetToken, is_stateless_reset,
};
pub use error::{DecodeError, TransportErrorCode};
pub use frame::{
    Ack, AckRanges, EcnCounts, Frame, Frames, MAX_ACK_RANGES, MAX_STREAMS, PacketKind, frames,
};
pub use packet::{
    Coalesced, Header, LongHeader, LongType, MAX_COALESCED, MIN_INITIAL_SIZE, MIN_PROTECTED,
    Packet, VERSION_1, coalesced, decode_packet_number, packet_number_len, parse_packet,
    write_retry, write_short, write_version_negotiation,
};
pub use params::{MAX_PARAMETERS, PreferredAddress, Side, TransportParameters};
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
