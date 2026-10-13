//! # quic_net
//!
//! QUIC transport for Rust over the UDP socket of net-io: connections, streams, loss recovery, and congestion control, with TLS 1.3 through tls-net. The base for HTTP/3.
//!
//! ## Status
//!
//! Scaffold. The design is written down in `dev/PLAN.md` and the milestone
//! schedule in `dev/ROADMAP.md` (both in the
//! [repository](https://github.com/jamesgober/quic-net)); the public API
//! begins with `0.2.0`.

#![doc(html_root_url = "https://docs.rs/quic-net")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

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
