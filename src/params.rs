//! Transport parameters (RFC 9000 section 18): what each endpoint tells the
//! other about its limits during the handshake, carried in a TLS extension.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

use crate::cid::{ConnectionId, ResetToken};
use crate::error::DecodeError;
use crate::frame::MAX_STREAMS;
use crate::varint::{self, MAX_VARINT, Reader};

/// The most parameters read from one peer, GREASE included. Version 1 defines
/// 17; the bound stops a peer from sending thousands of unknown ones.
pub const MAX_PARAMETERS: usize = 128;

/// Which endpoint sent a set of parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    /// The client.
    Client,
    /// The server.
    Server,
}

/// A server's preferred address for migration after the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreferredAddress {
    /// The IPv4 address, if any (all zeros on the wire when none).
    pub ipv4: Option<SocketAddrV4>,
    /// The IPv6 address, if any.
    pub ipv6: Option<SocketAddrV6>,
    /// The connection ID to use there (1 to 20 bytes).
    pub cid: ConnectionId,
    /// Its stateless reset token.
    pub reset_token: ResetToken,
}

/// One endpoint's transport parameters, with the defaults of RFC 9000 for
/// those it did not send.
///
/// ```
/// use quic_net::{ConnectionId, Side, TransportParameters};
/// let mut p = TransportParameters::default();
/// p.initial_source_connection_id = Some(ConnectionId::new(&[1; 8])?);
/// p.initial_max_data = 1 << 20;
/// p.initial_max_streams_bidi = 100;
/// let mut wire = Vec::new();
/// p.encode(&mut wire);
/// assert_eq!(TransportParameters::decode(&wire, Side::Client)?, p);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportParameters {
    /// The destination ID of the client's first Initial (server only).
    pub original_destination_connection_id: Option<ConnectionId>,
    /// The idle timeout; zero means none.
    pub max_idle_timeout: Duration,
    /// The stateless reset token for the handshake's ID (server only).
    pub stateless_reset_token: Option<ResetToken>,
    /// The largest UDP payload the endpoint accepts (at least 1,200).
    pub max_udp_payload_size: u64,
    /// The connection's initial flow control limit.
    pub initial_max_data: u64,
    /// The initial limit for bidirectional streams this endpoint opens.
    pub initial_max_stream_data_bidi_local: u64,
    /// The initial limit for bidirectional streams the peer opens.
    pub initial_max_stream_data_bidi_remote: u64,
    /// The initial limit for unidirectional streams the peer opens.
    pub initial_max_stream_data_uni: u64,
    /// Bidirectional streams the peer may open (at most 2^60).
    pub initial_max_streams_bidi: u64,
    /// Unidirectional streams the peer may open (at most 2^60).
    pub initial_max_streams_uni: u64,
    /// The exponent the ACK delay is scaled by (at most 20).
    pub ack_delay_exponent: u8,
    /// The longest it delays an ACK (under 2^14 ms).
    pub max_ack_delay: Duration,
    /// It does not accept migration to a new address.
    pub disable_active_migration: bool,
    /// The server's preferred address (server only).
    pub preferred_address: Option<PreferredAddress>,
    /// How many of the peer's connection IDs it keeps (at least 2).
    pub active_connection_id_limit: u64,
    /// The source ID of its first long header packet (required from both).
    pub initial_source_connection_id: Option<ConnectionId>,
    /// The source ID of the server's Retry (server only, after a Retry).
    pub retry_source_connection_id: Option<ConnectionId>,
}

impl Default for TransportParameters {
    /// The defaults of RFC 9000 section 18.2: no idle timeout, payloads up
    /// to 65,527 bytes, every flow control limit and stream count 0, an ACK
    /// delay exponent of 3, 25 ms of ACK delay, and 2 connection IDs.
    fn default() -> TransportParameters {
        TransportParameters {
            original_destination_connection_id: None,
            max_idle_timeout: Duration::ZERO,
            stateless_reset_token: None,
            max_udp_payload_size: 65_527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: Duration::from_millis(25),
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: 2,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
        }
    }
}

mod id {
    pub const ORIGINAL_DCID: u64 = 0x00;
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub const STATELESS_RESET_TOKEN: u64 = 0x02;
    pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    pub const ACK_DELAY_EXPONENT: u64 = 0x0a;
    pub const MAX_ACK_DELAY: u64 = 0x0b;
    pub const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
    pub const PREFERRED_ADDRESS: u64 = 0x0d;
    pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
    pub const INITIAL_SCID: u64 = 0x0f;
    pub const RETRY_SCID: u64 = 0x10;
}

impl TransportParameters {
    /// Reads the parameters `sender` sent.
    ///
    /// # Errors
    ///
    /// [`DecodeError::BadTransportParameter`] (`TRANSPORT_PARAMETER_ERROR`)
    /// for a parameter that is malformed, out of range, repeated, sent by a
    /// client when only a server may send it, or missing when required
    /// (`initial_source_connection_id` from both, and
    /// `original_destination_connection_id` from a server); or for more than
    /// [`MAX_PARAMETERS`] in all.
    pub fn decode(bytes: &[u8], sender: Side) -> Result<TransportParameters, DecodeError> {
        let mut p = TransportParameters::default();
        let mut seen: u32 = 0;
        let mut count = 0usize;
        let mut r = Reader::new(bytes);
        while !r.is_empty() {
            let pid = r.varint().map_err(|_| bad(u64::MAX))?;
            let len = r.length().map_err(|_| bad(pid))?;
            let value = r.bytes(len).map_err(|_| bad(pid))?;
            count += 1;
            if count > MAX_PARAMETERS {
                return Err(bad(pid));
            }
            if pid <= id::RETRY_SCID {
                let bit = 1u32 << pid;
                if seen & bit != 0 {
                    return Err(bad(pid));
                }
                seen |= bit;
            }
            let server_only = matches!(
                pid,
                id::ORIGINAL_DCID
                    | id::STATELESS_RESET_TOKEN
                    | id::PREFERRED_ADDRESS
                    | id::RETRY_SCID
            );
            if server_only && sender == Side::Client {
                return Err(bad(pid));
            }
            let int = || integer(value).ok_or(bad(pid));
            match pid {
                id::ORIGINAL_DCID => p.original_destination_connection_id = Some(cid(value, pid)?),
                id::MAX_IDLE_TIMEOUT => p.max_idle_timeout = Duration::from_millis(int()?),
                id::STATELESS_RESET_TOKEN => {
                    let t: [u8; 16] = value.try_into().map_err(|_| bad(pid))?;
                    p.stateless_reset_token = Some(ResetToken::new(t));
                }
                id::MAX_UDP_PAYLOAD_SIZE => {
                    p.max_udp_payload_size = int()?;
                    if p.max_udp_payload_size < 1200 {
                        return Err(bad(pid));
                    }
                }
                id::INITIAL_MAX_DATA => p.initial_max_data = int()?,
                id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    p.initial_max_stream_data_bidi_local = int()?;
                }
                id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    p.initial_max_stream_data_bidi_remote = int()?;
                }
                id::INITIAL_MAX_STREAM_DATA_UNI => p.initial_max_stream_data_uni = int()?,
                id::INITIAL_MAX_STREAMS_BIDI | id::INITIAL_MAX_STREAMS_UNI => {
                    let v = int()?;
                    if v > MAX_STREAMS {
                        return Err(bad(pid));
                    }
                    if pid == id::INITIAL_MAX_STREAMS_BIDI {
                        p.initial_max_streams_bidi = v;
                    } else {
                        p.initial_max_streams_uni = v;
                    }
                }
                id::ACK_DELAY_EXPONENT => {
                    let v = int()?;
                    if v > 20 {
                        return Err(bad(pid));
                    }
                    p.ack_delay_exponent = v as u8;
                }
                id::MAX_ACK_DELAY => {
                    let v = int()?;
                    if v >= 1 << 14 {
                        return Err(bad(pid));
                    }
                    p.max_ack_delay = Duration::from_millis(v);
                }
                id::DISABLE_ACTIVE_MIGRATION => {
                    if !value.is_empty() {
                        return Err(bad(pid));
                    }
                    p.disable_active_migration = true;
                }
                id::PREFERRED_ADDRESS => p.preferred_address = Some(preferred(value)?),
                id::ACTIVE_CONNECTION_ID_LIMIT => {
                    p.active_connection_id_limit = int()?;
                    if p.active_connection_id_limit < 2 {
                        return Err(bad(pid));
                    }
                }
                id::INITIAL_SCID => p.initial_source_connection_id = Some(cid(value, pid)?),
                id::RETRY_SCID => p.retry_source_connection_id = Some(cid(value, pid)?),
                // Unknown and GREASE parameters are ignored (section 18.1).
                _ => {}
            }
        }
        if p.initial_source_connection_id.is_none() {
            return Err(bad(id::INITIAL_SCID));
        }
        if sender == Side::Server && p.original_destination_connection_id.is_none() {
            return Err(bad(id::ORIGINAL_DCID));
        }
        Ok(p)
    }

    /// Writes the parameters: each one that differs from its default, and
    /// every connection ID and token that is set.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let d = TransportParameters::default();
        let int = |out: &mut Vec<u8>, pid: u64, v: u64| {
            varint::put(out, pid);
            varint::put(out, varint::size(v) as u64);
            varint::put(out, v);
        };
        let bytes = |out: &mut Vec<u8>, pid: u64, v: &[u8]| {
            varint::put(out, pid);
            varint::put(out, v.len() as u64);
            out.extend_from_slice(v);
        };
        if let Some(c) = &self.original_destination_connection_id {
            bytes(out, id::ORIGINAL_DCID, c.as_slice());
        }
        if self.max_idle_timeout != d.max_idle_timeout {
            int(out, id::MAX_IDLE_TIMEOUT, millis(self.max_idle_timeout));
        }
        if let Some(t) = &self.stateless_reset_token {
            bytes(out, id::STATELESS_RESET_TOKEN, t.as_bytes());
        }
        let ints = [
            (
                id::MAX_UDP_PAYLOAD_SIZE,
                self.max_udp_payload_size,
                d.max_udp_payload_size,
            ),
            (id::INITIAL_MAX_DATA, self.initial_max_data, 0),
            (
                id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                self.initial_max_stream_data_bidi_local,
                0,
            ),
            (
                id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                self.initial_max_stream_data_bidi_remote,
                0,
            ),
            (
                id::INITIAL_MAX_STREAM_DATA_UNI,
                self.initial_max_stream_data_uni,
                0,
            ),
            (
                id::INITIAL_MAX_STREAMS_BIDI,
                self.initial_max_streams_bidi,
                0,
            ),
            (id::INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni, 0),
            (
                id::ACK_DELAY_EXPONENT,
                u64::from(self.ack_delay_exponent),
                u64::from(d.ack_delay_exponent),
            ),
            (
                id::MAX_ACK_DELAY,
                millis(self.max_ack_delay),
                millis(d.max_ack_delay),
            ),
        ];
        for (pid, v, default) in ints {
            if v != default {
                int(out, pid, v.min(MAX_VARINT));
            }
        }
        if self.disable_active_migration {
            bytes(out, id::DISABLE_ACTIVE_MIGRATION, &[]);
        }
        if let Some(a) = &self.preferred_address {
            let mut v = Vec::with_capacity(41 + a.cid.len());
            let v4 = a
                .ipv4
                .unwrap_or(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
            v.extend_from_slice(&v4.ip().octets());
            v.extend_from_slice(&v4.port().to_be_bytes());
            let v6 = a
                .ipv6
                .unwrap_or(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));
            v.extend_from_slice(&v6.ip().octets());
            v.extend_from_slice(&v6.port().to_be_bytes());
            v.push(a.cid.len() as u8);
            v.extend_from_slice(a.cid.as_slice());
            v.extend_from_slice(a.reset_token.as_bytes());
            bytes(out, id::PREFERRED_ADDRESS, &v);
        }
        if self.active_connection_id_limit != d.active_connection_id_limit {
            int(
                out,
                id::ACTIVE_CONNECTION_ID_LIMIT,
                self.active_connection_id_limit.min(MAX_VARINT),
            );
        }
        if let Some(c) = &self.initial_source_connection_id {
            bytes(out, id::INITIAL_SCID, c.as_slice());
        }
        if let Some(c) = &self.retry_source_connection_id {
            bytes(out, id::RETRY_SCID, c.as_slice());
        }
    }
}

fn bad(pid: u64) -> DecodeError {
    DecodeError::BadTransportParameter { id: pid }
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis())
        .unwrap_or(MAX_VARINT)
        .min(MAX_VARINT)
}

/// A varint that fills `value` exactly.
fn integer(value: &[u8]) -> Option<u64> {
    let mut r = Reader::new(value);
    let v = r.varint().ok()?;
    r.is_empty().then_some(v)
}

fn cid(value: &[u8], pid: u64) -> Result<ConnectionId, DecodeError> {
    ConnectionId::new(value).map_err(|_| bad(pid))
}

fn preferred(value: &[u8]) -> Result<PreferredAddress, DecodeError> {
    let e = || bad(id::PREFERRED_ADDRESS);
    let mut r = Reader::new(value);
    let v4: [u8; 4] = r.array().map_err(|_| e())?;
    let p4 = r.u16().map_err(|_| e())?;
    let v6: [u8; 16] = r.array().map_err(|_| e())?;
    let p6 = r.u16().map_err(|_| e())?;
    let len = usize::from(r.u8().map_err(|_| e())?);
    // A zero-length ID is not allowed here (RFC 9000 section 18.2).
    if len == 0 {
        return Err(e());
    }
    let c = ConnectionId::new(r.bytes(len).map_err(|_| e())?).map_err(|_| e())?;
    let token: [u8; 16] = r.array().map_err(|_| e())?;
    if !r.is_empty() {
        return Err(e());
    }
    let ipv4 = (v4 != [0; 4] || p4 != 0).then(|| SocketAddrV4::new(v4.into(), p4));
    let ipv6 = (v6 != [0; 16] || p6 != 0).then(|| SocketAddrV6::new(v6.into(), p6, 0, 0));
    Ok(PreferredAddress {
        ipv4,
        ipv6,
        cid: c,
        reset_token: ResetToken::new(token),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(b: u8) -> ConnectionId {
        ConnectionId::new(&[b; 8]).unwrap()
    }

    fn server_params() -> TransportParameters {
        TransportParameters {
            original_destination_connection_id: Some(c(1)),
            max_idle_timeout: Duration::from_secs(30),
            stateless_reset_token: Some(ResetToken::new([9; 16])),
            max_udp_payload_size: 1452,
            initial_max_data: 10 << 20,
            initial_max_stream_data_bidi_local: 1 << 20,
            initial_max_stream_data_bidi_remote: 1 << 20,
            initial_max_stream_data_uni: 1 << 18,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: MAX_STREAMS,
            ack_delay_exponent: 20,
            max_ack_delay: Duration::from_millis(16_383),
            disable_active_migration: true,
            preferred_address: Some(PreferredAddress {
                ipv4: Some("192.0.2.1:443".parse().unwrap()),
                ipv6: None,
                cid: c(5),
                reset_token: ResetToken::new([5; 16]),
            }),
            active_connection_id_limit: 8,
            initial_source_connection_id: Some(c(2)),
            retry_source_connection_id: Some(c(3)),
        }
    }

    #[test]
    fn round_trip() {
        let p = server_params();
        let mut w = Vec::new();
        p.encode(&mut w);
        assert_eq!(TransportParameters::decode(&w, Side::Server), Ok(p.clone()));
        // Every truncation fails cleanly (or reads fewer parameters).
        for cut in 0..w.len() {
            let _ = TransportParameters::decode(&w[..cut], Side::Server);
        }
        // A client must not send the server's parameters.
        assert_eq!(
            TransportParameters::decode(&w, Side::Client),
            Err(DecodeError::BadTransportParameter { id: 0 })
        );
    }

    fn with(extra: &[u8]) -> Vec<u8> {
        let p = TransportParameters {
            initial_source_connection_id: Some(c(1)),
            ..TransportParameters::default()
        };
        let mut w = Vec::new();
        p.encode(&mut w);
        w.extend_from_slice(extra);
        w
    }

    #[test]
    fn rules() {
        let err = |b: &[u8]| TransportParameters::decode(&with(b), Side::Client).err();
        // A repeat.
        assert_eq!(err(&[0x04, 1, 5, 0x04, 1, 6]), Some(bad(4)));
        // An integer that does not fill its length.
        assert_eq!(err(&[0x04, 2, 5, 0]), Some(bad(4)));
        // Out of range.
        assert_eq!(err(&[0x03, 2, 0x44, 0xAF]), Some(bad(3)), "1199 bytes");
        assert_eq!(err(&[0x0a, 1, 21]), Some(bad(0x0a)));
        assert_eq!(err(&[0x0b, 2, 0x7F, 0xFF]), None, "16,383 ms is allowed");
        assert_eq!(err(&[0x0b, 4, 0x80, 0, 0x40, 0]), Some(bad(0x0b)));
        assert_eq!(err(&[0x0e, 1, 1]), Some(bad(0x0e)));
        assert_eq!(err(&[0x0c, 1, 0]), Some(bad(0x0c)));
        let mut over = vec![0x08, 8];
        varint::put(&mut over, MAX_STREAMS + 1);
        assert_eq!(err(&over), Some(bad(8)));
        // GREASE is ignored; too many of anything is not.
        assert_eq!(err(&[0x40, 0x1b, 0]), None);
        let mut flood = Vec::new();
        for _ in 0..MAX_PARAMETERS {
            flood.extend_from_slice(&[0x40, 0x1b, 0]);
        }
        assert!(err(&flood).is_some());
        // Required IDs.
        assert_eq!(
            TransportParameters::decode(&[], Side::Client),
            Err(bad(0x0f))
        );
        assert_eq!(
            TransportParameters::decode(&with(&[]), Side::Server),
            Err(bad(0x00))
        );
    }

    #[test]
    fn preferred_address_rules() {
        let mut v = vec![0x0d, 41];
        v.extend_from_slice(&[0; 4 + 2 + 16 + 2]);
        v.push(0); // a zero-length ID
        v.extend_from_slice(&[0; 16]);
        let mut p = server_params();
        p.preferred_address = None;
        let mut w = Vec::new();
        p.encode(&mut w);
        w.extend_from_slice(&v);
        assert_eq!(
            TransportParameters::decode(&w, Side::Server),
            Err(bad(0x0d))
        );
    }
}
