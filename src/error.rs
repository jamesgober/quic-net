//! What the decoders refuse, and the transport error codes (RFC 9000 section
//! 20) a connection closes with for each.

use std::fmt;

/// A transport error code (RFC 9000 section 20.1), carried in a
/// CONNECTION_CLOSE frame of type 0x1c.
///
/// ```
/// use quic_net::TransportErrorCode;
/// assert_eq!(TransportErrorCode::FRAME_ENCODING_ERROR.to_string(), "FRAME_ENCODING_ERROR");
/// assert_eq!(TransportErrorCode::crypto(80).to_string(), "CRYPTO_ERROR(80)");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransportErrorCode(pub u64);

impl TransportErrorCode {
    /// No error: an orderly close.
    pub const NO_ERROR: TransportErrorCode = TransportErrorCode(0x0);
    /// The endpoint failed in a way it does not otherwise describe.
    pub const INTERNAL_ERROR: TransportErrorCode = TransportErrorCode(0x1);
    /// The server refused the connection.
    pub const CONNECTION_REFUSED: TransportErrorCode = TransportErrorCode(0x2);
    /// More data than the advertised limits.
    pub const FLOW_CONTROL_ERROR: TransportErrorCode = TransportErrorCode(0x3);
    /// A stream past the advertised stream limit.
    pub const STREAM_LIMIT_ERROR: TransportErrorCode = TransportErrorCode(0x4);
    /// A frame for a stream in a state that does not allow it.
    pub const STREAM_STATE_ERROR: TransportErrorCode = TransportErrorCode(0x5);
    /// A final size that changed or was exceeded.
    pub const FINAL_SIZE_ERROR: TransportErrorCode = TransportErrorCode(0x6);
    /// A frame that is badly formatted.
    pub const FRAME_ENCODING_ERROR: TransportErrorCode = TransportErrorCode(0x7);
    /// Transport parameters that are badly formatted or invalid.
    pub const TRANSPORT_PARAMETER_ERROR: TransportErrorCode = TransportErrorCode(0x8);
    /// More connection IDs than `active_connection_id_limit`.
    pub const CONNECTION_ID_LIMIT_ERROR: TransportErrorCode = TransportErrorCode(0x9);
    /// A violation of the protocol not covered by another code.
    pub const PROTOCOL_VIOLATION: TransportErrorCode = TransportErrorCode(0xa);
    /// A token in an Initial packet that the server refuses.
    pub const INVALID_TOKEN: TransportErrorCode = TransportErrorCode(0xb);
    /// The application closed with a CONNECTION_CLOSE of the transport type.
    pub const APPLICATION_ERROR: TransportErrorCode = TransportErrorCode(0xc);
    /// More CRYPTO data than the endpoint can buffer.
    pub const CRYPTO_BUFFER_EXCEEDED: TransportErrorCode = TransportErrorCode(0xd);
    /// A key update that broke the rules.
    pub const KEY_UPDATE_ERROR: TransportErrorCode = TransportErrorCode(0xe);
    /// Too many packets protected with one key.
    pub const AEAD_LIMIT_REACHED: TransportErrorCode = TransportErrorCode(0xf);
    /// No network path can carry the connection.
    pub const NO_VIABLE_PATH: TransportErrorCode = TransportErrorCode(0x10);

    /// A TLS alert, as 0x100 plus its code (RFC 9001 section 4.8).
    #[must_use]
    pub fn crypto(alert: u8) -> TransportErrorCode {
        TransportErrorCode(0x100 + u64::from(alert))
    }

    const NAMES: [&'static str; 17] = [
        "NO_ERROR",
        "INTERNAL_ERROR",
        "CONNECTION_REFUSED",
        "FLOW_CONTROL_ERROR",
        "STREAM_LIMIT_ERROR",
        "STREAM_STATE_ERROR",
        "FINAL_SIZE_ERROR",
        "FRAME_ENCODING_ERROR",
        "TRANSPORT_PARAMETER_ERROR",
        "CONNECTION_ID_LIMIT_ERROR",
        "PROTOCOL_VIOLATION",
        "INVALID_TOKEN",
        "APPLICATION_ERROR",
        "CRYPTO_BUFFER_EXCEEDED",
        "KEY_UPDATE_ERROR",
        "AEAD_LIMIT_REACHED",
        "NO_VIABLE_PATH",
    ];
}

impl fmt::Display for TransportErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            n if (n as usize) < TransportErrorCode::NAMES.len() => {
                f.write_str(TransportErrorCode::NAMES[n as usize])
            }
            n @ 0x100..=0x1ff => write!(f, "CRYPTO_ERROR({})", n - 0x100),
            n => write!(f, "0x{n:x}"),
        }
    }
}

/// Why bytes were refused, and which transport error closes the connection
/// for it.
///
/// ```
/// use quic_net::{DecodeError, TransportErrorCode};
/// assert_eq!(DecodeError::Short.code(), TransportErrorCode::FRAME_ENCODING_ERROR);
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ends inside a field.
    Short,
    /// A value over its field's limit: an integer over 2^62 - 1, a stream
    /// count over 2^60, an offset and length past 2^62 - 1.
    TooLarge,
    /// A frame type no version 1 endpoint sends, or one not encoded on the
    /// fewest bytes (RFC 9000 section 12.4).
    UnknownFrame {
        /// The type.
        frame_type: u64,
    },
    /// A frame whose fields contradict each other or the specification.
    BadFrame {
        /// The type.
        frame_type: u64,
    },
    /// More of something than the budget allows: ACK ranges, coalesced
    /// packets, transport parameters.
    OverBudget,
    /// A connection ID over 20 bytes in a version 1 packet or frame.
    ConnectionIdTooLong,
    /// A packet header that is malformed: the fixed bit clear, a length past
    /// the datagram, a reserved field set where it must not be.
    BadPacket,
    /// Transport parameters that are malformed, repeated, out of range, or
    /// sent by the side that must not send them.
    BadTransportParameter {
        /// The parameter's id.
        id: u64,
    },
    /// A frame in a packet type that must not carry it (RFC 9000 section
    /// 12.4, table 3).
    WrongPacketType {
        /// The frame's type.
        frame_type: u64,
    },
}

impl DecodeError {
    /// The transport error a connection closes with for it.
    #[must_use]
    pub fn code(&self) -> TransportErrorCode {
        match self {
            DecodeError::Short
            | DecodeError::TooLarge
            | DecodeError::UnknownFrame { .. }
            | DecodeError::BadFrame { .. }
            | DecodeError::ConnectionIdTooLong => TransportErrorCode::FRAME_ENCODING_ERROR,
            DecodeError::BadTransportParameter { .. } => {
                TransportErrorCode::TRANSPORT_PARAMETER_ERROR
            }
            DecodeError::OverBudget
            | DecodeError::BadPacket
            | DecodeError::WrongPacketType { .. } => TransportErrorCode::PROTOCOL_VIOLATION,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Short => f.write_str("the input ends inside a field"),
            DecodeError::TooLarge => f.write_str("a value is over its limit"),
            DecodeError::UnknownFrame { frame_type } => {
                write!(
                    f,
                    "frame type 0x{frame_type:x} is unknown or not minimally encoded"
                )
            }
            DecodeError::BadFrame { frame_type } => {
                write!(f, "a frame of type 0x{frame_type:x} is malformed")
            }
            DecodeError::OverBudget => f.write_str("more items than the budget allows"),
            DecodeError::ConnectionIdTooLong => {
                f.write_str("a connection ID is longer than 20 bytes")
            }
            DecodeError::BadPacket => f.write_str("the packet header is malformed"),
            DecodeError::BadTransportParameter { id } => {
                write!(f, "transport parameter 0x{id:x} is invalid")
            }
            DecodeError::WrongPacketType { frame_type } => {
                write!(
                    f,
                    "frame type 0x{frame_type:x} is not allowed in this packet type"
                )
            }
        }
    }
}

impl std::error::Error for DecodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_codes() {
        assert_eq!(TransportErrorCode(0x10).to_string(), "NO_VIABLE_PATH");
        assert_eq!(TransportErrorCode(0x11).to_string(), "0x11");
        assert_eq!(TransportErrorCode(0x1ff).to_string(), "CRYPTO_ERROR(255)");
        assert_eq!(
            DecodeError::BadTransportParameter { id: 3 }.code(),
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR
        );
        assert_eq!(
            DecodeError::WrongPacketType { frame_type: 6 }.code(),
            TransportErrorCode::PROTOCOL_VIOLATION
        );
    }
}
