//! A QUIC connection, sans-IO (RFC 9000, RFC 9001, and the loss detection of
//! RFC 9002): the handshake through tls-net, packet number spaces, ACKs,
//! retransmission on loss and on the probe timeout, streams with flow
//! control, and closing.
//!
//! The caller owns the socket and the clock. It passes every datagram that
//! arrives to [`Connection::handle_datagram`], sends what
//! [`Connection::poll_transmit`] produces, calls
//! [`Connection::handle_timeout`] at [`Connection::poll_timeout`], and reads
//! [`Connection::poll_event`].
//!
//! Congestion control is NewReno with pacing (RFC 9002 section 7).
//!
//! Not in this version (PLAN section 3e): 0-RTT, connection migration,
//! issuing more connection IDs, and initiating key updates (the peer's are
//! followed).

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::{Duration, Instant};

use tls_net::quic::{DirectionalKeys, KeyChange, PacketKeySet, QuicSession, Secrets};
use tls_net::{TlsClient, TlsServer};

use crate::address::Amplification;
use crate::cc::{CongestionState, NewReno, Pacer};
use crate::cid::{ConnectionId, PeerCids, ResetKey, ResetToken, is_stateless_reset};
use crate::error::TransportErrorCode;
use crate::flow::{RecvCredit, SendCredit};
use crate::frame::{Ack, Frame, PacketKind, frames};
use crate::packet::{
    Header, LongHeader, LongType, MIN_INITIAL_SIZE, coalesced, packet_number_len, write_short,
};
use crate::params::{Side, TransportParameters};
use crate::protect::{
    AeadUsage, TAG_LEN, open_payload, remove_header_protection, seal_packet, verify_retry,
};
use crate::ranges::RangeSet;
use crate::recv::{CryptoRecv, RecvStream};
use crate::send::{Chunk, SendStream};
use crate::stream::{LocalStreams, RemoteStreams, StreamId};
use crate::tls::TlsRetry;

/// RFC 9002 section 6.1.1.
const PACKET_THRESHOLD: u64 = 3;
/// RFC 9002 section 6.2.2: before any RTT sample.
const INITIAL_RTT: Duration = Duration::from_millis(333);
/// RFC 9002 section 6.1.2.
const GRANULARITY: Duration = Duration::from_millis(1);
/// Received packet number ranges kept for ACK frames.
const ACK_RANGES_KEPT: usize = 32;
/// The ACK delay exponent this endpoint uses (the default).
const ACK_DELAY_EXPONENT: u8 = 3;
/// CRYPTO data held per level for retransmission: the largest handshake
/// flight tls-net writes (certificate chains included) fits.
const CRYPTO_BUFFER: usize = 128 * 1024;
/// Room for a long header with 20-byte connection IDs, a token length, a
/// length, and a 4-byte packet number.
const LONG_HEADER_MAX: usize = 1 + 4 + 1 + 20 + 1 + 20 + 2 + 4 + 4;

/// The transport settings of a connection.
#[derive(Clone, Debug)]
pub struct Config {
    /// The transport parameters to send. The connection IDs, the original
    /// destination ID, and the stateless reset token are filled in by the
    /// connection.
    pub params: TransportParameters,
    /// The largest UDP payload this endpoint sends (at least 1,200).
    pub max_datagram: usize,
    /// Bytes buffered per stream until acknowledged.
    pub send_buffer: usize,
    /// The key for the stateless reset token sent with the server's
    /// connection ID.
    pub reset_key: Option<std::sync::Arc<ResetKey>>,
    /// Whether to pace packets over the round trip (RFC 9002 section 7.7).
    /// On by default; off sends each window as fast as the socket takes it.
    pub pacing: bool,
}

impl Default for Config {
    /// 10 MiB of connection credit, 1 MiB per stream, 100 streams of each
    /// type, a 30-second idle timeout.
    fn default() -> Config {
        let params = TransportParameters {
            max_idle_timeout: Duration::from_secs(30),
            initial_max_data: 10 << 20,
            initial_max_stream_data_bidi_local: 1 << 20,
            initial_max_stream_data_bidi_remote: 1 << 20,
            initial_max_stream_data_uni: 1 << 20,
            initial_max_streams_bidi: 100,
            initial_max_streams_uni: 100,
            ..TransportParameters::default()
        };
        Config {
            params,
            max_datagram: MIN_INITIAL_SIZE,
            send_buffer: 1 << 20,
            reset_key: None,
            pacing: true,
        }
    }
}

/// Why a connection could not be created.
#[derive(Debug)]
pub enum ConnectError {
    /// tls-net refused to start the handshake.
    Tls(tls_net::TlsError),
    /// The Initial keys could not be derived.
    Keys,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectError::Tls(e) => write!(f, "the TLS handshake could not start: {e}"),
            ConnectError::Keys => f.write_str("the Initial keys could not be derived"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// How a connection ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Close {
    /// The error code: a transport error, or the application's.
    pub code: u64,
    /// Whether `code` is the application's.
    pub application: bool,
    /// The reason phrase.
    pub reason: Vec<u8>,
    /// Whether the peer closed it (or reset it statelessly); `false` when
    /// this endpoint did, or the idle timeout did.
    pub remote: bool,
}

/// What happened on a connection.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// The handshake finished: streams can be used.
    Connected,
    /// The peer opened a stream.
    StreamOpened(StreamId),
    /// Data arrived on a stream, or its end.
    StreamReadable(StreamId),
    /// The peer reset a stream.
    StreamReset {
        /// The stream.
        id: StreamId,
        /// The peer's error code.
        code: u64,
    },
    /// The peer asked this endpoint to stop sending on a stream; the stream
    /// was reset with its code.
    StreamStopped {
        /// The stream.
        id: StreamId,
        /// The peer's error code.
        code: u64,
    },
    /// The server sent a token for the next connection (`NEW_TOKEN`).
    NewToken(Vec<u8>),
    /// The connection ended.
    Closed(Close),
}

/// What an operation on a stream ran into.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// No such stream, or not in this direction.
    Unknown,
    /// The stream was reset.
    Reset(u64),
    /// The connection is not established, or closed.
    NotConnected,
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamError::Unknown => f.write_str("no such stream"),
            StreamError::Reset(c) => write!(f, "the stream was reset with {c}"),
            StreamError::NotConnected => f.write_str("the connection is not established"),
        }
    }
}

impl std::error::Error for StreamError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Initial = 0,
    Handshake = 1,
    Data = 2,
}

const LEVELS: [Level; 3] = [Level::Initial, Level::Handshake, Level::Data];

/// What a sent packet carried that matters when it is acknowledged or lost.
#[derive(Clone, Debug)]
enum Sent {
    Crypto(Chunk),
    Stream(StreamId, Chunk),
    HandshakeDone,
    MaxData,
    MaxStreamData(StreamId),
    MaxStreams(bool),
    ResetStream(StreamId),
    StopSending(StreamId, u64),
}

#[derive(Clone, Debug)]
struct SentPacket {
    time: Instant,
    ack_eliciting: bool,
    /// Ack-eliciting or padded: counted against the congestion window.
    in_flight: bool,
    size: usize,
    frames: Vec<Sent>,
}

struct Space {
    local: Option<DirectionalKeys>,
    remote: Option<DirectionalKeys>,
    next_pn: u64,
    largest_acked: Option<u64>,
    received: RangeSet,
    largest_received_at: Option<Instant>,
    /// Ack-eliciting packets received since the last ACK sent.
    unacked: u32,
    crypto_send: SendStream,
    crypto_recv: CryptoRecv,
    sent: BTreeMap<u64, SentPacket>,
    loss_time: Option<Instant>,
    last_ack_eliciting: Option<Instant>,
    probe: bool,
    discarded: bool,
}

impl Space {
    fn new() -> Space {
        Space {
            local: None,
            remote: None,
            next_pn: 0,
            largest_acked: None,
            received: RangeSet::new(),
            largest_received_at: None,
            unacked: 0,
            crypto_send: SendStream::new(u64::MAX >> 2, CRYPTO_BUFFER),
            crypto_recv: CryptoRecv::new(),
            sent: BTreeMap::new(),
            loss_time: None,
            last_ack_eliciting: None,
            probe: false,
            discarded: false,
        }
    }

    fn ack_eliciting_in_flight(&self) -> bool {
        self.sent.values().any(|p| p.ack_eliciting)
    }
}

#[derive(Default)]
struct StreamState {
    send: Option<SendStream>,
    recv: Option<RecvStream>,
}

/// The 1-RTT key phase state.
struct Phase {
    bit: bool,
    secrets: Secrets,
    next: Option<PacketKeySet>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Handshake,
    Established,
    /// This endpoint sent `CONNECTION_CLOSE` and waits out the drain.
    Closing,
    /// The peer closed; nothing more is sent.
    Draining,
    Closed,
}

struct Rtt {
    latest: Duration,
    smoothed: Duration,
    var: Duration,
    min: Duration,
    sampled: bool,
}

impl Rtt {
    fn new() -> Rtt {
        Rtt {
            latest: Duration::ZERO,
            smoothed: INITIAL_RTT,
            var: INITIAL_RTT / 2,
            min: Duration::ZERO,
            sampled: false,
        }
    }

    /// RFC 9002 section 5.3.
    fn update(&mut self, latest: Duration, ack_delay: Duration) {
        self.latest = latest;
        if !self.sampled {
            self.sampled = true;
            self.min = latest;
            self.smoothed = latest;
            self.var = latest / 2;
            return;
        }
        self.min = self.min.min(latest);
        let adjusted = if latest >= self.min + ack_delay {
            latest - ack_delay
        } else {
            latest
        };
        let diff = self.smoothed.abs_diff(adjusted);
        self.var = (self.var * 3 + diff) / 4;
        self.smoothed = (self.smoothed * 7 + adjusted) / 8;
    }

    fn pto(&self) -> Duration {
        self.smoothed + (self.var * 4).max(GRANULARITY)
    }

    fn loss_delay(&self) -> Duration {
        (self.smoothed.max(self.latest) * 9 / 8).max(GRANULARITY)
    }
}

/// A QUIC connection, client or server, sans-IO.
pub struct Connection {
    side: Side,
    state: State,
    tls: QuicSession,
    config: Config,
    spaces: [Space; 3],
    write_level: Level,
    phase: Option<Phase>,
    usage: Option<AeadUsage>,
    /// Our source connection ID.
    local_cid: ConnectionId,
    /// The destination ID we send to.
    remote_cid: ConnectionId,
    /// The destination ID of the client's first Initial.
    original_dcid: ConnectionId,
    /// The source ID of the Retry, when there was one.
    retry_scid: Option<ConnectionId>,
    /// The token the client sends in its Initial packets.
    token: Vec<u8>,
    /// The client heard from the server (a Retry is then refused).
    heard: bool,
    peer_params: Option<TransportParameters>,
    peer_cids: Option<PeerCids>,
    peer_reset: Option<ResetToken>,
    amplification: Amplification,
    rtt: Rtt,
    cc: NewReno,
    pacer: Pacer,
    /// When pacing next lets a packet in flight go.
    next_send: Option<Instant>,
    pto_count: u32,
    idle_timeout: Duration,
    last_activity: Instant,
    close_at: Option<Instant>,
    close: Option<Close>,
    close_pending: bool,
    handshake_done_pending: bool,
    confirmed: bool,
    /// The server acknowledged a Handshake packet of the client: its
    /// address is proved, and the client's anti-deadlock probes stop.
    handshake_acked: bool,
    connected_sent: bool,
    events: VecDeque<Event>,
    // Streams.
    streams: BTreeMap<StreamId, StreamState>,
    local_bidi: LocalStreams,
    local_uni: LocalStreams,
    remote_bidi: RemoteStreams,
    remote_uni: RemoteStreams,
    conn_recv: RecvCredit,
    conn_send: SendCredit,
    max_data_pending: bool,
    max_stream_data_pending: BTreeSet<StreamId>,
    max_streams_pending: [bool; 2],
    resets_pending: BTreeMap<StreamId, (u64, u64)>,
    stops_pending: BTreeMap<StreamId, u64>,
    path_responses: Vec<[u8; 8]>,
    /// Round robin over streams with data to send.
    next_stream: Option<StreamId>,
    /// The datagram being built may carry ACKs only.
    ack_only: bool,
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("side", &self.side)
            .field("state", &self.state)
            .field("local_cid", &self.local_cid)
            .field("remote_cid", &self.remote_cid)
            .finish_non_exhaustive()
    }
}

fn install(space: &mut Space, keys: tls_net::quic::Keys) {
    space.local = Some(keys.local);
    space.remote = Some(keys.remote);
}

fn initial_keys(dcid: &ConnectionId, side: Side) -> Result<tls_net::quic::Keys, ConnectError> {
    let side = match side {
        Side::Client => tls_net::quic::Side::Client,
        Side::Server => tls_net::quic::Side::Server,
    };
    tls_net::quic::initial_keys(dcid.as_slice(), side).map_err(|_| ConnectError::Keys)
}

impl Connection {
    /// A client connection to `server_name`, sending its first Initial to
    /// `initial_dcid` (at least 8 random bytes) from `local_cid`. Call
    /// [`poll_transmit`](Self::poll_transmit) to get the first datagram.
    ///
    /// # Errors
    ///
    /// [`ConnectError`] when tls-net refuses to start (no ALPN configured,
    /// for one) or the keys cannot be derived.
    pub fn client(
        tls: &TlsClient,
        server_name: &str,
        config: Config,
        local_cid: ConnectionId,
        initial_dcid: ConnectionId,
        now: Instant,
    ) -> Result<Connection, ConnectError> {
        let mut params = config.params.clone();
        params.initial_source_connection_id = Some(local_cid);
        params.original_destination_connection_id = None;
        params.retry_source_connection_id = None;
        params.stateless_reset_token = None;
        let mut bytes = Vec::new();
        params.encode(&mut bytes);
        let session = tls
            .connect_quic(server_name, bytes)
            .map_err(ConnectError::Tls)?;
        let mut c = Connection::new(
            Side::Client,
            session,
            config,
            local_cid,
            initial_dcid,
            initial_dcid,
            now,
        );
        install(&mut c.spaces[0], initial_keys(&initial_dcid, Side::Client)?);
        c.amplification = Amplification::validated();
        c.pump_tls();
        Ok(c)
    }

    /// A client connection that sends `token` (from a `NEW_TOKEN` frame of
    /// an earlier connection) in its Initial packets, so the server can
    /// skip address validation.
    ///
    /// # Errors
    ///
    /// As [`client`](Self::client).
    pub fn client_with_token(
        tls: &TlsClient,
        server_name: &str,
        config: Config,
        local_cid: ConnectionId,
        initial_dcid: ConnectionId,
        token: Vec<u8>,
        now: Instant,
    ) -> Result<Connection, ConnectError> {
        let mut c = Connection::client(tls, server_name, config, local_cid, initial_dcid, now)?;
        c.token = token;
        Ok(c)
    }

    /// A server connection for a client's first Initial, before the
    /// datagram is passed to [`handle_datagram`](Self::handle_datagram).
    ///
    /// - `client_dcid` is the destination ID of the Initial, `client_scid`
    ///   its source ID, `local_cid` the ID this server chooses.
    /// - After a Retry, `retry` holds what the token said:
    ///   `(original_dcid, retry_scid)`; the client's Initial is then sent to
    ///   `retry_scid`.
    /// - `validated`: whether a token proved the client's address; until it
    ///   is proved, the server sends at most three times what it receives.
    ///
    /// # Errors
    ///
    /// [`ConnectError`] when tls-net refuses (a capacity limit, for one).
    #[allow(clippy::too_many_arguments)]
    pub fn server(
        tls: &TlsServer,
        config: Config,
        local_cid: ConnectionId,
        client_dcid: ConnectionId,
        client_scid: ConnectionId,
        retry: Option<(ConnectionId, ConnectionId)>,
        validated: bool,
        now: Instant,
    ) -> Result<Connection, ConnectError> {
        let (original_dcid, retry_scid) = match retry {
            Some((o, r)) => (o, Some(r)),
            None => (client_dcid, None),
        };
        let mut params = config.params.clone();
        params.initial_source_connection_id = Some(local_cid);
        params.original_destination_connection_id = Some(original_dcid);
        params.retry_source_connection_id = retry_scid;
        params.stateless_reset_token = config.reset_key.as_ref().map(|k| k.token(&local_cid));
        let mut bytes = Vec::new();
        params.encode(&mut bytes);
        let session = tls.accept_quic(bytes).map_err(ConnectError::Tls)?;
        let mut c = Connection::new(
            Side::Server,
            session,
            config,
            local_cid,
            client_scid,
            original_dcid,
            now,
        );
        c.retry_scid = retry_scid;
        install(&mut c.spaces[0], initial_keys(&client_dcid, Side::Server)?);
        if validated {
            c.amplification.validate();
        }
        Ok(c)
    }

    fn new(
        side: Side,
        tls: QuicSession,
        config: Config,
        local_cid: ConnectionId,
        remote_cid: ConnectionId,
        original_dcid: ConnectionId,
        now: Instant,
    ) -> Connection {
        let p = &config.params;
        let (remote_bidi, remote_uni) = (
            RemoteStreams::new(p.initial_max_streams_bidi),
            RemoteStreams::new(p.initial_max_streams_uni),
        );
        let conn_recv = RecvCredit::new(p.initial_max_data);
        let idle_timeout = p.max_idle_timeout;
        Connection {
            side,
            state: State::Handshake,
            tls,
            spaces: [Space::new(), Space::new(), Space::new()],
            write_level: Level::Initial,
            phase: None,
            usage: None,
            local_cid,
            remote_cid,
            original_dcid,
            retry_scid: None,
            token: Vec::new(),
            heard: false,
            peer_params: None,
            peer_cids: None,
            peer_reset: None,
            amplification: Amplification::new(),
            rtt: Rtt::new(),
            cc: NewReno::new(MIN_INITIAL_SIZE),
            pacer: Pacer::new(),
            next_send: None,
            pto_count: 0,
            idle_timeout,
            last_activity: now,
            close_at: None,
            close: None,
            close_pending: false,
            handshake_done_pending: false,
            confirmed: false,
            handshake_acked: false,
            connected_sent: false,
            events: VecDeque::new(),
            streams: BTreeMap::new(),
            local_bidi: LocalStreams::new(0),
            local_uni: LocalStreams::new(0),
            remote_bidi,
            remote_uni,
            conn_recv,
            conn_send: SendCredit::new(0),
            max_data_pending: false,
            max_stream_data_pending: BTreeSet::new(),
            max_streams_pending: [false; 2],
            resets_pending: BTreeMap::new(),
            stops_pending: BTreeMap::new(),
            path_responses: Vec::new(),
            next_stream: None,
            ack_only: false,
            config,
        }
    }

    /// Which end this is.
    #[must_use]
    pub fn side(&self) -> Side {
        self.side
    }

    /// Whether the handshake finished and the connection is open.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.state == State::Established
    }

    /// Whether the connection has ended and holds no more state worth
    /// keeping.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// This endpoint's connection ID: where the peer sends.
    #[must_use]
    pub fn local_cid(&self) -> ConnectionId {
        self.local_cid
    }

    /// The agreed application protocol.
    #[must_use]
    pub fn alpn(&self) -> Option<&[u8]> {
        self.tls.alpn()
    }

    /// The peer's transport parameters, once they arrived.
    #[must_use]
    pub fn peer_params(&self) -> Option<&TransportParameters> {
        self.peer_params.as_ref()
    }

    /// The smoothed round-trip time.
    #[must_use]
    pub fn rtt(&self) -> Duration {
        self.rtt.smoothed
    }

    /// The congestion window, in bytes.
    #[must_use]
    pub fn congestion_window(&self) -> u64 {
        self.cc.window()
    }

    /// Bytes in flight: sent, ack-eliciting or padded, and neither
    /// acknowledged nor lost.
    #[must_use]
    pub fn bytes_in_flight(&self) -> u64 {
        self.cc.in_flight()
    }

    /// Where the congestion controller stands.
    #[must_use]
    pub fn congestion_state(&self) -> CongestionState {
        self.cc.state()
    }

    /// The next event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    // ---- The handshake --------------------------------------------------

    /// Moves CRYPTO data from TLS to the send buffers, and installs keys.
    fn pump_tls(&mut self) {
        loop {
            let mut out = Vec::new();
            let change = self.tls.write_handshake(&mut out);
            if !out.is_empty() {
                let level = self.write_level as usize;
                let n = self.spaces[level].crypto_send.write(&out);
                if n < out.len() {
                    self.close_error(
                        TransportErrorCode::CRYPTO_BUFFER_EXCEEDED,
                        b"handshake data",
                    );
                    return;
                }
            }
            match change {
                None => {
                    if out.is_empty() {
                        break;
                    }
                }
                Some(KeyChange::Handshake { keys }) => {
                    install(&mut self.spaces[1], keys);
                    self.write_level = Level::Handshake;
                }
                Some(KeyChange::OneRtt { keys, next }) => {
                    let limits = crate::protect::PacketKey::limits(&keys.local.packet);
                    install(&mut self.spaces[2], keys);
                    self.write_level = Level::Data;
                    self.phase = Some(Phase {
                        bit: false,
                        secrets: next,
                        next: None,
                    });
                    self.usage = Some(AeadUsage::new(limits));
                }
            }
        }
        // A resuming client gets the previous session's parameters from
        // rustls before the handshake (for 0-RTT); it takes the peer's only
        // once the handshake is complete and the new ones were read.
        let ready = self.side == Side::Server || !self.tls.is_handshaking();
        if self.peer_params.is_none() && ready {
            if let Some(bytes) = self.tls.peer_transport_parameters().map(<[u8]>::to_vec) {
                if let Err(code) = self.apply_peer_params(&bytes) {
                    self.close_error(code, b"transport parameters");
                    return;
                }
            }
        }
        if self.state == State::Handshake
            && !self.tls.is_handshaking()
            && self.peer_params.is_some()
        {
            self.state = State::Established;
            if !self.connected_sent {
                self.connected_sent = true;
                self.events.push_back(Event::Connected);
            }
            if self.side == Side::Server {
                // The server's handshake is confirmed when it completes
                // (RFC 9001 section 4.1.2).
                self.handshake_done_pending = true;
                self.confirm();
            }
        }
    }

    /// The handshake is confirmed: Handshake keys go (RFC 9001 section 4.9.2).
    fn confirm(&mut self) {
        if self.confirmed {
            return;
        }
        self.confirmed = true;
        self.discard(Level::Handshake);
    }

    fn discard(&mut self, level: Level) {
        let s = &mut self.spaces[level as usize];
        if s.discarded {
            return;
        }
        s.discarded = true;
        s.local = None;
        s.remote = None;
        for p in core::mem::take(&mut s.sent).into_values() {
            if p.in_flight {
                self.cc.on_discarded(p.size);
            }
        }
        let s = &mut self.spaces[level as usize];
        s.loss_time = None;
        s.probe = false;
        s.unacked = 0;
        self.pto_count = 0;
    }

    fn apply_peer_params(&mut self, bytes: &[u8]) -> Result<(), TransportErrorCode> {
        let peer_side = match self.side {
            Side::Client => Side::Server,
            Side::Server => Side::Client,
        };
        let p = TransportParameters::decode(bytes, peer_side).map_err(|e| e.code())?;
        // RFC 9000 section 7.3: the connection IDs must match what was seen
        // on the wire.
        if p.initial_source_connection_id != Some(self.remote_cid) {
            return Err(TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
        }
        if self.side == Side::Client {
            if p.original_destination_connection_id != Some(self.original_dcid)
                || p.retry_source_connection_id != self.retry_scid
            {
                return Err(TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
            }
            self.peer_reset = p.stateless_reset_token;
        }
        let ours = &self.config.params;
        // The idle timeout is the smaller of the two that are set.
        let theirs = p.max_idle_timeout;
        self.idle_timeout = match (ours.max_idle_timeout.is_zero(), theirs.is_zero()) {
            (true, true) => Duration::ZERO,
            (true, false) => theirs,
            (false, true) => ours.max_idle_timeout,
            (false, false) => ours.max_idle_timeout.min(theirs),
        };
        self.conn_send = SendCredit::new(p.initial_max_data);
        self.local_bidi = LocalStreams::new(p.initial_max_streams_bidi);
        self.local_uni = LocalStreams::new(p.initial_max_streams_uni);
        self.peer_cids = Some(PeerCids::new(
            self.remote_cid,
            ours.active_connection_id_limit.max(2),
        ));
        self.peer_params = Some(p);
        Ok(())
    }

    // ---- Receiving --------------------------------------------------------

    /// A datagram from the peer, decrypted in place.
    pub fn handle_datagram(&mut self, now: Instant, data: &mut [u8]) {
        match self.state {
            State::Closed | State::Draining => return,
            State::Closing => {
                // Answer with the close again, at most once per datagram.
                self.close_pending = true;
                return;
            }
            _ => {}
        }
        self.amplification.on_received(data.len());
        let spans: Vec<(usize, usize, usize, Owned)> = coalesced(data, self.local_cid.len())
            .filter_map(Result::ok)
            .map(|p| {
                let start = p.bytes.as_ptr() as usize - data.as_ptr() as usize;
                (
                    start,
                    start + p.bytes.len(),
                    p.pn_offset,
                    Owned::from(&p.header),
                )
            })
            .collect();
        if spans.is_empty() {
            self.check_reset(data);
            return;
        }
        for (start, end, pn_offset, header) in spans {
            let packet = &mut data[start..end];
            match self.handle_packet(now, packet, pn_offset, header) {
                Ok(()) => {}
                Err(code) => {
                    self.close_error(code, b"");
                    return;
                }
            }
            if matches!(self.state, State::Closed | State::Draining | State::Closing) {
                return;
            }
        }
    }

    fn check_reset(&mut self, data: &[u8]) {
        if let Some(t) = &self.peer_reset {
            if is_stateless_reset(data, core::iter::once(t)) {
                self.enter_closed(Close {
                    code: 0,
                    application: false,
                    reason: b"stateless reset".to_vec(),
                    remote: true,
                });
            }
        }
    }

    fn handle_packet(
        &mut self,
        now: Instant,
        packet: &mut [u8],
        pn_offset: usize,
        header: Owned,
    ) -> Result<(), TransportErrorCode> {
        let (level, kind) = match header {
            Owned::VersionNegotiation(versions) => {
                // RFC 9000 section 6.2: ignored once anything else arrived, or
                // when it lists our version.
                if self.side == Side::Client
                    && !self.heard
                    && !versions.contains(&crate::packet::VERSION_1)
                {
                    self.enter_closed(Close {
                        code: 0,
                        application: false,
                        reason: b"no compatible version".to_vec(),
                        remote: true,
                    });
                }
                return Ok(());
            }
            Owned::Retry { scid, token } => {
                self.handle_retry(packet, scid, token);
                return Ok(());
            }
            Owned::Initial { scid } => {
                if self.side == Side::Client && !self.heard {
                    // The server's chosen ID becomes our destination.
                    self.remote_cid = scid;
                }
                (Level::Initial, PacketKind::Initial)
            }
            Owned::Handshake => (Level::Handshake, PacketKind::Handshake),
            Owned::Short => {
                if self.side == Side::Server && self.tls.is_handshaking() {
                    // RFC 9001 section 5.7: no 1-RTT before the client is
                    // authenticated.
                    return Ok(());
                }
                (Level::Data, PacketKind::OneRtt)
            }
            Owned::Other => return Ok(()),
        };
        let li = level as usize;
        if self.spaces[li].remote.is_none() {
            if level == Level::Data {
                self.check_reset(packet);
            }
            return Ok(());
        }
        let largest = self.spaces[li].received.max();
        let unprotected = {
            let keys = self.spaces[li]
                .remote
                .as_ref()
                .ok_or(TransportErrorCode::INTERNAL_ERROR)?;
            match remove_header_protection(packet, pn_offset, largest, &keys.header) {
                Ok(u) => u,
                Err(_) => return Ok(()),
            }
        };
        let range = match self.open(level, packet, &unprotected) {
            Some(Ok(r)) => r,
            Some(Err(code)) => return Err(code),
            None => {
                if level == Level::Data {
                    self.check_reset(packet);
                }
                if let Some(u) = self.usage.as_mut() {
                    u.failed()?;
                }
                return Ok(());
            }
        };
        let pn = unprotected.pn;
        if self.spaces[li].received.contains(pn) {
            return Ok(());
        }
        self.heard = true;
        self.last_activity = now;
        let payload = packet[range].to_vec();
        let mut ack_eliciting = false;
        for f in frames(&payload, kind) {
            let f = f.map_err(|e| e.code())?;
            ack_eliciting |= f.is_ack_eliciting();
            self.handle_frame(now, level, f)?;
            if matches!(self.state, State::Closed | State::Draining) {
                return Ok(());
            }
        }
        let s = &mut self.spaces[li];
        s.received.insert(pn..pn + 1);
        s.received.keep_highest(ACK_RANGES_KEPT);
        if s.received.max() == Some(pn) {
            s.largest_received_at = Some(now);
        }
        if ack_eliciting {
            s.unacked += 1;
        }
        if self.side == Side::Server && level == Level::Handshake {
            // A Handshake packet proves the client's address, and the
            // server's Initial keys go (RFC 9001 section 4.9.1).
            self.amplification.validate();
            self.discard(Level::Initial);
        }
        Ok(())
    }

    /// Opens a packet's payload. For 1-RTT, follows the peer's key phase.
    /// `None` when it does not authenticate.
    fn open(
        &mut self,
        level: Level,
        packet: &mut [u8],
        u: &crate::protect::Unprotected,
    ) -> Option<Result<core::ops::Range<usize>, TransportErrorCode>> {
        let li = level as usize;
        if level == Level::Data {
            let phase = self.phase.as_mut()?;
            if u.key_phase != phase.bit {
                // The peer moved to the next keys (RFC 9001 section 6.2).
                if phase.next.is_none() {
                    phase.next = Some(phase.secrets.next_packet_keys());
                }
                let next = phase.next.as_ref()?;
                let r = open_payload(packet, u, &next.remote).ok()?;
                let next = phase.next.take()?;
                phase.bit = u.key_phase;
                let s = &mut self.spaces[li];
                if let Some(k) = s.local.as_mut() {
                    k.packet = next.local;
                }
                if let Some(k) = s.remote.as_mut() {
                    k.packet = next.remote;
                }
                if let Some(usage) = self.usage.as_mut() {
                    usage.key_updated();
                }
                return Some(Ok(r));
            }
        }
        let keys = self.spaces[li].remote.as_ref()?;
        match open_payload(packet, u, &keys.packet) {
            Ok(r) => Some(Ok(r)),
            Err(e) => e.code().map(Err),
        }
    }

    fn handle_retry(&mut self, packet: &[u8], scid: ConnectionId, token: Vec<u8>) {
        // RFC 9000 section 17.2.5.2: one Retry, before anything else, with
        // a valid tag, a new ID, and a token.
        if self.side != Side::Client || self.heard || self.retry_scid.is_some() || token.is_empty()
        {
            return;
        }
        if scid == self.remote_cid || !verify_retry(&self.original_dcid, packet, &TlsRetry) {
            return;
        }
        let Ok(keys) = initial_keys(&scid, Side::Client) else {
            return;
        };
        self.retry_scid = Some(scid);
        self.remote_cid = scid;
        self.token = token;
        let s = &mut self.spaces[0];
        install(s, keys);
        // Everything sent in Initial packets goes again under the new keys.
        let lost: Vec<SentPacket> = core::mem::take(&mut s.sent).into_values().collect();
        for p in lost {
            if p.in_flight {
                self.cc.on_discarded(p.size);
            }
            self.on_packet_lost(Level::Initial, p);
        }
    }

    fn handle_frame(
        &mut self,
        now: Instant,
        level: Level,
        f: Frame<'_>,
    ) -> Result<(), TransportErrorCode> {
        let li = level as usize;
        match f {
            Frame::Padding { .. } | Frame::Ping => {}
            Frame::Ack(ack) => self.on_ack(now, level, &ack)?,
            Frame::Crypto { offset, data } => {
                self.spaces[li].crypto_recv.on_crypto(offset, data)?;
                let mut buf = vec![0u8; self.spaces[li].crypto_recv.readable()];
                let n = self.spaces[li].crypto_recv.read(&mut buf);
                if n > 0 {
                    if self.tls.read_handshake(&buf[..n]).is_err() {
                        let code = self.tls.alert().map_or(
                            TransportErrorCode::CONNECTION_REFUSED,
                            TransportErrorCode::crypto,
                        );
                        return Err(code);
                    }
                    self.pump_tls();
                }
            }
            Frame::NewToken { token } => {
                if self.side == Side::Server {
                    return Err(TransportErrorCode::PROTOCOL_VIOLATION);
                }
                self.events.push_back(Event::NewToken(token.to_vec()));
            }
            Frame::HandshakeDone => {
                if self.side == Side::Server {
                    return Err(TransportErrorCode::PROTOCOL_VIOLATION);
                }
                self.confirm();
            }
            Frame::ConnectionClose {
                error_code,
                frame_type,
                reason,
            } => {
                let close = Close {
                    code: error_code,
                    application: frame_type.is_none(),
                    reason: reason.to_vec(),
                    remote: true,
                };
                self.state = State::Draining;
                self.close_at = Some(now + self.rtt.pto() * 3);
                self.close = Some(close.clone());
                self.events.push_back(Event::Closed(close));
            }
            Frame::Stream {
                stream_id,
                offset,
                data,
                fin,
            } => {
                let id = self.peer_stream(stream_id, true)?;
                let st = self
                    .streams
                    .get_mut(&id)
                    .ok_or(TransportErrorCode::STREAM_STATE_ERROR)?;
                let recv = st
                    .recv
                    .as_mut()
                    .ok_or(TransportErrorCode::STREAM_STATE_ERROR)?;
                let before = recv.readable();
                let growth = recv.on_stream(offset, data, fin)?;
                self.conn_recv.receive_more(growth)?;
                if recv.readable() > before || recv.is_finished() {
                    self.events.push_back(Event::StreamReadable(id));
                }
            }
            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                let id = self.peer_stream(stream_id, true)?;
                let st = self
                    .streams
                    .get_mut(&id)
                    .ok_or(TransportErrorCode::STREAM_STATE_ERROR)?;
                let recv = st
                    .recv
                    .as_mut()
                    .ok_or(TransportErrorCode::STREAM_STATE_ERROR)?;
                let growth = recv.on_reset(error_code, final_size)?;
                self.conn_recv.receive_more(growth)?;
                self.conn_recv.consumed(recv.take_consumed());
                self.events.push_back(Event::StreamReset {
                    id,
                    code: error_code,
                });
            }
            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                let id = self.peer_stream(stream_id, false)?;
                let st = self
                    .streams
                    .get_mut(&id)
                    .ok_or(TransportErrorCode::STREAM_STATE_ERROR)?;
                let send = st
                    .send
                    .as_mut()
                    .ok_or(TransportErrorCode::STREAM_STATE_ERROR)?;
                if let Some(reset) = send.on_stop_sending(error_code) {
                    self.resets_pending.insert(id, reset);
                }
                self.events.push_back(Event::StreamStopped {
                    id,
                    code: error_code,
                });
            }
            Frame::MaxData(max) => self.conn_send.raise(max),
            Frame::MaxStreamData { stream_id, max } => {
                let id = self.peer_stream(stream_id, false)?;
                if let Some(send) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) {
                    send.raise(max);
                }
            }
            Frame::MaxStreams { bidi, max } => {
                if bidi {
                    self.local_bidi.raise(max);
                } else {
                    self.local_uni.raise(max);
                }
            }
            Frame::DataBlocked(_)
            | Frame::StreamDataBlocked { .. }
            | Frame::StreamsBlocked { .. } => {}
            Frame::NewConnectionId {
                sequence,
                retire_prior_to,
                cid,
                reset_token,
            } => {
                if self.remote_cid.is_empty() {
                    return Err(TransportErrorCode::PROTOCOL_VIOLATION);
                }
                if let Some(p) = self.peer_cids.as_mut() {
                    // The IDs retired here are not used yet: this version
                    // sends to the first ID only.
                    let _ = p.on_new_connection_id(sequence, retire_prior_to, cid, reset_token)?;
                }
            }
            Frame::RetireConnectionId { .. } => {}
            Frame::PathChallenge(data) => {
                // Answered with PATH_RESPONSE on the next packet; this
                // version keeps one path, so the answer is immediate.
                self.path_responses.push(data);
            }
            Frame::PathResponse(_) => {}
        }
        Ok(())
    }

    /// The stream a peer's frame names, opening it (and the lower ones of
    /// its type) when the peer may open it. `receiving`: whether the frame
    /// is about the receiving part.
    fn peer_stream(&mut self, raw: u64, receiving: bool) -> Result<StreamId, TransportErrorCode> {
        let id = StreamId::from_raw(raw).ok_or(TransportErrorCode::STREAM_STATE_ERROR)?;
        let ok = if receiving {
            id.can_receive(self.side)
        } else {
            id.can_send(self.side)
        };
        if !ok {
            return Err(TransportErrorCode::STREAM_STATE_ERROR);
        }
        if id.initiator() == self.side {
            let opened = if id.is_bidi() {
                self.local_bidi.is_opened(id.index())
            } else {
                self.local_uni.is_opened(id.index())
            };
            if !opened {
                return Err(TransportErrorCode::STREAM_STATE_ERROR);
            }
            return Ok(id);
        }
        let opens = if id.is_bidi() {
            self.remote_bidi.on_frame(id.index())?
        } else {
            self.remote_uni.on_frame(id.index())?
        };
        for index in opens {
            let Some(new) = StreamId::new(id.initiator(), id.is_bidi(), index) else {
                continue;
            };
            let st = self.new_stream_state(new);
            self.streams.insert(new, st);
            self.events.push_back(Event::StreamOpened(new));
        }
        Ok(id)
    }

    fn new_stream_state(&self, id: StreamId) -> StreamState {
        let ours = &self.config.params;
        let theirs = self.peer_params.as_ref();
        let local = id.initiator() == self.side;
        // Receive windows: ours. Send credit: the peer's (RFC 9000 18.2).
        let recv_window = match (id.is_bidi(), local) {
            (true, true) => ours.initial_max_stream_data_bidi_local,
            (true, false) => ours.initial_max_stream_data_bidi_remote,
            (false, _) => ours.initial_max_stream_data_uni,
        };
        let send_credit = theirs.map_or(0, |p| match (id.is_bidi(), local) {
            (true, true) => p.initial_max_stream_data_bidi_remote,
            (true, false) => p.initial_max_stream_data_bidi_local,
            (false, _) => p.initial_max_stream_data_uni,
        });
        StreamState {
            send: id
                .can_send(self.side)
                .then(|| SendStream::new(send_credit, self.config.send_buffer)),
            recv: id
                .can_receive(self.side)
                .then(|| RecvStream::new(recv_window)),
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        level: Level,
        ack: &Ack<'_>,
    ) -> Result<(), TransportErrorCode> {
        let li = level as usize;
        if ack.largest >= self.spaces[li].next_pn {
            return Err(TransportErrorCode::PROTOCOL_VIOLATION);
        }
        let mut acked = Vec::new();
        for r in ack.ranges() {
            let pns: Vec<u64> = self.spaces[li].sent.range(r).map(|(pn, _)| *pn).collect();
            for pn in pns {
                if let Some(p) = self.spaces[li].sent.remove(&pn) {
                    acked.push((pn, p));
                }
            }
        }
        if acked.is_empty() {
            return Ok(());
        }
        let s = &mut self.spaces[li];
        s.largest_acked = Some(s.largest_acked.map_or(ack.largest, |l| l.max(ack.largest)));
        // An RTT sample when the largest acknowledged is new and
        // ack-eliciting (RFC 9002 section 5.1).
        if let Some((pn, p)) = acked.iter().max_by_key(|(pn, _)| *pn) {
            if *pn == ack.largest && p.ack_eliciting {
                let delay = if level == Level::Data {
                    let exp = self
                        .peer_params
                        .as_ref()
                        .map_or(3, |p| p.ack_delay_exponent);
                    let max = self
                        .peer_params
                        .as_ref()
                        .map_or(Duration::from_millis(25), |p| p.max_ack_delay);
                    let d = Duration::from_micros(ack.delay.saturating_mul(1 << exp.min(20)));
                    if self.confirmed { d.min(max) } else { d }
                } else {
                    Duration::ZERO
                };
                self.rtt
                    .update(now.saturating_duration_since(p.time), delay);
            }
        }
        for (_, p) in acked {
            if p.in_flight {
                self.cc.on_acked(p.size, p.time);
            }
            for f in p.frames {
                self.on_frame_acked(level, f);
            }
        }
        if self.side == Side::Client && level == Level::Data {
            // An acknowledged 1-RTT packet confirms the handshake too.
            self.confirm();
        }
        if level == Level::Handshake {
            self.handshake_acked = true;
        }
        // A client does not reset its backoff on Initial ACKs: the server
        // may still be limited by its amplification allowance, and must not
        // be probed faster than it can answer (RFC 9002 section 6.2.1).
        if !(self.side == Side::Client && level == Level::Initial) {
            self.pto_count = 0;
        }
        self.detect_lost(now, level);
        Ok(())
    }

    fn on_frame_acked(&mut self, level: Level, f: Sent) {
        match f {
            Sent::Crypto(c) => self.spaces[level as usize].crypto_send.on_acked(&c),
            Sent::Stream(id, c) => {
                if let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) {
                    s.on_acked(&c);
                }
                self.collect(id);
            }
            Sent::ResetStream(id) => {
                if let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) {
                    s.on_reset_acked();
                }
                self.collect(id);
            }
            _ => {}
        }
    }

    /// RFC 9002 section 6.1: packet and time thresholds.
    fn detect_lost(&mut self, now: Instant, level: Level) {
        let li = level as usize;
        let Some(largest) = self.spaces[li].largest_acked else {
            return;
        };
        let delay = self.rtt.loss_delay();
        let mut lost = Vec::new();
        let mut loss_time: Option<Instant> = None;
        for (pn, p) in self.spaces[li].sent.range(..largest) {
            if largest >= pn + PACKET_THRESHOLD || p.time + delay <= now {
                lost.push(*pn);
            } else {
                let t = p.time + delay;
                loss_time = Some(loss_time.map_or(t, |l| l.min(t)));
            }
        }
        self.spaces[li].loss_time = loss_time;
        let mut bytes = 0;
        let mut span: Option<(Instant, Instant)> = None;
        let mut eliciting = 0;
        for pn in lost {
            if let Some(p) = self.spaces[li].sent.remove(&pn) {
                if p.in_flight {
                    bytes += p.size;
                    span = Some(
                        span.map_or((p.time, p.time), |(a, b)| (a.min(p.time), b.max(p.time))),
                    );
                }
                eliciting += usize::from(p.ack_eliciting);
                self.on_packet_lost(level, p);
            }
        }
        if let Some((first, last)) = span {
            self.cc.on_lost(bytes, last, now);
            // RFC 9002 section 7.6: losses spanning three probe timeouts,
            // with an RTT sample to judge by.
            let max_ack_delay = self
                .peer_params
                .as_ref()
                .map_or(Duration::ZERO, |p| p.max_ack_delay);
            let period =
                (self.rtt.pto() + max_ack_delay) * crate::cc::PERSISTENT_CONGESTION_THRESHOLD;
            if self.rtt.sampled && eliciting >= 2 && last.saturating_duration_since(first) > period
            {
                self.cc.on_persistent_congestion();
            }
        }
    }

    fn on_packet_lost(&mut self, level: Level, p: SentPacket) {
        for f in p.frames {
            match f {
                Sent::Crypto(c) => self.spaces[level as usize].crypto_send.on_lost(&c),
                Sent::Stream(id, c) => {
                    if let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) {
                        s.on_lost(&c);
                    }
                }
                Sent::HandshakeDone => self.handshake_done_pending = !self.confirmed_by_peer(),
                Sent::MaxData => self.max_data_pending = true,
                Sent::MaxStreamData(id) => {
                    self.max_stream_data_pending.insert(id);
                }
                Sent::MaxStreams(bidi) => self.max_streams_pending[usize::from(!bidi)] = true,
                Sent::ResetStream(id) => {
                    if let Some(r) = self
                        .streams
                        .get(&id)
                        .and_then(|s| s.send.as_ref())
                        .and_then(SendStream::on_reset_lost)
                    {
                        self.resets_pending.insert(id, r);
                    }
                }
                Sent::StopSending(id, code) => {
                    self.stops_pending.insert(id, code);
                }
            }
        }
    }

    fn confirmed_by_peer(&self) -> bool {
        // HANDSHAKE_DONE is resent until a 1-RTT packet of the server is
        // acknowledged; with nothing else tracked, resend it.
        false
    }

    // ---- Timers -----------------------------------------------------------

    /// When [`handle_timeout`](Self::handle_timeout) should next be called.
    #[must_use]
    pub fn poll_timeout(&self) -> Option<Instant> {
        if self.state == State::Closed {
            return None;
        }
        if let Some(t) = self.close_at {
            return Some(t);
        }
        let mut t = self.idle_deadline();
        let mut earliest = |x: Option<Instant>| {
            if let Some(x) = x {
                t = Some(t.map_or(x, |t: Instant| t.min(x)));
            }
        };
        earliest(self.loss_or_pto().map(|(at, _, _)| at));
        earliest(self.ack_deadline());
        earliest(self.next_send);
        t
    }

    fn idle_deadline(&self) -> Option<Instant> {
        if self.idle_timeout.is_zero() {
            return None;
        }
        Some(self.last_activity + self.idle_timeout.max(self.rtt.pto() * 3))
    }

    fn ack_deadline(&self) -> Option<Instant> {
        let s = &self.spaces[2];
        if s.unacked == 0 {
            return None;
        }
        s.largest_received_at
            .map(|t| t + self.config.params.max_ack_delay)
    }

    /// The next loss timer or probe timeout: when, which level, whether it
    /// is a loss timer.
    fn loss_or_pto(&self) -> Option<(Instant, Level, bool)> {
        let mut best: Option<(Instant, Level, bool)> = None;
        for level in LEVELS {
            if let Some(t) = self.spaces[level as usize].loss_time {
                if best.is_none_or(|(b, _, _)| t < b) {
                    best = Some((t, level, true));
                }
            }
        }
        if best.is_some() {
            return best;
        }
        let backoff = 1u32 << self.pto_count.min(16);
        for level in LEVELS {
            let s = &self.spaces[level as usize];
            if s.discarded || s.local.is_none() {
                continue;
            }
            if level == Level::Data && !self.confirmed {
                continue;
            }
            let mut period = self.rtt.pto();
            if level == Level::Data {
                period += self
                    .peer_params
                    .as_ref()
                    .map_or(Duration::ZERO, |p| p.max_ack_delay);
            }
            let from = if s.ack_eliciting_in_flight() {
                s.last_ack_eliciting
            } else if self.side == Side::Client
                && !self.confirmed
                && !self.handshake_acked
                && level != Level::Data
            {
                // The client keeps probing until the server can send freely:
                // until one of its Handshake packets is acknowledged (RFC
                // 9002 section 6.2.2.1).
                s.last_ack_eliciting.or(Some(self.last_activity))
            } else {
                None
            };
            if let Some(from) = from {
                let t = from + period * backoff;
                if best.is_none_or(|(b, _, _)| t < b) {
                    best = Some((t, level, false));
                }
            }
        }
        best
    }

    /// Runs the timers due at `now`.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.state == State::Closed {
            return;
        }
        if self.next_send.is_some_and(|t| now >= t) {
            // Pacing allows the next packet; poll_transmit sets a new time
            // if it is still held back.
            self.next_send = None;
        }
        if let Some(t) = self.close_at {
            if now >= t {
                self.state = State::Closed;
                self.close_at = None;
            }
            return;
        }
        if self.idle_deadline().is_some_and(|t| now >= t) {
            self.enter_closed(Close {
                code: 0,
                application: false,
                reason: b"idle timeout".to_vec(),
                remote: false,
            });
            return;
        }
        if let Some((at, level, loss)) = self.loss_or_pto() {
            if now >= at {
                if loss {
                    self.detect_lost(now, level);
                } else {
                    self.pto_count += 1;
                    let s = &mut self.spaces[level as usize];
                    let lost: Vec<SentPacket> = core::mem::take(&mut s.sent)
                        .into_values()
                        .filter(|p| p.ack_eliciting)
                        .collect();
                    s.probe = true;
                    for p in lost {
                        if p.in_flight {
                            self.cc.on_discarded(p.size);
                        }
                        self.on_packet_lost(level, p);
                    }
                }
            }
        }
    }

    // ---- Closing ------------------------------------------------------------

    /// Closes the connection with the application's `code` and `reason`.
    pub fn close(&mut self, now: Instant, code: u64, reason: &[u8]) {
        if matches!(self.state, State::Closing | State::Draining | State::Closed) {
            return;
        }
        self.begin_close(
            now,
            Close {
                code,
                application: true,
                reason: reason.to_vec(),
                remote: false,
            },
        );
    }

    fn close_error(&mut self, code: TransportErrorCode, reason: &[u8]) {
        if matches!(self.state, State::Closing | State::Draining | State::Closed) {
            return;
        }
        let now = self.last_activity;
        self.begin_close(
            now,
            Close {
                code: code.0,
                application: false,
                reason: reason.to_vec(),
                remote: false,
            },
        );
    }

    fn begin_close(&mut self, now: Instant, close: Close) {
        self.state = State::Closing;
        self.close_pending = true;
        self.close_at = Some(now + self.rtt.pto() * 3);
        self.close = Some(close.clone());
        self.events.push_back(Event::Closed(close));
    }

    fn enter_closed(&mut self, close: Close) {
        self.state = State::Closed;
        self.close_at = None;
        self.close = Some(close.clone());
        self.events.push_back(Event::Closed(close));
    }

    /// How the connection ended, once it has.
    #[must_use]
    pub fn close_reason(&self) -> Option<&Close> {
        self.close.as_ref()
    }
}

impl Connection {
    // ---- Sending ----------------------------------------------------------

    fn max_datagram(&self) -> usize {
        let peer = self
            .peer_params
            .as_ref()
            .map_or(u64::MAX, |p| p.max_udp_payload_size);
        let ours = self.config.max_datagram.max(MIN_INITIAL_SIZE);
        usize::try_from(peer).map_or(ours, |p| ours.min(p.max(MIN_INITIAL_SIZE)))
    }

    /// Whether `level` has something to send at `now`.
    fn wants(&self, now: Instant, level: Level) -> bool {
        let s = &self.spaces[level as usize];
        if s.local.is_none() || s.discarded {
            return false;
        }
        if self.state == State::Closing {
            return true;
        }
        let ack = s.unacked > 0
            && (level != Level::Data
                || s.unacked >= 2
                || self.ack_deadline().is_some_and(|t| now >= t));
        if ack || s.probe || s.crypto_send.has_pending() {
            return true;
        }
        level == Level::Data && self.state == State::Established && self.data_pending()
    }

    fn data_pending(&self) -> bool {
        self.handshake_done_pending
            || self.max_data_pending
            || !self.max_stream_data_pending.is_empty()
            || self.max_streams_pending.iter().any(|p| *p)
            || !self.resets_pending.is_empty()
            || !self.stops_pending.is_empty()
            || !self.path_responses.is_empty()
            || (self.conn_send.available() > 0
                && self
                    .streams
                    .values()
                    .any(|s| s.send.as_ref().is_some_and(SendStream::has_pending)))
            || self.streams.values().any(|s| {
                s.send
                    .as_ref()
                    .is_some_and(|s| s.has_pending() && s.held() == 0)
            })
    }

    /// Writes the next datagram into `out` (cleared first): coalesced
    /// Initial, Handshake, and 1-RTT packets as needed. `false` when there
    /// is nothing to send now.
    pub fn poll_transmit(&mut self, now: Instant, out: &mut Vec<u8>) -> bool {
        out.clear();
        if matches!(self.state, State::Closed | State::Draining) {
            return false;
        }
        if self.state == State::Closing && !self.close_pending {
            return false;
        }
        let mut budget = self.max_datagram();
        if !self.amplification.is_validated() {
            budget =
                budget.min(usize::try_from(self.amplification.allowance()).unwrap_or(usize::MAX));
        }
        let mut levels: Vec<Level> = LEVELS.into_iter().filter(|l| self.wants(now, *l)).collect();
        if levels.is_empty() {
            return false;
        }
        // Congestion control and pacing hold back what would be in flight;
        // ACKs always go, and so do probes and closes (RFC 9002 section 7.5).
        let probing = self.state == State::Closing || self.spaces.iter().any(|s| s.probe);
        let mut ack_only = false;
        if !probing {
            let available = usize::try_from(self.cc.available()).unwrap_or(usize::MAX);
            // A datagram goes while the window has room: it may pass the
            // window by less than one datagram, as is usual.
            if available == 0 {
                ack_only = true;
            } else if self.config.pacing {
                let window = self.cc.window();
                let paced =
                    self.pacer
                        .check(now, budget, window, self.rtt.smoothed, self.max_datagram());
                match paced {
                    Ok(()) => {}
                    Err(at) => {
                        self.next_send = Some(at);
                        ack_only = true;
                    }
                }
            }
        }
        if ack_only {
            levels.retain(|l| self.spaces[*l as usize].unacked > 0);
            if levels.is_empty() {
                return false;
            }
        } else {
            self.next_send = None;
        }
        self.ack_only = ack_only;
        // A datagram with an Initial packet is padded to 1,200 bytes: a
        // client's always, a server's when the Initial is ack-eliciting
        // (RFC 9000 section 14.1). An ACK alone is not padded, so it spends
        // none of the amplification allowance it does not need.
        let initial = &self.spaces[0];
        let eliciting =
            initial.crypto_send.has_pending() || initial.probe || self.state == State::Closing;
        let pad = levels.contains(&Level::Initial) && (self.side == Side::Client || eliciting);
        if pad && budget < MIN_INITIAL_SIZE {
            return false;
        }
        let mut sent_handshake = false;
        for (i, level) in levels.iter().enumerate() {
            let last = i + 1 == levels.len();
            let min_len = if pad && last {
                MIN_INITIAL_SIZE.saturating_sub(out.len())
            } else {
                0
            };
            let room = budget.saturating_sub(out.len());
            if self.write_packet(now, *level, out, room, min_len) && *level == Level::Handshake {
                sent_handshake = true;
            }
        }
        if self.state == State::Closing {
            self.close_pending = false;
        }
        if out.is_empty() {
            return false;
        }
        if !ack_only && self.config.pacing {
            self.pacer.on_sent(out.len());
        }
        self.amplification.on_sent(out.len());
        if sent_handshake && self.side == Side::Client {
            // RFC 9001 section 4.9.1.
            self.discard(Level::Initial);
        }
        true
    }

    /// Builds one packet at `level` into `out`, within `room` bytes and at
    /// least `min_len` long. `false` when nothing was written.
    fn write_packet(
        &mut self,
        now: Instant,
        level: Level,
        out: &mut Vec<u8>,
        room: usize,
        min_len: usize,
    ) -> bool {
        let li = level as usize;
        let pn = self.spaces[li].next_pn;
        let pn_len = packet_number_len(pn, self.spaces[li].largest_acked);
        let header_max = match level {
            Level::Data => 1 + self.remote_cid.len() + pn_len,
            Level::Initial => LONG_HEADER_MAX + self.token.len() + 8,
            Level::Handshake => LONG_HEADER_MAX,
        };
        if room < header_max + TAG_LEN + 8 {
            return false;
        }
        let max_payload = room - header_max - TAG_LEN;
        let mut payload: Vec<u8> = Vec::with_capacity(max_payload.min(1500));
        let mut sent: Vec<Sent> = Vec::new();
        let mut ack_eliciting = false;

        if self.state == State::Closing {
            self.write_close_frame(level, &mut payload, max_payload);
        } else if self.ack_only {
            self.write_ack(now, level, &mut payload);
        } else {
            self.write_ack(now, level, &mut payload);
            while max_payload.saturating_sub(payload.len()) > 24 {
                let space_left = max_payload - payload.len() - 16;
                let Some(chunk) = self.spaces[li].crypto_send.next_chunk(space_left, u64::MAX)
                else {
                    break;
                };
                self.spaces[li]
                    .crypto_send
                    .write_crypto_frame(&chunk, &mut payload);
                sent.push(Sent::Crypto(chunk));
                ack_eliciting = true;
            }
            if level == Level::Data && self.state == State::Established {
                ack_eliciting |= self.write_data_frames(&mut payload, max_payload, &mut sent);
            }
            if self.spaces[li].probe && !ack_eliciting {
                payload.push(0x01); // PING
                ack_eliciting = true;
            }
        }
        if payload.is_empty() && min_len == 0 {
            return false;
        }
        // The sample needs 4 bytes from the packet number on (RFC 9001
        // section 5.4.2); and the datagram may need padding.
        let mut pad = (4usize.saturating_sub(pn_len)).saturating_sub(payload.len());
        let start = out.len();
        let mut pn_offset;
        loop {
            out.truncate(start);
            pn_offset = self.write_header(level, out, pn, pn_len, payload.len() + pad + TAG_LEN);
            let total = out.len() - start + payload.len() + pad + TAG_LEN;
            if total >= min_len {
                break;
            }
            pad += min_len - total;
        }
        out.extend_from_slice(&payload);
        out.resize(out.len() + pad + TAG_LEN, 0);
        let sealed = {
            let Some(keys) = self.spaces[li].local.as_ref() else {
                out.truncate(start);
                return false;
            };
            seal_packet(&mut out[start..], pn_offset, pn, &keys.packet, &keys.header).is_ok()
        };
        if !sealed {
            out.truncate(start);
            return false;
        }
        let size = out.len() - start;
        let in_flight = ack_eliciting || pad > 0;
        if in_flight {
            self.cc.on_sent(size);
        }
        let s = &mut self.spaces[li];
        s.next_pn += 1;
        if in_flight || !sent.is_empty() {
            s.sent.insert(
                pn,
                SentPacket {
                    time: now,
                    ack_eliciting,
                    in_flight,
                    size,
                    frames: sent,
                },
            );
        }
        if ack_eliciting {
            s.last_ack_eliciting = Some(now);
            s.probe = false;
        }
        if level == Level::Data {
            if let Some(u) = self.usage.as_mut() {
                u.sealed();
            }
        }
        true
    }

    fn write_header(
        &self,
        level: Level,
        out: &mut Vec<u8>,
        pn: u64,
        pn_len: usize,
        rest: usize,
    ) -> usize {
        match level {
            Level::Initial => LongHeader {
                ty: LongType::Initial,
                dcid: self.remote_cid,
                scid: self.local_cid,
                token: &self.token,
            }
            .encode(out, pn, pn_len, rest),
            Level::Handshake => LongHeader {
                ty: LongType::Handshake,
                dcid: self.remote_cid,
                scid: self.local_cid,
                token: &[],
            }
            .encode(out, pn, pn_len, rest),
            Level::Data => {
                let bit = self.phase.as_ref().is_some_and(|p| p.bit);
                write_short(out, &self.remote_cid, false, bit, pn, pn_len)
            }
        }
    }

    fn write_ack(&mut self, now: Instant, level: Level, payload: &mut Vec<u8>) {
        let s = &mut self.spaces[level as usize];
        if s.unacked == 0 && (!s.probe || s.received.is_empty()) {
            return;
        }
        let ranges: Vec<core::ops::RangeInclusive<u64>> = s.received.iter_desc().collect();
        if ranges.is_empty() {
            return;
        }
        let delay = if level == Level::Data {
            s.largest_received_at.map_or(0, |t| {
                now.saturating_duration_since(t).as_micros() as u64 >> ACK_DELAY_EXPONENT
            })
        } else {
            0
        };
        if Ack::write(payload, &ranges, delay, None) {
            s.unacked = 0;
        }
    }

    fn write_close_frame(&self, level: Level, payload: &mut Vec<u8>, max: usize) {
        let Some(close) = self.close.as_ref() else {
            return;
        };
        let reason = &close.reason[..close.reason.len().min(max.saturating_sub(24))];
        let frame = if close.application && level == Level::Data {
            Frame::ConnectionClose {
                error_code: close.code,
                frame_type: None,
                reason,
            }
        } else if close.application {
            // Before 1-RTT, an application close is sent as a transport
            // close without its reason (RFC 9000 section 10.2.3).
            Frame::ConnectionClose {
                error_code: TransportErrorCode::APPLICATION_ERROR.0,
                frame_type: Some(0),
                reason: &[],
            }
        } else {
            Frame::ConnectionClose {
                error_code: close.code,
                frame_type: Some(0),
                reason,
            }
        };
        frame.encode(payload);
    }

    /// The 1-RTT frames beyond ACK and CRYPTO. Returns whether any is
    /// ack-eliciting.
    fn write_data_frames(
        &mut self,
        payload: &mut Vec<u8>,
        max: usize,
        sent: &mut Vec<Sent>,
    ) -> bool {
        let start = payload.len();
        let fits = |payload: &Vec<u8>, n: usize| max.saturating_sub(payload.len()) >= n;
        if self.handshake_done_pending && fits(payload, 1) {
            Frame::HandshakeDone.encode(payload);
            sent.push(Sent::HandshakeDone);
            self.handshake_done_pending = false;
        }
        while let Some(data) = self.path_responses.pop() {
            if !fits(payload, 9) {
                self.path_responses.push(data);
                break;
            }
            Frame::PathResponse(data).encode(payload);
        }
        if self.max_data_pending && fits(payload, 9) {
            Frame::MaxData(self.conn_recv.max()).encode(payload);
            sent.push(Sent::MaxData);
            self.max_data_pending = false;
        }
        let ids: Vec<StreamId> = self.max_stream_data_pending.iter().copied().collect();
        for id in ids {
            if !fits(payload, 17) {
                break;
            }
            self.max_stream_data_pending.remove(&id);
            if let Some(r) = self.streams.get(&id).and_then(|s| s.recv.as_ref()) {
                Frame::MaxStreamData {
                    stream_id: id.raw(),
                    max: r.limit(),
                }
                .encode(payload);
                sent.push(Sent::MaxStreamData(id));
            }
        }
        for (i, bidi) in [(0, true), (1, false)] {
            if self.max_streams_pending[i] && fits(payload, 9) {
                let max = if bidi {
                    self.remote_bidi.limit()
                } else {
                    self.remote_uni.limit()
                };
                Frame::MaxStreams { bidi, max }.encode(payload);
                sent.push(Sent::MaxStreams(bidi));
                self.max_streams_pending[i] = false;
            }
        }
        let resets: Vec<(StreamId, (u64, u64))> =
            self.resets_pending.iter().map(|(k, v)| (*k, *v)).collect();
        for (id, (code, final_size)) in resets {
            if !fits(payload, 25) {
                break;
            }
            self.resets_pending.remove(&id);
            Frame::ResetStream {
                stream_id: id.raw(),
                error_code: code,
                final_size,
            }
            .encode(payload);
            sent.push(Sent::ResetStream(id));
        }
        let stops: Vec<(StreamId, u64)> =
            self.stops_pending.iter().map(|(k, v)| (*k, *v)).collect();
        for (id, code) in stops {
            if !fits(payload, 17) {
                break;
            }
            self.stops_pending.remove(&id);
            Frame::StopSending {
                stream_id: id.raw(),
                error_code: code,
            }
            .encode(payload);
            sent.push(Sent::StopSending(id, code));
        }
        // Stream data, round robin from after the last stream served.
        let ids: Vec<StreamId> = self
            .streams
            .iter()
            .filter(|(_, s)| s.send.as_ref().is_some_and(SendStream::has_pending))
            .map(|(id, _)| *id)
            .collect();
        if !ids.is_empty() {
            let first = self
                .next_stream
                .and_then(|n| ids.iter().position(|id| *id > n))
                .unwrap_or(0);
            for k in 0..ids.len() {
                let id = ids[(first + k) % ids.len()];
                let left = max.saturating_sub(payload.len());
                if left < 32 {
                    break;
                }
                let available = self.conn_send.available();
                let Some(send) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) else {
                    continue;
                };
                let Some(chunk) = send.next_chunk(left - 24, available) else {
                    continue;
                };
                send.write_frame(id, &chunk, payload);
                self.conn_send.consume(chunk.new);
                sent.push(Sent::Stream(id, chunk));
                self.next_stream = Some(id);
            }
        }
        payload.len() > start
    }
}

impl Connection {
    // ---- Streams ----------------------------------------------------------

    /// Opens a stream, or `None` at the peer's limit or before the
    /// connection is established.
    pub fn open_stream(&mut self, bidi: bool) -> Option<StreamId> {
        if self.state != State::Established {
            return None;
        }
        let index = if bidi {
            self.local_bidi.open()?
        } else {
            self.local_uni.open()?
        };
        let id = StreamId::new(self.side, bidi, index)?;
        let st = self.new_stream_state(id);
        self.streams.insert(id, st);
        Some(id)
    }

    fn send_part(&mut self, id: StreamId) -> Result<&mut SendStream, StreamError> {
        if self.state != State::Established {
            return Err(StreamError::NotConnected);
        }
        self.streams
            .get_mut(&id)
            .and_then(|s| s.send.as_mut())
            .ok_or(StreamError::Unknown)
    }

    /// Buffers what fits of `data` on stream `id`; returns how much.
    ///
    /// # Errors
    ///
    /// [`StreamError`] for an unknown or receive-only stream, or a closed
    /// connection.
    pub fn stream_write(&mut self, id: StreamId, data: &[u8]) -> Result<usize, StreamError> {
        let s = self.send_part(id)?;
        if let crate::send::SendState::ResetSent | crate::send::SendState::ResetRecvd = s.state() {
            return Err(StreamError::Reset(0));
        }
        Ok(s.write(data))
    }

    /// Ends stream `id`'s sending part after what was written.
    ///
    /// # Errors
    ///
    /// As [`stream_write`](Self::stream_write).
    pub fn stream_finish(&mut self, id: StreamId) -> Result<(), StreamError> {
        self.send_part(id)?.finish();
        Ok(())
    }

    /// Resets stream `id`'s sending part with `code`.
    ///
    /// # Errors
    ///
    /// As [`stream_write`](Self::stream_write).
    pub fn stream_reset(&mut self, id: StreamId, code: u64) -> Result<(), StreamError> {
        if let Some(r) = self.send_part(id)?.reset(code) {
            self.resets_pending.insert(id, r);
        }
        Ok(())
    }

    /// Reads from stream `id` into `out`; `Ok(0)` when nothing is ready (see
    /// [`stream_is_finished`](Self::stream_is_finished) for the end).
    ///
    /// # Errors
    ///
    /// [`StreamError::Reset`] when the peer reset it, or as
    /// [`stream_write`](Self::stream_write).
    pub fn stream_read(&mut self, id: StreamId, out: &mut [u8]) -> Result<usize, StreamError> {
        if !matches!(self.state, State::Established) {
            return Err(StreamError::NotConnected);
        }
        if !self.streams.contains_key(&id) && self.was_opened(id) && id.can_receive(self.side) {
            // Finished and forgotten.
            return Ok(0);
        }
        let recv = self
            .streams
            .get_mut(&id)
            .and_then(|s| s.recv.as_mut())
            .ok_or(StreamError::Unknown)?;
        if let crate::recv::RecvState::ResetRecvd(code) = recv.state() {
            return Err(StreamError::Reset(code));
        }
        let n = recv.read(out);
        let consumed = recv.take_consumed();
        if recv.update().is_some() {
            self.max_stream_data_pending.insert(id);
        }
        self.conn_recv.consumed(consumed);
        if self.conn_recv.update().is_some() {
            self.max_data_pending = true;
        }
        self.collect(id);
        Ok(n)
    }

    /// Asks the peer to stop sending on stream `id` (`STOP_SENDING`).
    ///
    /// # Errors
    ///
    /// As [`stream_read`](Self::stream_read).
    pub fn stream_stop(&mut self, id: StreamId, code: u64) -> Result<(), StreamError> {
        let recv = self
            .streams
            .get_mut(&id)
            .and_then(|s| s.recv.as_mut())
            .ok_or(StreamError::Unknown)?;
        recv.stop();
        let consumed = recv.take_consumed();
        self.conn_recv.consumed(consumed);
        self.stops_pending.insert(id, code);
        Ok(())
    }

    /// Whether stream `id` was read to its end.
    #[must_use]
    pub fn stream_is_finished(&self, id: StreamId) -> bool {
        match self.streams.get(&id) {
            Some(s) => s.recv.as_ref().is_some_and(RecvStream::is_finished),
            None => self.was_opened(id) && id.can_receive(self.side),
        }
    }

    /// Whether stream `id` was opened, by either side; one that was and is
    /// no longer held is finished both ways.
    fn was_opened(&self, id: StreamId) -> bool {
        match (id.initiator() == self.side, id.is_bidi()) {
            (true, true) => self.local_bidi.is_opened(id.index()),
            (true, false) => self.local_uni.is_opened(id.index()),
            (false, true) => self.remote_bidi.is_opened(id.index()),
            (false, false) => self.remote_uni.is_opened(id.index()),
        }
    }

    /// Forgets a peer's stream once both of its parts are done, so the
    /// peer may open another (RFC 9000 section 4.6).
    fn collect(&mut self, id: StreamId) {
        let Some(st) = self.streams.get(&id) else {
            return;
        };
        let recv_done = st.recv.as_ref().is_none_or(|r| {
            r.is_finished() || matches!(r.state(), crate::recv::RecvState::ResetRecvd(_))
        });
        let send_done = st.send.as_ref().is_none_or(|s| {
            matches!(
                s.state(),
                crate::send::SendState::DataRecvd | crate::send::SendState::ResetRecvd
            )
        });
        if !(recv_done && send_done) {
            return;
        }
        self.streams.remove(&id);
        if id.initiator() != self.side {
            let (remote, i) = if id.is_bidi() {
                (&mut self.remote_bidi, 0)
            } else {
                (&mut self.remote_uni, 1)
            };
            remote.on_closed();
            if remote.update().is_some() {
                self.max_streams_pending[i] = true;
            }
        }
    }
}

/// A header's fields, copied out of the datagram so it can be decrypted in
/// place.
enum Owned {
    VersionNegotiation(Vec<u32>),
    Retry { scid: ConnectionId, token: Vec<u8> },
    Initial { scid: ConnectionId },
    Handshake,
    Short,
    Other,
}

impl From<&Header<'_>> for Owned {
    fn from(h: &Header<'_>) -> Owned {
        match h {
            Header::VersionNegotiation { .. } => Owned::VersionNegotiation(h.versions().collect()),
            Header::Retry { scid, token, .. } => Owned::Retry {
                scid: *scid,
                token: token.to_vec(),
            },
            Header::Long { ty, scid, .. } => match ty {
                LongType::Initial => Owned::Initial { scid: *scid },
                LongType::Handshake => Owned::Handshake,
                _ => Owned::Other,
            },
            Header::Short { .. } => Owned::Short,
            _ => Owned::Other,
        }
    }
}
