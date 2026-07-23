// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! Transparent forwarding: relays intercepted flows to real upstream servers
//! over `protect()`ed sockets so allowed traffic reaches the internet instead of
//! being black-holed.
//!
//! TCP rides the smoltcp proxy in `adwarden_netstack::NetStack`; the upstream
//! side is a `protect()`ed non-blocking `TcpStream`. UDP is a small NAT table of
//! `protect()`ed connected `UdpSocket`s. All sockets share the datapath thread's
//! mio `Poll` via tokens allocated here.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::time::{Instant as StdInstant, SystemTime, UNIX_EPOCH};

use mio::net::{TcpStream, UdpSocket};
use mio::{Interest, Registry, Token};
use socket2::{Domain, Socket, Type};

use adwarden_filter::FilterEngine;
use adwarden_pcap::PcapWriter;
use adwarden_netstack::packet::L4;
use adwarden_netstack::{reset_for_syn, udp, Decoded, FlowId, FlowKey, FlowTable, NetStack};
use adwarden_tls::{peek_sni, write_har, DnsKind, HttpTransaction, MitmConfigs, SniPeek, TlsMitm};

use crate::bridge::Bridge;
use crate::config::{Config, EncryptedDnsMode};
use crate::event::{Batcher, Event};
use crate::proxy::{self, Handshake, Proxy, Step as ProxyStep};

const DOT_PORT: u16 = 853;
const HTTPS_PORT: u16 = 443;
const PROTO_TCP: i32 = 6;
const PROTO_UDP: i32 = 17;
const VERDICT_CACHE_CAP: usize = 4096;
/// Backpressure cap: stop reading a MITM'd upstream while this many decrypted
/// bytes are still queued for the (slow) app side.
const MITM_APP_BUF_CAP: usize = 256 * 1024;
/// Bound on decrypted HTTP transactions retained for HAR export (P2-3). Oldest
/// are dropped past this so a long session can't grow memory without limit.
const HAR_MAX_ENTRIES: usize = 5_000;
/// Bound on remembered (app, server) pairs that pin against our leaf (P2-4).
const PINNED_CAP: usize = 4_096;

/// Current default network transport, matching Kotlin's NetworkStateMonitor.
pub const TRANSPORT_OTHER: u8 = 0;
pub const TRANSPORT_WIFI: u8 = 1;
pub const TRANSPORT_CELLULAR: u8 = 2;

/// Per-app policy: allowed on Wi-Fi / cellular, and whether its HTTPS should be
/// TLS-intercepted (P2). Interception is opt-in per app so enabling the feature
/// never MITMs a flow the user didn't choose (and can't break, e.g., system DoH).
#[derive(Clone, Copy)]
pub struct AppPolicy {
    pub allow_wifi: bool,
    pub allow_cellular: bool,
    pub inspect_tls: bool,
}

/// First token handed to an upstream socket (0/1 are reserved for TUN/waker).
const FIRST_DYNAMIC_TOKEN: usize = 16;
const UDP_IDLE_MS: i64 = 60_000;
const MAX_DATAGRAM: usize = 65_535;
/// A proxy handshake (TCP CONNECT, HTTPS-proxy TLS, or SOCKS5 ASSOCIATE) that
/// hasn't completed within this is failed closed — so a TLS ClientHello sent to a
/// plaintext proxy port, or a black-holed proxy, errors quickly instead of hanging
/// until the app or the 60s idle reap gives up (P5).
const PROXY_HS_TIMEOUT_MS: i64 = 10_000;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct UdpKey {
    app: SocketAddr,
    server: SocketAddr,
}

enum Route {
    Tcp(FlowId),
    Udp(UdpKey),
    /// SOCKS5 UDP ASSOCIATE control connection (keeps the association alive).
    SocksCtrl(UdpKey),
    /// SOCKS5 UDP ASSOCIATE relay socket (carries the encapsulated datagrams).
    SocksRelay(UdpKey),
    /// A one-shot DNS-over-TCP query through an HTTP/HTTPS proxy (P5). Keyed in
    /// `dns_tcp` by the socket's own token, which is the readiness token here.
    DnsTcp,
}

/// Whether a flow's interception has been decided, or is waiting on the SNI.
enum Classify {
    /// Interception (or raw relay) was decided when the flow opened.
    Settled,
    /// A 443 flow under Filter mode: buffer the app's bytes until the ClientHello
    /// reveals the SNI, then classify as DoH (filter), cosmetic (inspected app),
    /// or raw. Encrypted-DNS detection is auto (all apps), so we must peek.
    PendingSni(Vec<u8>),
}

/// Cap on ClientHello bytes buffered while waiting to peek the SNI; past this we
/// give up peeking and treat the flow as non-DoH.
const SNI_PEEK_CAP: usize = 16 * 1024;

/// Outcome of inspecting an allowed-so-far DNS datagram in [`Forwarder::handle_dns`].
enum DnsOutcome {
    /// The name matched the blocklist: an NXDOMAIN was already injected toward the
    /// app and a block event emitted; the query must not be forwarded.
    Sinkholed,
    /// Forward the query upstream. Carries the decoded query name (when it parsed)
    /// so the allowed flow event can surface the domain in the live log.
    Forward(Option<String>),
}

/// The upstream transport for a TCP flow. A plaintext socket (`Plain`) — used for
/// a direct dial, or a connection to an HTTP/SOCKS5 proxy — or a rustls session
/// to an HTTPS proxy (`Tls`), through which the relayed bytes (and the CONNECT
/// handshake) tunnel. The relay code above works in *plaintext*; `UpstreamIo`
/// hides whether that plaintext rides a bare socket or a TLS session to the proxy.
enum UpstreamIo {
    Plain(TcpStream),
    Tls(Box<ProxyTls>),
}

/// A TLS client session to an HTTPS proxy, wrapping the underlying socket.
struct ProxyTls {
    stream: TcpStream,
    conn: rustls::ClientConnection,
}

impl ProxyTls {
    /// Build a client session verifying the proxy against the bundled root store
    /// (an HTTPS proxy with a publicly-trusted cert). `None` on config/name error.
    fn new(stream: TcpStream, server_name: &str) -> Option<ProxyTls> {
        let config = adwarden_tls::upstream_client_config().ok()?;
        let name = rustls::pki_types::ServerName::try_from(server_name.to_string()).ok()?;
        let conn = rustls::ClientConnection::new(config, name).ok()?;
        Some(ProxyTls { stream, conn })
    }

    /// Move TLS records between the socket and rustls: flush queued output, then
    /// read and process available input. Nonblocking — `WouldBlock` means "done
    /// for now". Advances the handshake as a side effect.
    fn pump(&mut self) -> io::Result<()> {
        while self.conn.wants_write() {
            match self.conn.write_tls(&mut self.stream) {
                Ok(0) => break,
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        loop {
            match self.conn.read_tls(&mut self.stream) {
                Ok(0) => break, // socket EOF
                Ok(_) => self
                    .conn
                    .process_new_packets()
                    .map(|_| ())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

impl UpstreamIo {
    /// The underlying socket, for mio (de)registration and error polling.
    fn source(&mut self) -> &mut TcpStream {
        match self {
            UpstreamIo::Plain(s) => s,
            UpstreamIo::Tls(t) => &mut t.stream,
        }
    }

    /// Whether an HTTPS-proxy TLS handshake is still in progress.
    fn tls_handshaking(&self) -> bool {
        match self {
            UpstreamIo::Plain(_) => false,
            UpstreamIo::Tls(t) => t.conn.is_handshaking(),
        }
    }

    /// Drive the TLS state machine (no-op for a plaintext transport).
    fn pump_tls(&mut self) -> io::Result<()> {
        match self {
            UpstreamIo::Plain(_) => Ok(()),
            UpstreamIo::Tls(t) => t.pump(),
        }
    }

    /// Read plaintext (through the TLS session for an HTTPS proxy). `Ok(0)` = EOF.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            UpstreamIo::Plain(s) => s.read(buf),
            UpstreamIo::Tls(t) => {
                t.pump()?;
                match t.conn.reader().read(buf) {
                    Ok(n) => Ok(n),
                    // rustls signals "no plaintext yet" as WouldBlock and a peer
                    // close as UnexpectedEof; map the latter to a clean EOF.
                    Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Write plaintext (encrypted into the TLS session for an HTTPS proxy). The
    /// TLS writer buffers, so it accepts the whole slice; `pump` flushes records.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            UpstreamIo::Plain(s) => s.write(buf),
            UpstreamIo::Tls(t) => {
                // Flush queued records first; if the socket is still backed up,
                // refuse new plaintext (WouldBlock) so the caller retains it in
                // `to_upstream` instead of growing rustls's buffer without bound.
                t.pump()?;
                if t.conn.wants_write() {
                    return Err(io::Error::from(io::ErrorKind::WouldBlock));
                }
                let n = t.conn.writer().write(buf)?;
                t.pump()?;
                Ok(n)
            }
        }
    }

    /// Half-close the write side (sends TLS close_notify for an HTTPS proxy).
    fn shutdown_write(&mut self) -> io::Result<()> {
        match self {
            UpstreamIo::Plain(s) => s.shutdown(std::net::Shutdown::Write),
            UpstreamIo::Tls(t) => {
                t.conn.send_close_notify();
                let _ = t.pump();
                t.stream.shutdown(std::net::Shutdown::Write)
            }
        }
    }

    fn take_error(&mut self) -> io::Result<Option<io::Error>> {
        self.source().take_error()
    }
}

struct TcpUpstream {
    io: UpstreamIo,
    /// Proxy handshake in progress; `None` once the tunnel to `server` is open (or
    /// when no proxy is configured). While `Some`, app data is left buffered in the
    /// smoltcp socket and no relay/MITM runs.
    handshake: Option<Handshake>,
    /// Handshake bytes queued for the proxy but not yet flushed (socket backpressure).
    hs_out: Vec<u8>,
    token: Token,
    connecting: bool,
    /// Raw bytes queued for the upstream socket. For a MITM'd flow these are the
    /// client session's TLS records; otherwise the app's bytes verbatim.
    to_upstream: Vec<u8>,
    write_closed: bool,
    /// Present when this flow is being TLS-intercepted. When set, app bytes are
    /// fed through the splice instead of relayed raw.
    mitm: Option<TlsMitm>,
    /// Staging for MITM-produced TLS records bound for the app, drained into the
    /// smoltcp socket as its send window allows.
    to_app: Vec<u8>,
    /// Owning app UID and upstream address — retained so a leaf rejection can be
    /// attributed and remembered for the metadata-only fallback (P2-4).
    uid: i32,
    server: SocketAddr,
    /// Set once we've reported this flow as pinned, so the metadata-only event
    /// fires exactly once even though a failed splice stays closed across the
    /// several service passes before the flow is finally torn down.
    pin_reported: bool,
    /// Set once the cosmetic payload has been handed to the splice (P4-2), so we
    /// compute it from the engine exactly once, right after the SNI is learned.
    cosmetic_set: bool,
    /// Set once this flow's SNI has been surfaced to the live log, so the passive
    /// observer (log-open only) reports the host exactly once per flow.
    sni_reported: bool,
    /// Deferred DoH classification state (P3). `Settled` for every flow except a
    /// 443 flow under Filter mode, which peeks the SNI before deciding.
    classify: Classify,
    /// When the flow was opened (ms since `start`), used to fail a stuck proxy
    /// handshake closed after [`PROXY_HS_TIMEOUT_MS`] (P5).
    opened_ms: i64,
}

struct UdpSession {
    socket: UdpSocket,
    token: Token,
    app: SocketAddr,
    server: SocketAddr,
    last_used_ms: i64,
}

/// A SOCKS5 UDP ASSOCIATE session (P5, Stage 2): one per (app, server) pair, like
/// [`UdpSession`]. A control TCP connection to the proxy runs the ASSOCIATE
/// handshake and is then held open (the association lives only as long as it is);
/// a separate `protect()`ed relay UDP socket carries the encapsulated datagrams to
/// the proxy's relay endpoint. Fail-closed: any handshake/setup failure drops the
/// session and its buffered datagrams rather than leaking around the proxy.
struct Socks5UdpSession {
    /// Control connection; kept open for the association's lifetime.
    ctrl: TcpStream,
    ctrl_token: Token,
    /// True until the control socket's non-blocking connect completes.
    ctrl_connecting: bool,
    /// ASSOCIATE handshake; `Some` until it completes (then relaying begins).
    handshake: Option<Handshake>,
    /// Handshake bytes queued for the control socket (backpressure).
    hs_out: Vec<u8>,
    /// Relay socket, connected to the relay endpoint once the reply arrives.
    relay: UdpSocket,
    relay_token: Token,
    /// The app source (reply destination).
    app: SocketAddr,
    /// The address replies appear to come from — what the app targeted (e.g. the
    /// DNS placeholder), which may differ from the real encapsulation `target`.
    reply_src: SocketAddr,
    /// The real destination datagrams are encapsulated toward (e.g. the upstream
    /// resolver for a DNS flow, or the origin server otherwise).
    target: SocketAddr,
    /// Datagrams buffered until the association is ready; capped.
    pending: Vec<Vec<u8>>,
    ready: bool,
    last_used_ms: i64,
}

/// Cap on datagrams buffered while a SOCKS5 UDP association is still handshaking.
const SOCKS_UDP_PENDING_CAP: usize = 8;

/// A one-shot DNS-over-TCP query relayed through an HTTP/HTTPS proxy (P5): dial
/// the proxy, CONNECT to the resolver, send the length-prefixed query, read the
/// length-prefixed response, inject it back to the app, done. Used for HTTP/HTTPS
/// proxies (which can't carry UDP) when "resolve DNS through the proxy" is on; a
/// SOCKS5 proxy uses UDP ASSOCIATE instead. Per-query (Option A) — simple and
/// leak-free, at the cost of a proxy handshake per lookup.
struct DnsTcpJob {
    /// Transport to the proxy (plain, or TLS for an HTTPS proxy).
    io: UpstreamIo,
    /// True until the non-blocking connect to the proxy completes.
    connecting: bool,
    /// CONNECT/handshake to the resolver; `None` once the tunnel is open.
    handshake: Option<Handshake>,
    hs_out: Vec<u8>,
    /// The 2-byte-length-prefixed query, drained as it is written.
    to_send: Vec<u8>,
    query_sent: bool,
    /// Accumulates the length-prefixed response until a full message is present.
    resp_buf: Vec<u8>,
    /// The app to answer, and the address the answer appears to come from (the
    /// tunnel-local DNS placeholder the app targeted).
    app: SocketAddr,
    reply_src: SocketAddr,
    /// For timeout reaping.
    created_ms: i64,
}

/// Cap on concurrent in-flight DNS-over-TCP jobs; excess queries are dropped
/// (the app's resolver retries). Bounds sockets during a burst of lookups.
const DNS_TCP_MAX_JOBS: usize = 64;
/// A DNS-over-TCP job that hasn't answered within this is reaped (fail-closed).
const DNS_TCP_TIMEOUT_MS: i64 = 5_000;

/// Allowed-flow telemetry coalesced over one flush window while the live log is
/// closed and no app is engaged (P3-4). Drained into a single [`Event::coarse`]
/// per flush instead of one [`Event::flow`] per packet.
#[derive(Default, Clone, Copy)]
struct CoarseAccum {
    packets: u64,
    bytes: u64,
    tcp: u64,
    udp: u64,
    dns: u64,
}

/// Rolling datapath counters, logged as a heartbeat to diagnose stalls.
#[derive(Default, Clone, Copy)]
pub struct ForwarderStats {
    pub tun_in: u64,
    pub tcp_new: u64,
    pub udp_new: u64,
    pub protect_ok: u64,
    pub protect_fail: u64,
    pub connect_fail: u64,
    pub upstream_reply: u64,
    pub out_written: u64,
    pub uid_lookups: u64,
    pub blocked: u64,
    pub mitm_new: u64,
    pub pinned: u64,
    pub proxy_ok: u64,
    pub proxy_fail: u64,
}

pub struct Forwarder {
    stack: NetStack,
    registry: Registry,
    tcp: HashMap<FlowId, TcpUpstream>,
    udp: HashMap<UdpKey, UdpSession>,
    /// SOCKS5 UDP ASSOCIATE sessions, used instead of `udp` when the proxy is
    /// SOCKS5 (P5, Stage 2).
    socks_udp: HashMap<UdpKey, Socks5UdpSession>,
    /// In-flight DNS-over-TCP jobs, keyed by their socket token (P5): DNS routed
    /// through an HTTP/HTTPS proxy when `proxy_dns_over_tcp` is on.
    dns_tcp: HashMap<Token, DnsTcpJob>,
    routes: HashMap<Token, Route>,
    next_token: usize,
    outbox: Vec<Vec<u8>>,
    start: StdInstant,
    engine: Option<FilterEngine>,
    encrypted_dns_mode: EncryptedDnsMode,
    firewall: HashMap<i32, AppPolicy>,
    transport: u8,
    verdicts: FlowTable<Verdict>,
    pcap: Option<PcapWriter<File>>,
    dns_upstream_v4: IpAddr,
    dns_upstream_v6: IpAddr,
    /// Upstream proxy (P5): when `Some`, TCP flows are dialed through it (HTTP/
    /// HTTPS CONNECT or SOCKS5) instead of the origin. `None` = direct (today's
    /// behavior). A start-time setting, fixed for the session.
    proxy: Option<Proxy>,
    /// A proxy is configured but couldn't be set up (bad/unresolvable address).
    /// When true, all forwarding fails closed (blocked) so nothing leaks around
    /// the intended proxy. Mutually exclusive with `proxy` being `Some`.
    proxy_broken: bool,
    /// Route DNS through the proxy via DNS-over-TCP (P5); live-updatable. For an
    /// HTTP/HTTPS proxy this replaces direct DNS; for a SOCKS5 proxy it replaces
    /// UDP ASSOCIATE for DNS (non-DNS UDP still uses ASSOCIATE).
    proxy_dns_over_tcp: bool,
    /// Learned at runtime: the configured SOCKS5 proxy refused/failed UDP
    /// ASSOCIATE (most free SOCKS5 proxies are TCP-only). Once set, DNS falls back
    /// to DNS-over-TCP through the proxy so name resolution keeps working — without
    /// it, all DNS would fail closed. Reset on reconnect (a fresh `Forwarder`).
    socks_udp_unsupported: bool,
    /// Prebuilt rustls configs; `Some` when TLS interception is on (P2).
    tls: Option<MitmConfigs>,
    /// Decrypted HTTP transactions captured this session, drained on HAR export.
    har: Vec<HttpTransaction>,
    /// (app UID, server IP) pairs whose leaf the app rejected (pinning). Future
    /// flows to these relay raw instead of re-breaking the app (P2-4).
    pinned: HashSet<(i32, IpAddr)>,
    stats: ForwarderStats,
    /// Whether the live log / a capture is open (P3-4). Gates the fast-path:
    /// while false, allowed flows of non-engaged apps are coalesced into coarse
    /// aggregates instead of per-flow events. Enforcement is unaffected.
    log_open: bool,
    /// Coarse allowed-flow telemetry accumulated this flush window (P3-4).
    coarse: CoarseAccum,
    /// Cosmetic element hiding on (P4): inject hostname CSS into `text/html` on
    /// inspected flows. Applies to every inspected app.
    cosmetic_element_hiding: bool,
    /// Cosmetic scriptlet injection on (P4): requires element hiding + a loaded pack.
    cosmetic_scriptlets: bool,
}

const PCAP_SNAPLEN: u32 = 65_535;
const DEFAULT_DNS_V4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const DEFAULT_DNS_V6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);

/// A cached per-flow firewall decision.
#[derive(Clone, Copy)]
struct Verdict {
    blocked: bool,
    uid: i32,
}

impl Forwarder {
    pub fn new(config: &Config, registry: Registry) -> Self {
        let (dns_v4, dns_v6) = parse_dns_upstreams(&config.dns_servers);
        let (proxy_active, proxy_broken) = build_proxy(config);
        Forwarder {
            stack: NetStack::new(config.mtu),
            registry,
            tcp: HashMap::new(),
            udp: HashMap::new(),
            socks_udp: HashMap::new(),
            dns_tcp: HashMap::new(),
            routes: HashMap::new(),
            next_token: FIRST_DYNAMIC_TOKEN,
            outbox: Vec::new(),
            start: StdInstant::now(),
            engine: None,
            encrypted_dns_mode: config.encrypted_dns_mode,
            firewall: HashMap::new(),
            transport: TRANSPORT_OTHER,
            verdicts: FlowTable::new(VERDICT_CACHE_CAP),
            pcap: None,
            dns_upstream_v4: dns_v4,
            dns_upstream_v6: dns_v6,
            proxy: proxy_active,
            proxy_broken,
            proxy_dns_over_tcp: config.proxy_dns_over_tcp,
            socks_udp_unsupported: false,
            tls: build_tls_factory(config),
            har: Vec::new(),
            pinned: HashSet::new(),
            stats: ForwarderStats::default(),
            log_open: config.log_open,
            coarse: CoarseAccum::default(),
            cosmetic_element_hiding: config.cosmetic_element_hiding,
            cosmetic_scriptlets: config.cosmetic_scriptlets,
        }
    }

    /// Read and reset the rolling datapath counters (for the heartbeat log).
    pub fn take_stats(&mut self) -> ForwarderStats {
        std::mem::take(&mut self.stats)
    }

    pub fn flow_counts(&self) -> (usize, usize) {
        (self.tcp.len(), self.udp.len() + self.socks_udp.len())
    }

    /// Start a pcapng capture writing to `fd` (owned henceforth). `ring_bytes` of
    /// 0 means unbounded.
    pub fn start_pcap(&mut self, fd: RawFd, ring_bytes: u64) {
        let file = unsafe { File::from_raw_fd(fd) };
        let cap = if ring_bytes > 0 { Some(ring_bytes) } else { None };
        self.pcap = PcapWriter::new(file, PCAP_SNAPLEN, cap).ok();
    }

    /// Stop the capture and close its file.
    pub fn stop_pcap(&mut self) {
        self.pcap = None;
    }

    /// Write the decrypted HTTP transactions captured so far as a HAR 1.2 file to
    /// `fd` (owned henceforth, closed when written). The buffer is retained, so a
    /// later export includes this session's full history. Runs on the datapath
    /// thread, so it briefly pauses forwarding — acceptable, like pcap I/O.
    pub fn export_har(&self, fd: RawFd) {
        let mut file = unsafe { File::from_raw_fd(fd) };
        if let Err(e) = write_har(&mut file, &self.har) {
            crate::alog!("HAR export failed: {e}");
        }
        // `file` drops here, closing the fd.
    }

    /// Number of HAR transactions buffered (for the heartbeat log).
    pub fn har_len(&self) -> usize {
        self.har.len()
    }

    /// Write a packet to the capture, if one is active.
    fn tap(&mut self, packet: &[u8]) {
        if let Some(writer) = self.pcap.as_mut() {
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
            let _ = writer.write_packet(ts, packet);
        }
    }

    /// Load (or replace) the filter engine from its serialized cache file,
    /// optionally applying a scriptlet resource pack (P4-3). The pack lives outside
    /// the cache (resources aren't serialized), so it is re-read on each load.
    pub fn load_engine(&mut self, path: &str, resources_path: Option<&str>) {
        if let Ok(bytes) = std::fs::read(path) {
            let resources = resources_path.and_then(|p| std::fs::read_to_string(p).ok());
            self.engine = FilterEngine::from_serialized_with_resources(&bytes, resources.as_deref());
        }
    }

    pub fn set_encrypted_dns_mode(&mut self, mode: EncryptedDnsMode) {
        self.encrypted_dns_mode = mode;
    }

    /// Replace the per-app firewall rules. Verdict cache is cleared so new rules
    /// take effect on the next packet of each flow.
    pub fn set_firewall(&mut self, rules: HashMap<i32, AppPolicy>) {
        self.firewall = rules;
        self.verdicts = FlowTable::new(VERDICT_CACHE_CAP);
    }

    pub fn set_transport(&mut self, transport: u8) {
        if transport != self.transport {
            self.transport = transport;
            self.verdicts = FlowTable::new(VERDICT_CACHE_CAP);
        }
    }

    /// Toggle the live-log-open flag (P3-4). Flipping it on takes effect on the
    /// next packet; the datapath thread's flush/heartbeat cadence ramps back to
    /// full immediately (the command that carries this also wakes the poll).
    pub fn set_log_open(&mut self, open: bool) {
        self.log_open = open;
    }

    /// Set the cosmetic-filtering mode (P4). Takes effect on flows opened after
    /// this; live flows keep the payload they were provisioned with (one host per
    /// splice). Enforcement and the fast-path are unaffected.
    pub fn set_cosmetic(&mut self, element_hiding: bool, scriptlets: bool) {
        self.cosmetic_element_hiding = element_hiding;
        self.cosmetic_scriptlets = scriptlets;
    }

    /// Toggle DNS-over-TCP-through-proxy live (P5). Takes effect on the next DNS
    /// query; in-flight jobs finish as they are.
    pub fn set_proxy_dns_over_tcp(&mut self, on: bool) {
        self.proxy_dns_over_tcp = on;
    }

    /// Hand the cosmetic payload to a splice once its SNI host is known (P4-2).
    /// Computes CSS/JS from the engine here so `rust/tls` needs no filter
    /// dependency; called exactly once per flow (guarded by `cosmetic_set`).
    /// Always sets a payload once the host is known — empty (a no-op passthrough)
    /// when the engine is absent or the feature is off — so the rewriter, which
    /// holds nothing until provisioned, is never left waiting.
    fn provision_cosmetics(&mut self, id: FlowId) {
        let host = match self.tcp.get(&id) {
            Some(up) if !up.cosmetic_set => match up.mitm.as_ref().and_then(|m| m.host()) {
                Some(h) => h.to_string(),
                None => return, // SNI not learned yet; retry next pump
            },
            _ => return,
        };
        let (css, js) = match self.engine.as_ref() {
            Some(engine) if self.cosmetic_element_hiding => {
                let css = engine.cosmetic_css(&host);
                let js = if self.cosmetic_scriptlets { engine.scriptlets_js(&host) } else { String::new() };
                (css, js)
            }
            _ => (String::new(), String::new()),
        };
        if let Some(up) = self.tcp.get_mut(&id) {
            if let Some(mitm) = up.mitm.as_mut() {
                mitm.set_cosmetic(css, js);
            }
            up.cosmetic_set = true;
        }
    }

    /// Whether an allowed flow owned by `uid` should be coalesced into the coarse
    /// aggregate rather than surfaced as its own event (P3-4). True only when the
    /// live log is closed AND the app isn't engaged (has no non-default rule).
    /// Enforcement (verdict/DNS/RST) is decided elsewhere and never gated by this.
    fn coarse_mode(&self, uid: i32) -> bool {
        !self.log_open && !self.firewall.contains_key(&uid)
    }

    /// Whether telemetry should run at full cadence: the log is open, or at least
    /// one app is engaged (so per-flow events are being produced and watched).
    /// When false the datapath relaxes its flush/heartbeat timers (P3-4).
    pub fn telemetry_hot(&self) -> bool {
        self.log_open || !self.firewall.is_empty()
    }

    /// Fold one coalesced allowed packet into the coarse window.
    fn coarse_add(&mut self, len: u32, proto: L4, is_dns: bool) {
        self.coarse.packets += 1;
        self.coarse.bytes += len as u64;
        match proto {
            L4::Tcp => self.coarse.tcp += 1,
            L4::Udp => self.coarse.udp += 1,
            _ => {}
        }
        if is_dns {
            self.coarse.dns += 1;
        }
    }

    /// Take the accumulated coarse window as a single event, or `None` if empty.
    /// Called by the datapath loop just before each batch flush (P3-4).
    pub fn take_coarse(&mut self) -> Option<Event> {
        if self.coarse.packets == 0 {
            return None;
        }
        let c = std::mem::take(&mut self.coarse);
        let cap = |v: u64| v.min(u32::MAX as u64) as u32;
        Some(Event::coarse(cap(c.packets), c.bytes, cap(c.tcp), cap(c.udp), cap(c.dns)))
    }

    /// Resolve (and cache) the firewall verdict for a flow. Unknown UIDs and
    /// unruled apps are allowed.
    fn verdict(&mut self, decoded: &Decoded, proto: i32, env: &mut jni::JNIEnv, bridge: &Bridge) -> Verdict {
        // No per-app rules -> normally allow everything without the (per-flow,
        // binder) getConnectionOwnerUid upcall, keeping DNS/browsing off the JNI
        // path entirely in the common case. But while the live log is open we
        // still resolve the owning app so the traffic view can attribute flows;
        // policy_blocks() returns false for an unruled app, so this never changes
        // the allow/block decision — only the reported uid.
        if self.firewall.is_empty() && !self.log_open {
            return Verdict { blocked: false, uid: -1 };
        }
        let key = FlowKey::new(proto as u8, decoded.src, decoded.src_port, decoded.dst, decoded.dst_port);
        if let Some(cached) = self.verdicts.get(&key) {
            return *cached;
        }
        self.stats.uid_lookups += 1;
        let uid = bridge.lookup_uid(
            env,
            proto,
            std::net::SocketAddr::new(decoded.src, decoded.src_port),
            std::net::SocketAddr::new(decoded.dst, decoded.dst_port),
        );
        let blocked = self.policy_blocks(uid);
        if blocked {
            self.stats.blocked += 1;
        }
        let verdict = Verdict { blocked, uid };
        self.verdicts.insert(key, verdict);
        verdict
    }

    fn policy_blocks(&self, uid: i32) -> bool {
        if uid < 0 {
            return false; // unattributable -> allow
        }
        match self.firewall.get(&uid) {
            Some(policy) => match self.transport {
                TRANSPORT_WIFI => !policy.allow_wifi,
                TRANSPORT_CELLULAR => !policy.allow_cellular,
                _ => false,
            },
            None => false,
        }
    }

    /// Whether the app owning `uid` opted its HTTPS into TLS interception.
    /// Unattributable flows (uid < 0) are never intercepted.
    fn app_inspects(&self, uid: i32) -> bool {
        uid >= 0 && self.firewall.get(&uid).map_or(false, |p| p.inspect_tls)
    }

    /// Whether an encrypted-DNS (DoT/DoH) flow to `server` can be TLS-intercepted:
    /// the CA is loaded and this (app, server) hasn't already rejected our leaf.
    /// Unlike [`app_inspects`](Self::app_inspects), encrypted-DNS interception is
    /// auto-detected for every app (not opt-in). When this is false under Filter
    /// mode the flow is dropped, not relayed raw — fail closed.
    fn can_intercept_enc_dns(&self, uid: i32, server: IpAddr) -> bool {
        self.tls.is_some() && !(uid >= 0 && self.pinned.contains(&(uid, server)))
    }

    fn now_ms(&self) -> i64 {
        self.start.elapsed().as_millis() as i64
    }

    fn alloc_token(&mut self) -> Token {
        let t = Token(self.next_token);
        self.next_token += 1;
        t
    }

    pub fn take_outbox(&mut self) -> Vec<Vec<u8>> {
        let outbox = std::mem::take(&mut self.outbox);
        self.stats.out_written += outbox.len() as u64;
        // Drain the MITM key log every pass so its buffer can't grow unbounded;
        // fold it into an active capture (as a DSB) ahead of this pass's packets
        // so Wireshark has the secrets before the records they decrypt (P2-4).
        if let Some(tls) = self.tls.as_ref() {
            let secrets = tls.take_key_log();
            if !secrets.is_empty() {
                if let Some(writer) = self.pcap.as_mut() {
                    let _ = writer.write_tls_secrets(&secrets);
                }
            }
        }
        if self.pcap.is_some() {
            for packet in &outbox {
                self.tap(packet);
            }
        }
        outbox
    }

    /// Suggested poll timeout: the sooner of smoltcp's need and a UDP-reap tick.
    pub fn poll_timeout_ms(&mut self) -> u64 {
        let now = self.now_ms();
        self.stack
            .poll_delay(now)
            .map(|d| d.total_millis())
            .unwrap_or(1_000)
            .min(1_000)
    }

    /// A packet was read off the TUN. Route it for forwarding, emitting exactly
    /// one event describing what happened to it.
    pub fn on_tun_packet(&mut self, packet: &[u8], env: &mut jni::JNIEnv, bridge: &Bridge, batcher: &mut Batcher) {
        self.stats.tun_in += 1;
        self.tap(packet); // capture every inbound packet, whatever its verdict
        let Some(decoded) = adwarden_netstack::decode(packet) else { return };
        match decoded.proto {
            L4::Tcp => {
                let verdict = self.verdict(&decoded, PROTO_TCP, env, bridge);
                if verdict.blocked {
                    // RST the app so it fails fast instead of timing out.
                    if let Some(rst) = reset_for_syn(packet) {
                        self.outbox.push(rst);
                    }
                    batcher.push(Event::blocked(&decoded).with_uid(verdict.uid));
                    return;
                }
                // Fail closed: a configured-but-unusable proxy (P5) blocks all
                // forwarding rather than leaking around it. RST so the app fails fast.
                if self.proxy_broken {
                    if let Some(rst) = reset_for_syn(packet) {
                        self.outbox.push(rst);
                    }
                    batcher.push(Event::blocked(&decoded).with_uid(verdict.uid));
                    return;
                }
                // DoT (TLS/853): off = relay raw; block = drop; filter = intercept
                // when we can, else drop (fail closed — never leak it unfiltered).
                if decoded.dst_port == DOT_PORT {
                    let intercept = self.encrypted_dns_mode == EncryptedDnsMode::Filter
                        && self.can_intercept_enc_dns(verdict.uid, decoded.dst);
                    if self.encrypted_dns_mode != EncryptedDnsMode::Off && !intercept {
                        if let Some(rst) = reset_for_syn(packet) {
                            self.outbox.push(rst);
                        }
                        batcher.push(Event::blocked(&decoded).with_uid(verdict.uid));
                        return;
                    }
                }
                if self.coarse_mode(verdict.uid) {
                    self.coarse_add(decoded.length, L4::Tcp, false);
                } else {
                    batcher.push(Event::flow(&decoded).with_uid(verdict.uid));
                }
                if let Some((id, server)) = self.stack.on_tcp_packet(packet) {
                    self.open_tcp(id, server, verdict.uid, env, bridge);
                }
            }
            L4::Udp => {
                // Encrypted DNS over QUIC can't be intercepted (no QUIC stack) and
                // its SNI is hidden, so under Block or Filter we suppress it to
                // force the interceptable TCP fallback: DoQ (UDP/853) always, and
                // DoH3 (UDP/443) to known resolver IPs.
                if self.encrypted_dns_mode != EncryptedDnsMode::Off
                    && (decoded.dst_port == DOT_PORT
                        || (decoded.dst_port == HTTPS_PORT
                            && adwarden_dns::is_known_doh_ip(decoded.dst)))
                {
                    batcher.push(Event::blocked(&decoded));
                    return;
                }
                let verdict = self.verdict(&decoded, PROTO_UDP, env, bridge);
                if verdict.blocked {
                    batcher.push(Event::blocked(&decoded).with_uid(verdict.uid));
                    return; // firewall drop (covers this app's DNS too)
                }
                // Fail closed: a configured-but-unusable proxy (P5) drops all UDP
                // (incl. DNS) rather than leaking around it.
                if self.proxy_broken {
                    batcher.push(Event::blocked(&decoded).with_uid(verdict.uid));
                    return;
                }
                // Upstream proxy (P5): a SOCKS5 proxy carries all UDP via UDP
                // ASSOCIATE; an HTTP/HTTPS proxy can't carry UDP, so its non-DNS UDP
                // is dropped fail-closed (QUIC then falls back to proxied TCP). DNS
                // to an HTTP/HTTPS proxy follows the `proxy_dns_over_tcp` switch:
                // DNS-over-TCP through the proxy when on, else resolved directly.
                let proxy_udp = self.proxy.as_ref().map(|p| p.supports_udp());
                let is_dns = decoded.dst_port == 53 || decoded.dst_port == 5353;
                if proxy_udp == Some(false) && !is_dns {
                    batcher.push(Event::blocked(&decoded).with_uid(verdict.uid));
                    return;
                }
                // QUIC suppression (P4-5): when cosmetics are on, drop UDP :443 for
                // inspected apps so they fall back to TCP+TLS — the no-ALPN H1
                // downgrade the rewriter needs to see HTML. Without this, HTTP/3
                // bypasses the TCP MITM entirely and cosmetics silently don't apply.
                if self.cosmetic_element_hiding
                    && decoded.dst_port == HTTPS_PORT
                    && self.app_inspects(verdict.uid)
                {
                    batcher.push(Event::blocked(&decoded).with_uid(verdict.uid));
                    return;
                }
                if let Some(dgram) = udp::parse(packet) {
                    // For DNS, learn the query name up front (and sinkhole blocked
                    // names) so the allowed flow event can carry the decoded domain.
                    let dns_name = if is_dns {
                        match self.handle_dns(&decoded, &dgram, batcher) {
                            DnsOutcome::Sinkholed => return, // NXDOMAIN already injected
                            DnsOutcome::Forward(name) => name,
                        }
                    } else {
                        None
                    };
                    if self.coarse_mode(verdict.uid) {
                        self.coarse_add(decoded.length, L4::Udp, is_dns);
                    } else {
                        batcher.push(
                            Event::flow(&decoded).with_uid(verdict.uid).with_domain(dns_name),
                        );
                    }
                    // Allowed DNS goes to the real upstream (the app targeted a
                    // tunnel-local placeholder); everything else keeps its dst.
                    let upstream = if is_dns {
                        self.dns_upstream(dgram.dst)
                    } else {
                        dgram.dst
                    };
                    // A SOCKS5 proxy relays UDP via ASSOCIATE — except DNS falls
                    // back to DNS-over-TCP (CONNECT resolver:53) when the switch is
                    // on or we've learned this proxy refuses ASSOCIATE, so DNS still
                    // resolves on the many SOCKS5 proxies that are TCP-only. For an
                    // HTTP/HTTPS proxy, DNS goes over DNS-over-TCP when the switch is
                    // on (else direct). Everything else goes direct.
                    if proxy_udp == Some(true) {
                        if is_dns && (self.proxy_dns_over_tcp || self.socks_udp_unsupported) {
                            self.forward_dns_over_proxy(dgram, upstream, env, bridge);
                        } else {
                            self.forward_udp_socks(dgram, upstream, env, bridge);
                        }
                    } else if is_dns && self.proxy.is_some() && self.proxy_dns_over_tcp {
                        self.forward_dns_over_proxy(dgram, upstream, env, bridge);
                    } else {
                        self.forward_udp(dgram, upstream, env, bridge);
                    }
                } else if self.coarse_mode(verdict.uid) {
                    self.coarse_add(decoded.length, L4::Udp, is_dns);
                } else {
                    batcher.push(Event::flow(&decoded).with_uid(verdict.uid));
                }
            }
            _ => {
                // ICMP / other: logged, dropped. No uid attribution, so it's
                // coalesced whenever the log is closed (coarse_mode(-1)).
                if self.coarse_mode(-1) {
                    self.coarse_add(decoded.length, decoded.proto, false);
                } else {
                    batcher.push(Event::flow(&decoded));
                }
            }
        }
    }

    /// Intercept a DNS query: if the engine blocks the name, inject an NXDOMAIN
    /// response toward the app and report a block ([`DnsOutcome::Sinkholed`]).
    /// Otherwise return [`DnsOutcome::Forward`] carrying the decoded query name
    /// (when it parsed) so the allowed flow event can surface the domain.
    fn handle_dns(
        &mut self,
        decoded: &Decoded,
        dgram: &udp::UdpDatagram,
        batcher: &mut Batcher,
    ) -> DnsOutcome {
        let Some(query) = adwarden_dns::parse_query(&dgram.payload) else {
            return DnsOutcome::Forward(None);
        };
        let blocked = self
            .engine
            .as_ref()
            .map_or(false, |engine| engine.is_blocked_domain(&query.name));
        if !blocked {
            return DnsOutcome::Forward(Some(query.name));
        }
        let response = adwarden_dns::synthesize_nxdomain(&dgram.payload, &query);
        if let Some(packet) = udp::build_reply(dgram.dst, dgram.src, &response) {
            self.outbox.push(packet);
        }
        batcher.push(Event::blocked_domain(decoded, query.name));
        DnsOutcome::Sinkholed
    }

    /// Advance the stack and pump both directions of every flow.
    pub fn service(&mut self, _env: &mut jni::JNIEnv, _bridge: &Bridge, batcher: &mut Batcher) {
        let now = self.now_ms();
        let outcome = self.stack.poll(now);
        for id in outcome.closed {
            self.teardown_tcp(id);
            self.stack.remove_flow(id);
        }

        // App -> upstream for each active flow.
        for id in self.stack.active_flows() {
            // Defer all relay until the upstream tunnel is open: while dialing or
            // running the proxy handshake, leave app data in the smoltcp socket
            // (its window backpressures the app) rather than draining it.
            match self.tcp.get(&id).map(|up| (up.connecting, up.handshake.is_some())) {
                Some((true, _)) => continue,
                Some((false, true)) => {
                    self.drive_proxy_handshake(id, batcher);
                    continue;
                }
                _ => {}
            }
            let data = self.stack.tcp_take_app_data(id);
            let pending = matches!(
                self.tcp.get(&id).map(|up| &up.classify),
                Some(Classify::PendingSni(_))
            );
            if pending {
                // A 443 flow still awaiting its SNI: buffer + try to classify.
                self.classify_pending(id, &data, batcher);
                self.flush_to_upstream(id);
                self.flush_to_app(id);
                continue;
            }
            let is_mitm = self.tcp.get(&id).map_or(false, |up| up.mitm.is_some());
            if is_mitm {
                if !data.is_empty() {
                    if let Some(up) = self.tcp.get_mut(&id) {
                        if let Some(mitm) = up.mitm.as_mut() {
                            mitm.recv_from_app(&data);
                        }
                    }
                }
                // Always drive: handshakes and buffered plaintext make progress
                // even when the app sent nothing this pass.
                self.drive_mitm(id, batcher);
            } else if !data.is_empty() {
                // Raw relay. While the live log is open, passively peek the SNI so
                // the traffic view can name an otherwise IP-only HTTPS flow. The
                // bytes are relayed unchanged below — pure observation, so this
                // never affects filtering or forwarding.
                if self.log_open {
                    self.observe_sni(id, &data, batcher);
                }
                if let Some(up) = self.tcp.get_mut(&id) {
                    up.to_upstream.extend_from_slice(&data);
                }
            }
            self.flush_to_upstream(id);
            self.flush_to_app(id);
            // Propagate the app's half-close once its data is drained — but
            // never while the upstream connect is still in flight: shutdown()
            // on a SYN_SENT socket is tcp_disconnect() in the kernel and
            // latches ECONNRESET. The check re-runs every service pass, so the
            // FIN propagates as soon as the connect completes. For a MITM'd flow
            // the splice's close_notify already sits in `to_upstream`.
            if self.stack.tcp_app_finished(id) {
                if let Some(up) = self.tcp.get_mut(&id) {
                    if up.to_upstream.is_empty() && !up.write_closed && !up.connecting {
                        let _ = up.io.shutdown_write();
                        up.write_closed = true;
                    }
                }
            }
        }

        self.reap_udp(now);
        self.reap_socks(now);
        self.reap_dns_tcp(now);
        self.reap_proxy_handshakes(now, batcher);
        self.drain_stack_outbound();
    }

    fn drain_stack_outbound(&mut self) {
        let outbox = &mut self.outbox;
        self.stack.drain_outbound(|packet| outbox.push(packet.to_vec()));
    }

    /// mio readiness for an upstream socket.
    pub fn on_ready(&mut self, token: Token, event: &mio::event::Event, batcher: &mut Batcher) {
        match self.routes.get(&token) {
            Some(Route::Tcp(id)) => {
                let id = *id;
                if event.is_writable() {
                    let was_connecting = self.tcp.get(&id).map_or(false, |up| up.connecting);
                    if was_connecting {
                        // A non-blocking connect that failed still reports
                        // writable, with the error latched on the socket.
                        let err = self
                            .tcp
                            .get_mut(&id)
                            .and_then(|up| up.io.take_error().ok().flatten());
                        if let Some(up) = self.tcp.get_mut(&id) {
                            up.connecting = false;
                        }
                        if err.is_some() {
                            self.stats.connect_fail += 1;
                            self.stack.tcp_abort(id);
                            return;
                        }
                    }
                }
                // While the proxy handshake runs, drive it and defer all relay: no
                // app data flows upstream until the tunnel to `server` is open.
                if self.tcp.get(&id).map_or(false, |up| up.handshake.is_some()) {
                    self.drive_proxy_handshake(id, batcher);
                    return;
                }
                if event.is_writable() {
                    self.flush_to_upstream(id);
                }
                let is_mitm = self.tcp.get(&id).map_or(false, |up| up.mitm.is_some());
                if event.is_readable() {
                    if is_mitm {
                        self.read_upstream_into_mitm(id);
                        self.drive_mitm(id, batcher);
                        self.flush_to_app(id);
                    } else {
                        self.pump_upstream_to_app(id);
                    }
                }
                if event.is_read_closed() || event.is_write_closed() {
                    if is_mitm {
                        self.read_upstream_into_mitm(id);
                        self.drive_mitm(id, batcher);
                        self.flush_to_app(id);
                    } else {
                        self.pump_upstream_to_app(id);
                    }
                    self.stack.tcp_close_app(id);
                }
            }
            Some(Route::Udp(key)) => {
                let key = *key;
                self.pump_udp_reply(key, batcher);
            }
            Some(Route::SocksCtrl(key)) => {
                let key = *key;
                if self.socks_udp.get(&key).map_or(false, |s| s.handshake.is_some()) {
                    self.drive_socks_ctrl(key);
                } else if event.is_read_closed() || event.is_write_closed() {
                    // The control connection dropped ⇒ the association is dead.
                    self.teardown_socks(key);
                }
            }
            Some(Route::SocksRelay(key)) => {
                let key = *key;
                if event.is_readable() {
                    self.pump_socks_relay(key);
                }
            }
            Some(Route::DnsTcp) => self.drive_dns_tcp(token),
            None => {}
        }
    }

    // --- TCP -------------------------------------------------------------

    fn open_tcp(&mut self, id: FlowId, server: SocketAddr, uid: i32, env: &mut jni::JNIEnv, bridge: &Bridge) {
        // A 443 flow under Filter mode defers its decision until the ClientHello
        // reveals the SNI (DoH is auto-detected across all apps, by SNI).
        let defer = self.encrypted_dns_mode == EncryptedDnsMode::Filter
            && server.port() == HTTPS_PORT;
        // Otherwise decide now: an encrypted-DNS flow we meant to filter but
        // couldn't get a splice for must be dropped, not relayed raw.
        let mitm = if defer { None } else { self.new_mitm_if_intercepting(server, uid) };
        if !defer && mitm.is_none() && self.requires_enc_dns_intercept(server) {
            self.stack.tcp_abort(id);
            return;
        }
        let classify = if defer { Classify::PendingSni(Vec::new()) } else { Classify::Settled };
        match self.connect_tcp(server, env, bridge) {
            Some((io, token)) => {
                self.stats.tcp_new += 1;
                // With a proxy, dial through it: attach a handshake targeting the
                // real `server`, run before any relay/MITM begins.
                let handshake = self.proxy.as_ref().map(|p| Handshake::connect(p, server));
                self.routes.insert(token, Route::Tcp(id));
                self.tcp.insert(
                    id,
                    TcpUpstream {
                        io,
                        handshake,
                        hs_out: Vec::new(),
                        token,
                        connecting: true,
                        to_upstream: Vec::new(),
                        write_closed: false,
                        mitm,
                        to_app: Vec::new(),
                        uid,
                        server,
                        pin_reported: false,
                        cosmetic_set: false,
                        sni_reported: false,
                        classify,
                        opened_ms: self.now_ms(),
                    },
                );
            }
            None => {
                // Couldn't reach upstream: RST the app so it fails fast.
                self.stats.connect_fail += 1;
                self.stack.tcp_abort(id);
            }
        }
    }

    /// Whether a flow to `server` is an encrypted-DNS flow the datapath is meant
    /// to intercept under Filter mode (drives the fail-closed drop in `open_tcp`).
    fn requires_enc_dns_intercept(&self, server: SocketAddr) -> bool {
        self.encrypted_dns_mode == EncryptedDnsMode::Filter && server.port() == DOT_PORT
    }

    /// Start a TLS interception splice for this flow, or `None` (raw relay) when
    /// it shouldn't be intercepted. Two triggers:
    ///  - encrypted DNS (DoT/853) under Filter mode — auto-detected for every app;
    ///  - HTTPS (443) for apps that opted into inspection (cosmetics/HAR, P2/P4).
    fn new_mitm_if_intercepting(&mut self, server: SocketAddr, uid: i32) -> Option<TlsMitm> {
        // Encrypted DNS: DoT filtering. The caller (`on_tun_packet`) has already
        // dropped flows we can't intercept, so a splice failure here is rare.
        if self.requires_enc_dns_intercept(server) {
            if uid >= 0 && self.pinned.contains(&(uid, server.ip())) {
                return None;
            }
            let splice = self.tls.as_ref()?.new_splice_dns(DnsKind::Dot);
            return match splice {
                Ok(mitm) => {
                    self.stats.mitm_new += 1;
                    Some(mitm)
                }
                Err(e) => {
                    crate::alog!("DoT TlsMitm::new failed ({e}); dropping {}", server);
                    None
                }
            };
        }
        if server.port() != HTTPS_PORT || !self.app_inspects(uid) {
            return None;
        }
        // This app already rejected our leaf for this server: relay raw so it
        // keeps working (metadata-only) instead of breaking it again (P2-4).
        if self.pinned.contains(&(uid, server.ip())) {
            return None;
        }
        let splice = self.tls.as_ref()?.new_splice();
        match splice {
            Ok(mitm) => {
                self.stats.mitm_new += 1;
                Some(mitm)
            }
            Err(e) => {
                crate::alog!("TlsMitm::new failed ({e}); relaying {} raw", server);
                None
            }
        }
    }

    /// A deferred 443 flow (Filter mode) received app bytes: buffer them, and once
    /// the ClientHello reveals the SNI, classify the flow as DoH (filter),
    /// cosmetic (inspected app), or raw — then replay the buffered bytes.
    fn classify_pending(&mut self, id: FlowId, data: &[u8], batcher: &mut Batcher) {
        // Buffer + peek (holding the flow's borrow briefly).
        let (sni, over_cap, buffered, uid, server) = {
            let Some(up) = self.tcp.get_mut(&id) else { return };
            let Classify::PendingSni(buf) = &mut up.classify else { return };
            buf.extend_from_slice(data);
            let peek = peek_sni(buf);
            let over_cap = buf.len() > SNI_PEEK_CAP;
            if matches!(peek, SniPeek::NeedMore) && !over_cap {
                return; // keep waiting for the rest of the ClientHello
            }
            let sni = if let SniPeek::Found(s) = peek { Some(s) } else { None };
            let buffered = std::mem::take(buf);
            (sni, over_cap, buffered, up.uid, up.server)
        };
        let _ = over_cap;
        if let Some(up) = self.tcp.get_mut(&id) {
            up.classify = Classify::Settled;
        }

        let is_doh = sni.as_deref().map_or(false, adwarden_dns::is_doh_host);
        if is_doh {
            // Encrypted DNS: filter if we can, else fail closed (drop).
            if self.can_intercept_enc_dns(uid, server.ip()) {
                if let Some(mitm) = self.tls.as_ref().and_then(|t| t.new_splice_dns(DnsKind::Doh).ok()) {
                    self.stats.mitm_new += 1;
                    if let Some(up) = self.tcp.get_mut(&id) {
                        up.mitm = Some(mitm);
                    }
                    self.feed_and_drive(id, &buffered, batcher);
                    return;
                }
            }
            // No CA / pinned / splice error: drop rather than leak DoH.
            batcher.push(Event::blocked_flow(server).with_uid(uid));
            self.stack.tcp_abort(id);
            self.teardown_tcp(id);
            return;
        }

        // Not DoH: surface the SNI to the live log (log-open only) for both the
        // cosmetic-MITM and raw-relay outcomes below — these flows are classified
        // here and never reach the raw-relay observer in `service`. Mark it
        // reported so that observer can't also emit a duplicate. Observational.
        if self.log_open {
            if let Some(host) = sni.as_ref() {
                batcher.push(Event::flow_to(server).with_uid(uid).with_domain(Some(host.clone())));
            }
            if let Some(up) = self.tcp.get_mut(&id) {
                up.sni_reported = true;
            }
        }

        // Fall back to today's behavior for a 443 flow — cosmetic interception for
        // an opted-in app, otherwise raw relay.
        let cosmetic = server.port() == HTTPS_PORT
            && self.app_inspects(uid)
            && !(uid >= 0 && self.pinned.contains(&(uid, server.ip())));
        if cosmetic {
            if let Some(mitm) = self.tls.as_ref().and_then(|t| t.new_splice().ok()) {
                self.stats.mitm_new += 1;
                if let Some(up) = self.tcp.get_mut(&id) {
                    up.mitm = Some(mitm);
                }
                self.feed_and_drive(id, &buffered, batcher);
                return;
            }
        }
        // Raw relay: hand the buffered ClientHello (and everything after) upstream.
        if let Some(up) = self.tcp.get_mut(&id) {
            up.to_upstream.extend_from_slice(&buffered);
        }
    }

    /// Passively peek the ClientHello SNI on a raw-relayed HTTPS flow and surface
    /// it once as a flow event, so the live log can show the host for a flow that
    /// otherwise carries only an IP:port. Best-effort (only this pass's bytes are
    /// examined) and observational — it never buffers, delays, or alters the
    /// relayed bytes, so filtering/forwarding is untouched. Log-open only.
    fn observe_sni(&mut self, id: FlowId, data: &[u8], batcher: &mut Batcher) {
        let (uid, server) = match self.tcp.get(&id) {
            Some(up) if !up.sni_reported && up.server.port() == HTTPS_PORT => (up.uid, up.server),
            _ => return,
        };
        if let SniPeek::Found(host) = peek_sni(data) {
            batcher.push(Event::flow_to(server).with_uid(uid).with_domain(Some(host)));
            if let Some(up) = self.tcp.get_mut(&id) {
                up.sni_reported = true;
            }
        }
    }

    /// Feed buffered app bytes into a just-attached splice and advance it.
    fn feed_and_drive(&mut self, id: FlowId, data: &[u8], batcher: &mut Batcher) {
        if !data.is_empty() {
            if let Some(mitm) = self.tcp.get_mut(&id).and_then(|up| up.mitm.as_mut()) {
                mitm.recv_from_app(data);
            }
        }
        self.drive_mitm(id, batcher);
    }

    fn connect_tcp(&mut self, server: SocketAddr, env: &mut jni::JNIEnv, bridge: &Bridge) -> Option<(UpstreamIo, Token)> {
        // Dial the proxy when configured, else the origin directly. The relay/MITM
        // above targets `server` regardless; the handshake (set in `open_tcp`)
        // bridges the proxy connection to it.
        let dial = self.proxy.as_ref().map_or(server, |p| p.addr);
        let domain = if dial.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::STREAM, None).ok()?;
        socket.set_nonblocking(true).ok()?;
        if bridge.protect(env, socket.as_raw_fd()) {
            self.stats.protect_ok += 1;
        } else {
            self.stats.protect_fail += 1;
            crate::alog!("protect() failed for upstream TCP socket -> {}", dial);
            return None;
        }
        // Non-blocking connect returns EINPROGRESS; that's expected.
        let _ = socket.connect(&dial.into());
        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream);
        // Wrap in TLS for an HTTPS proxy; otherwise a bare socket carries the
        // plaintext CONNECT / SOCKS handshake and the relayed bytes.
        let mut io = match self.proxy.as_ref().filter(|p| p.is_tls()) {
            Some(p) => match ProxyTls::new(stream, &p.server_name) {
                Some(t) => UpstreamIo::Tls(Box::new(t)),
                None => {
                    crate::alog!("HTTPS proxy TLS setup failed for {}", p.server_name);
                    return None;
                }
            },
            None => UpstreamIo::Plain(stream),
        };
        let token = self.alloc_token();
        self.registry
            .register(io.source(), token, Interest::READABLE | Interest::WRITABLE)
            .ok()?;
        Some((io, token))
    }

    // --- Proxy handshake ------------------------------------------------

    /// Advance a flow's proxy handshake. For an HTTPS proxy the rustls session is
    /// completed first; then the HTTP `CONNECT` / SOCKS5 step machine runs until
    /// the tunnel to `server` opens (`handshake` cleared → relay resumes next
    /// pass) or any error tears the flow down (fail-closed).
    fn drive_proxy_handshake(&mut self, id: FlowId, batcher: &mut Batcher) {
        // 1. Finish the TLS handshake to an HTTPS proxy.
        if self.tcp.get(&id).map_or(false, |up| up.io.tls_handshaking()) {
            let pumped = self.tcp.get_mut(&id).map(|up| up.io.pump_tls());
            if !matches!(pumped, Some(Ok(()))) {
                return self.fail_proxy(id, batcher);
            }
            if self.tcp.get(&id).map_or(false, |up| up.io.tls_handshaking()) {
                return; // still handshaking; resume on next readiness
            }
        }
        // 2. Flush any handshake bytes left over from a backed-up socket.
        if !self.flush_handshake_out(id) {
            return self.fail_proxy(id, batcher);
        }
        if self.tcp.get(&id).map_or(true, |up| !up.hs_out.is_empty()) {
            return; // socket still full (or flow gone); wait for writable
        }
        // 3. Drain whatever the proxy has sent so far.
        let mut input = Vec::new();
        let mut eof = false;
        let mut buf = [0u8; 4096];
        loop {
            let Some(up) = self.tcp.get_mut(&id) else { return };
            match up.io.read(&mut buf) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(n) => input.extend_from_slice(&buf[..n]),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => return self.fail_proxy(id, batcher),
            }
        }
        // 4. Step the protocol machine, sending each produced message.
        let mut first = true;
        loop {
            let step = {
                let Some(up) = self.tcp.get_mut(&id) else { return };
                let Some(hs) = up.handshake.as_mut() else { return };
                let feed: &[u8] = if first { &input } else { &[] };
                hs.step(feed)
            };
            first = false;
            match step {
                Ok(ProxyStep::Write(bytes)) => {
                    if let Some(up) = self.tcp.get_mut(&id) {
                        up.hs_out.extend_from_slice(&bytes);
                    }
                    if !self.flush_handshake_out(id) {
                        return self.fail_proxy(id, batcher);
                    }
                    // Not fully flushed → wait for writable before stepping on.
                    if self.tcp.get(&id).map_or(true, |up| !up.hs_out.is_empty()) {
                        return;
                    }
                }
                Ok(ProxyStep::Read) => {
                    // The proxy closed before completing the handshake ⇒ fail closed.
                    if eof {
                        return self.fail_proxy(id, batcher);
                    }
                    return;
                }
                Ok(ProxyStep::Done { leftover }) => {
                    self.stats.proxy_ok += 1;
                    if let Some(up) = self.tcp.get_mut(&id) {
                        up.handshake = None;
                        // Bytes past the reply belong to the origin stream. On a
                        // MITM'd flow they're the server's TLS records (feed the
                        // splice); otherwise raw app-bound bytes. Normally empty —
                        // for CONNECT/SOCKS the origin doesn't speak until we send.
                        if !leftover.is_empty() {
                            match up.mitm.as_mut() {
                                Some(mitm) => mitm.recv_from_upstream(&leftover),
                                None => up.to_app.extend_from_slice(&leftover),
                            }
                        }
                    }
                    self.flush_to_app(id);
                    return; // relay/MITM resumes on the next service pass
                }
                Err(e) => {
                    crate::alog!("proxy handshake failed: {e}");
                    return self.fail_proxy(id, batcher);
                }
            }
        }
    }

    /// Write as much of the pending handshake output as the socket accepts,
    /// retaining any unsent tail in `hs_out`. Returns false on a hard write error.
    fn flush_handshake_out(&mut self, id: FlowId) -> bool {
        let Some(up) = self.tcp.get_mut(&id) else { return false };
        if up.hs_out.is_empty() {
            return true;
        }
        let data = std::mem::take(&mut up.hs_out);
        let mut written = 0;
        let mut ok = true;
        while written < data.len() {
            match up.io.write(&data[written..]) {
                Ok(0) => break,
                Ok(n) => written += n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    ok = false;
                    break;
                }
            }
        }
        up.hs_out = data[written..].to_vec();
        ok
    }

    /// Fail-closed teardown of a flow whose proxy handshake failed: reset the app
    /// (so it errors fast instead of leaking around the proxy) and drop the flow.
    fn fail_proxy(&mut self, id: FlowId, batcher: &mut Batcher) {
        self.stats.proxy_fail += 1;
        if let Some(up) = self.tcp.get(&id) {
            batcher.push(Event::blocked_flow(up.server).with_uid(up.uid));
        }
        self.stack.tcp_abort(id);
        self.teardown_tcp(id);
    }

    fn flush_to_upstream(&mut self, id: FlowId) {
        let Some(up) = self.tcp.get_mut(&id) else { return };
        // Never relay app bytes while still connecting or mid proxy handshake.
        if up.connecting || up.handshake.is_some() || up.to_upstream.is_empty() {
            return;
        }
        let mut written = 0;
        let mut failed = false;
        while written < up.to_upstream.len() {
            match up.io.write(&up.to_upstream[written..]) {
                Ok(0) => break,
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            self.stack.tcp_abort(id);
            return;
        }
        if written > 0 {
            up.to_upstream.drain(..written);
        }
    }

    // --- TLS interception (MITM) -----------------------------------------

    /// Advance a flow's TLS splice: pump it, queue the produced TLS records
    /// toward each peer, and on completion/failure tear the flow down.
    fn drive_mitm(&mut self, id: FlowId, batcher: &mut Batcher) {
        let is_dns = self
            .tcp
            .get(&id)
            .and_then(|up| up.mitm.as_ref())
            .map_or(false, |m| m.is_dns());
        let io = if is_dns {
            // Encrypted-DNS path: the filter needs a block decision per query.
            // Split-borrow the engine (immutable) and this flow's mitm (mutable).
            let engine = self.engine.as_ref();
            let Some(up) = self.tcp.get_mut(&id) else { return };
            let Some(mitm) = up.mitm.as_mut() else { return };
            let mut is_blocked = |name: &str| engine.map_or(false, |e| e.is_blocked_domain(name));
            let io = mitm.pump_dns(&mut is_blocked);
            let hits = mitm.take_dns_blocked();
            let (uid, server) = (up.uid, up.server);
            for name in hits {
                batcher.push(Event::enc_dns_blocked(uid, server, name));
            }
            io
        } else {
            let io = match self.tcp.get_mut(&id).and_then(|up| up.mitm.as_mut()) {
                Some(mitm) => mitm.pump(),
                None => return,
            };
            // The pump may have just learned the SNI; provision cosmetics before
            // its decrypted output is drained toward the app (P4-2). This runs
            // before any response byte can exist (the upstream session is created
            // lazily on the same pump the SNI is learned, so it hasn't handshaked).
            self.provision_cosmetics(id);
            io
        };
        if let Some(up) = self.tcp.get_mut(&id) {
            up.to_upstream.extend_from_slice(&io.to_upstream);
            up.to_app.extend_from_slice(&io.to_app);
        }
        self.drain_mitm_transactions(id);
        if io.closed {
            self.note_pin_if_rejected(id, batcher);
            // Flush whatever the splice produced, then close both directions.
            self.flush_to_upstream(id);
            self.flush_to_app(id);
            self.stack.tcp_close_app(id);
            if let Some(up) = self.tcp.get_mut(&id) {
                if !up.write_closed && !up.connecting {
                    let _ = up.io.shutdown_write();
                    up.write_closed = true;
                }
            }
        }
    }

    /// If the splice closed because the app refused our leaf, remember the
    /// (app, server) pair so future flows relay raw, and surface the flow as
    /// metadata-only in the live log (P2-4). Fires once, as the splice closes.
    fn note_pin_if_rejected(&mut self, id: FlowId, batcher: &mut Batcher) {
        let Some(up) = self.tcp.get(&id) else { return };
        let Some(mitm) = up.mitm.as_ref() else { return };
        if up.pin_reported || !mitm.cert_rejected() {
            return;
        }
        let (uid, server) = (up.uid, up.server);
        let host = mitm.host().map(str::to_string);
        if let Some(up) = self.tcp.get_mut(&id) {
            up.pin_reported = true;
        }
        if self.pinned.len() < PINNED_CAP {
            self.pinned.insert((uid, server.ip()));
        }
        self.stats.pinned += 1;
        batcher.push(Event::tls_pinned(uid, server, host));
    }

    /// Pull any HTTP transactions the splice has decrypted into the session HAR
    /// buffer, dropping the oldest past [`HAR_MAX_ENTRIES`].
    fn drain_mitm_transactions(&mut self, id: FlowId) {
        let txns = match self.tcp.get_mut(&id).and_then(|up| up.mitm.as_mut()) {
            Some(mitm) => mitm.take_transactions(),
            None => return,
        };
        for txn in txns {
            if self.har.len() >= HAR_MAX_ENTRIES {
                self.har.remove(0);
            }
            self.har.push(txn);
        }
    }

    /// Drain the MITM staging buffer into the smoltcp socket as its send window
    /// allows (mirrors [`Self::pump_upstream_to_app`]'s backpressure, but for
    /// bytes the splice already produced).
    fn flush_to_app(&mut self, id: FlowId) {
        loop {
            let space = self.stack.tcp_send_space(id);
            if space == 0 {
                return;
            }
            let chunk = match self.tcp.get_mut(&id) {
                Some(up) if !up.to_app.is_empty() => {
                    let n = space.min(up.to_app.len());
                    up.to_app.drain(..n).collect::<Vec<u8>>()
                }
                _ => return,
            };
            self.stack.tcp_send_to_app(id, &chunk);
        }
    }

    /// Read raw TLS bytes off the upstream socket and feed them into the splice,
    /// pausing while the app-bound buffer is backed up.
    fn read_upstream_into_mitm(&mut self, id: FlowId) {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let backed_up = self
                .tcp
                .get(&id)
                .map_or(true, |up| up.to_app.len() > MITM_APP_BUF_CAP);
            if backed_up {
                break;
            }
            let Some(up) = self.tcp.get_mut(&id) else { break };
            match up.io.read(&mut buf) {
                Ok(0) => break, // upstream EOF; the read-closed path closes the app side
                Ok(n) => {
                    self.stats.upstream_reply += 1;
                    if let Some(mitm) = up.mitm.as_mut() {
                        mitm.recv_from_upstream(&buf[..n]);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    fn pump_upstream_to_app(&mut self, id: FlowId) {
        loop {
            let space = self.stack.tcp_send_space(id);
            if space == 0 {
                break; // app-bound buffer full; wait for it to drain
            }
            let Some(up) = self.tcp.get_mut(&id) else { break };
            let mut buf = vec![0u8; space.min(32 * 1024)];
            match up.io.read(&mut buf) {
                Ok(0) => {
                    // Upstream EOF -> half-close toward the app.
                    self.stack.tcp_close_app(id);
                    break;
                }
                Ok(n) => {
                    self.stats.upstream_reply += 1;
                    self.stack.tcp_send_to_app(id, &buf[..n]);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.stack.tcp_abort(id);
                    break;
                }
            }
        }
    }

    fn teardown_tcp(&mut self, id: FlowId) {
        // Flush any final transaction (e.g. a connection-close-delimited response)
        // before the splice is dropped.
        if let Some(up) = self.tcp.get_mut(&id) {
            if let Some(mitm) = up.mitm.as_mut() {
                mitm.finish();
            }
        }
        self.drain_mitm_transactions(id);
        if let Some(mut up) = self.tcp.remove(&id) {
            let _ = self.registry.deregister(up.io.source());
            self.routes.remove(&up.token);
        }
    }

    // --- UDP -------------------------------------------------------------

    /// Forward a datagram to `upstream`. The NAT key and reply source stay tied
    /// to `dgram.dst` (what the app targeted), so a DNS answer relayed from a
    /// real resolver still appears to come from the advertised placeholder.
    fn forward_udp(
        &mut self,
        dgram: udp::UdpDatagram,
        upstream: SocketAddr,
        env: &mut jni::JNIEnv,
        bridge: &Bridge,
    ) {
        let key = UdpKey { app: dgram.src, server: dgram.dst };
        let now = self.now_ms();
        if !self.udp.contains_key(&key) {
            if let Some((socket, token)) = self.connect_udp(upstream, env, bridge) {
                self.stats.udp_new += 1;
                self.routes.insert(token, Route::Udp(key));
                self.udp.insert(
                    key,
                    UdpSession { socket, token, app: dgram.src, server: dgram.dst, last_used_ms: now },
                );
            } else {
                self.stats.connect_fail += 1;
                return;
            }
        }
        if let Some(session) = self.udp.get_mut(&key) {
            session.last_used_ms = now;
            let _ = session.socket.send(&dgram.payload);
        }
    }

    /// The real resolver to forward an allowed DNS query to, matching the
    /// query's address family and keeping its port.
    fn dns_upstream(&self, queried: SocketAddr) -> SocketAddr {
        let ip = match queried.ip() {
            IpAddr::V4(_) => self.dns_upstream_v4,
            IpAddr::V6(_) => self.dns_upstream_v6,
        };
        SocketAddr::new(ip, queried.port())
    }

    fn connect_udp(&mut self, server: SocketAddr, env: &mut jni::JNIEnv, bridge: &Bridge) -> Option<(UdpSocket, Token)> {
        let domain = if server.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::DGRAM, None).ok()?;
        socket.set_nonblocking(true).ok()?;
        if bridge.protect(env, socket.as_raw_fd()) {
            self.stats.protect_ok += 1;
        } else {
            self.stats.protect_fail += 1;
            crate::alog!("protect() failed for upstream UDP socket -> {}", server);
            return None;
        }
        socket.connect(&server.into()).ok()?;
        let std_udp: std::net::UdpSocket = socket.into();
        let mut mio_udp = UdpSocket::from_std(std_udp);
        let token = self.alloc_token();
        self.registry.register(&mut mio_udp, token, Interest::READABLE).ok()?;
        Some((mio_udp, token))
    }

    fn pump_udp_reply(&mut self, key: UdpKey, _batcher: &mut Batcher) {
        let (app, server) = match self.udp.get(&key) {
            Some(s) => (s.app, s.server),
            None => return,
        };
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let Some(session) = self.udp.get_mut(&key) else { break };
            match session.socket.recv(&mut buf) {
                Ok(n) => {
                    session.last_used_ms = self.start.elapsed().as_millis() as i64;
                    self.stats.upstream_reply += 1;
                    if let Some(packet) = udp::build_reply(server, app, &buf[..n]) {
                        self.outbox.push(packet);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    fn reap_udp(&mut self, now: i64) {
        let stale: Vec<UdpKey> = self
            .udp
            .iter()
            .filter(|(_, s)| now - s.last_used_ms > UDP_IDLE_MS)
            .map(|(k, _)| *k)
            .collect();
        for key in stale {
            if let Some(mut session) = self.udp.remove(&key) {
                let _ = self.registry.deregister(&mut session.socket);
                self.routes.remove(&session.token);
            }
        }
    }

    // --- SOCKS5 UDP ASSOCIATE (Stage 2) ----------------------------------

    /// Forward a datagram through a SOCKS5 UDP association, creating one for this
    /// (app, server) pair on first use. `target` is the real encapsulation
    /// destination (the upstream resolver for DNS, else the origin server).
    fn forward_udp_socks(
        &mut self,
        dgram: udp::UdpDatagram,
        target: SocketAddr,
        env: &mut jni::JNIEnv,
        bridge: &Bridge,
    ) {
        let key = UdpKey { app: dgram.src, server: dgram.dst };
        let now = self.now_ms();
        if let Some(session) = self.socks_udp.get_mut(&key) {
            session.last_used_ms = now;
            if session.ready {
                let wire = proxy::socks5_udp_encapsulate(session.target, &dgram.payload);
                let _ = session.relay.send(&wire);
            } else if session.pending.len() < SOCKS_UDP_PENDING_CAP {
                session.pending.push(dgram.payload);
            }
            return;
        }
        let Some(proxy) = self.proxy.clone() else { return };
        let Some((ctrl, ctrl_token)) = self.connect_socks_ctrl(env, bridge) else {
            self.stats.connect_fail += 1;
            return;
        };
        let Some((relay, relay_token)) = self.new_relay_socket(env, bridge) else {
            // Undo the control socket registered just above (its route isn't set yet).
            let mut ctrl = ctrl;
            let _ = self.registry.deregister(&mut ctrl);
            self.stats.connect_fail += 1;
            return;
        };
        self.stats.udp_new += 1;
        self.routes.insert(ctrl_token, Route::SocksCtrl(key));
        self.routes.insert(relay_token, Route::SocksRelay(key));
        self.socks_udp.insert(
            key,
            Socks5UdpSession {
                ctrl,
                ctrl_token,
                ctrl_connecting: true,
                handshake: Some(Handshake::udp_associate(&proxy)),
                hs_out: Vec::new(),
                relay,
                relay_token,
                app: dgram.src,
                reply_src: dgram.dst,
                target,
                pending: vec![dgram.payload],
                ready: false,
                last_used_ms: now,
            },
        );
    }

    /// Dial the proxy for a UDP-associate control connection (plaintext — SOCKS5 is
    /// never TLS-wrapped). Registered for read/write to detect connect + close.
    fn connect_socks_ctrl(&mut self, env: &mut jni::JNIEnv, bridge: &Bridge) -> Option<(TcpStream, Token)> {
        let dial = self.proxy.as_ref()?.addr;
        let domain = if dial.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::STREAM, None).ok()?;
        socket.set_nonblocking(true).ok()?;
        if bridge.protect(env, socket.as_raw_fd()) {
            self.stats.protect_ok += 1;
        } else {
            self.stats.protect_fail += 1;
            crate::alog!("protect() failed for SOCKS5 UDP control socket -> {}", dial);
            return None;
        }
        let _ = socket.connect(&dial.into());
        let std_stream: std::net::TcpStream = socket.into();
        let mut stream = TcpStream::from_std(std_stream);
        let token = self.alloc_token();
        self.registry
            .register(&mut stream, token, Interest::READABLE | Interest::WRITABLE)
            .ok()?;
        Some((stream, token))
    }

    /// Create the `protect()`ed relay UDP socket. Its address family matches the
    /// proxy host (where the relay lives); a v6 target still rides it via the
    /// per-datagram SOCKS address header. Connected to the relay endpoint later.
    fn new_relay_socket(&mut self, env: &mut jni::JNIEnv, bridge: &Bridge) -> Option<(UdpSocket, Token)> {
        let proxy_addr = self.proxy.as_ref()?.addr;
        let domain = if proxy_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::DGRAM, None).ok()?;
        socket.set_nonblocking(true).ok()?;
        if bridge.protect(env, socket.as_raw_fd()) {
            self.stats.protect_ok += 1;
        } else {
            self.stats.protect_fail += 1;
            crate::alog!("protect() failed for SOCKS5 UDP relay socket");
            return None;
        }
        let std_udp: std::net::UdpSocket = socket.into();
        let mut mio_udp = UdpSocket::from_std(std_udp);
        let token = self.alloc_token();
        self.registry.register(&mut mio_udp, token, Interest::READABLE).ok()?;
        Some((mio_udp, token))
    }

    /// Advance a UDP association's control handshake; on completion, connect the
    /// relay socket and flush buffered datagrams. Any failure tears it down.
    fn drive_socks_ctrl(&mut self, key: UdpKey) {
        // Clear the connect flag on the first writable, checking for a connect error.
        let connecting = self.socks_udp.get(&key).map_or(false, |s| s.ctrl_connecting);
        if connecting {
            let err = self
                .socks_udp
                .get_mut(&key)
                .and_then(|s| s.ctrl.take_error().ok().flatten());
            if let Some(s) = self.socks_udp.get_mut(&key) {
                s.ctrl_connecting = false;
            }
            if err.is_some() {
                self.teardown_socks(key);
                return;
            }
        }
        let progress = if let Some(s) = self.socks_udp.get_mut(&key) {
            match s.handshake.as_mut() {
                Some(hs) => pump_ctrl_handshake(&mut s.ctrl, hs, &mut s.hs_out),
                None => return,
            }
        } else {
            return;
        };
        match progress {
            CtrlStep::Pending => {}
            CtrlStep::Failed => {
                // The proxy refused/failed ASSOCIATE (most free SOCKS5 proxies are
                // TCP-only). Remember it so DNS falls back to DNS-over-TCP through
                // the proxy instead of failing closed forever.
                self.socks_udp_unsupported = true;
                self.teardown_socks(key);
            }
            CtrlStep::Ready(bound) => self.socks_associate_ready(key, bound),
        }
    }

    /// The ASSOCIATE reply arrived: resolve the relay endpoint, connect the relay
    /// socket to it, and flush datagrams buffered during the handshake.
    fn socks_associate_ready(&mut self, key: UdpKey, bound: Option<SocketAddr>) {
        let Some(proxy_ip) = self.proxy.as_ref().map(|p| p.addr.ip()) else {
            self.teardown_socks(key);
            return;
        };
        // An all-zero bound address means "the proxy host" (RFC 1928).
        let relay_addr = match bound {
            Some(a) if a.ip().is_unspecified() => SocketAddr::new(proxy_ip, a.port()),
            Some(a) => a,
            None => {
                crate::alog!("SOCKS5 UDP associate: no usable relay address");
                self.teardown_socks(key);
                return;
            }
        };
        let ok = if let Some(s) = self.socks_udp.get_mut(&key) {
            if s.relay.connect(relay_addr).is_ok() {
                s.handshake = None;
                s.ready = true;
                let target = s.target;
                for payload in std::mem::take(&mut s.pending) {
                    let wire = proxy::socks5_udp_encapsulate(target, &payload);
                    let _ = s.relay.send(&wire);
                }
                true
            } else {
                false
            }
        } else {
            return;
        };
        if ok {
            self.stats.proxy_ok += 1;
        } else {
            self.teardown_socks(key);
        }
    }

    /// Drain relayed datagrams: decapsulate the SOCKS UDP header and inject each
    /// toward the app, sourced from what it originally targeted (`reply_src`).
    fn pump_socks_relay(&mut self, key: UdpKey) {
        let (reply_src, app) = match self.socks_udp.get(&key) {
            Some(s) => (s.reply_src, s.app),
            None => return,
        };
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            let Some(s) = self.socks_udp.get_mut(&key) else { break };
            match s.relay.recv(&mut buf) {
                Ok(n) => {
                    s.last_used_ms = self.start.elapsed().as_millis() as i64;
                    self.stats.upstream_reply += 1;
                    if let Some((_origin, payload)) = proxy::socks5_udp_decapsulate(&buf[..n]) {
                        if let Some(packet) = udp::build_reply(reply_src, app, payload) {
                            self.outbox.push(packet);
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    fn teardown_socks(&mut self, key: UdpKey) {
        if let Some(mut s) = self.socks_udp.remove(&key) {
            let _ = self.registry.deregister(&mut s.ctrl);
            let _ = self.registry.deregister(&mut s.relay);
            self.routes.remove(&s.ctrl_token);
            self.routes.remove(&s.relay_token);
        }
    }

    fn reap_socks(&mut self, now: i64) {
        let stale: Vec<UdpKey> = self
            .socks_udp
            .iter()
            .filter(|(_, s)| now - s.last_used_ms > UDP_IDLE_MS)
            .map(|(k, _)| *k)
            .collect();
        for key in stale {
            self.teardown_socks(key);
        }
    }

    /// Fail closed any proxy handshake still unfinished past [`PROXY_HS_TIMEOUT_MS`]
    /// (P5). Without this a handshake that never completes — a TLS ClientHello to a
    /// plaintext proxy port, or a black-holed proxy — would hang the flow until the
    /// app or the 60s idle reap gives up. Direct (non-proxy) flows have no
    /// handshake, so they are untouched.
    fn reap_proxy_handshakes(&mut self, now: i64, batcher: &mut Batcher) {
        let stuck: Vec<FlowId> = self
            .tcp
            .iter()
            .filter(|(_, up)| up.handshake.is_some() && now - up.opened_ms > PROXY_HS_TIMEOUT_MS)
            .map(|(id, _)| *id)
            .collect();
        for id in stuck {
            crate::alog!("proxy handshake timed out ({PROXY_HS_TIMEOUT_MS}ms); failing closed");
            self.fail_proxy(id, batcher);
        }
        // A SOCKS5 ASSOCIATE that never completes: tear it down and fall back to
        // DNS-over-TCP for later DNS, like an explicit ASSOCIATE refusal.
        let stuck_socks: Vec<UdpKey> = self
            .socks_udp
            .iter()
            .filter(|(_, s)| s.handshake.is_some() && now - s.last_used_ms > PROXY_HS_TIMEOUT_MS)
            .map(|(k, _)| *k)
            .collect();
        for key in stuck_socks {
            crate::alog!("SOCKS5 UDP associate timed out; falling back to DNS-over-TCP");
            self.socks_udp_unsupported = true;
            self.teardown_socks(key);
        }
    }

    // --- DNS-over-TCP through an HTTP/HTTPS proxy (P5) --------------------

    /// Start a one-shot DNS-over-TCP job: dial the proxy, then (after CONNECT)
    /// send the length-prefixed query to `resolver` and await the response. The
    /// datagram was already allowed and its name learned by `handle_dns`.
    fn forward_dns_over_proxy(
        &mut self,
        dgram: udp::UdpDatagram,
        resolver: SocketAddr,
        env: &mut jni::JNIEnv,
        bridge: &Bridge,
    ) {
        if self.dns_tcp.len() >= DNS_TCP_MAX_JOBS || dgram.payload.len() > u16::MAX as usize {
            return; // over the cap or an oversize query: drop (the app retries)
        }
        let Some(proxy) = self.proxy.clone() else { return };
        // `connect_tcp` dials the proxy (and TLS-wraps it for an HTTPS proxy); the
        // handshake below then CONNECTs onward to the resolver.
        let Some((io, token)) = self.connect_tcp(resolver, env, bridge) else {
            self.stats.connect_fail += 1;
            return;
        };
        let mut to_send = Vec::with_capacity(dgram.payload.len() + 2);
        to_send.extend_from_slice(&(dgram.payload.len() as u16).to_be_bytes());
        to_send.extend_from_slice(&dgram.payload);
        self.routes.insert(token, Route::DnsTcp);
        self.dns_tcp.insert(
            token,
            DnsTcpJob {
                io,
                connecting: true,
                handshake: Some(Handshake::connect(&proxy, resolver)),
                hs_out: Vec::new(),
                to_send,
                query_sent: false,
                resp_buf: Vec::new(),
                app: dgram.src,
                reply_src: dgram.dst,
                created_ms: self.now_ms(),
            },
        );
    }

    /// Advance a DNS-over-TCP job on readiness: finish the proxy handshake, send
    /// the query, and once a full length-prefixed response is buffered, inject it
    /// toward the app and tear the job down. Any failure drops it (fail-closed).
    fn drive_dns_tcp(&mut self, token: Token) {
        // 1. Clear the connect flag on the first writable, checking for an error.
        let connecting = self.dns_tcp.get(&token).map_or(false, |j| j.connecting);
        if connecting {
            let err = self.dns_tcp.get_mut(&token).and_then(|j| j.io.take_error().ok().flatten());
            if let Some(j) = self.dns_tcp.get_mut(&token) {
                j.connecting = false;
            }
            if err.is_some() {
                self.teardown_dns_tcp(token);
                return;
            }
        }
        // 2. Proxy handshake (HTTP CONNECT, or HTTPS TLS + CONNECT).
        if self.dns_tcp.get(&token).map_or(false, |j| j.handshake.is_some()) {
            let progress = if let Some(j) = self.dns_tcp.get_mut(&token) {
                match j.handshake.as_mut() {
                    Some(hs) => pump_handshake_io(&mut j.io, hs, &mut j.hs_out),
                    None => return,
                }
            } else {
                return;
            };
            match progress {
                HsPump::Pending => return,
                HsPump::Failed => {
                    self.teardown_dns_tcp(token);
                    return;
                }
                HsPump::Done { leftover } => {
                    if let Some(j) = self.dns_tcp.get_mut(&token) {
                        j.handshake = None;
                        j.resp_buf.extend_from_slice(&leftover); // normally empty
                    }
                }
            }
        }
        // 3. Send the length-prefixed query once the tunnel is open.
        let mut send_failed = false;
        if let Some(j) = self.dns_tcp.get_mut(&token) {
            if j.handshake.is_none() && !j.query_sent {
                if flush_io(&mut j.io, &mut j.to_send) {
                    j.query_sent = j.to_send.is_empty();
                } else {
                    send_failed = true;
                }
            }
        }
        if send_failed {
            self.teardown_dns_tcp(token);
            return;
        }
        // 4. Read the response; reply and finish once a full message is buffered.
        let mut eof = false;
        if let Some(j) = self.dns_tcp.get_mut(&token) {
            if j.query_sent {
                let mut buf = [0u8; 4096];
                loop {
                    match j.io.read(&mut buf) {
                        Ok(0) => {
                            eof = true;
                            break;
                        }
                        Ok(n) => j.resp_buf.extend_from_slice(&buf[..n]),
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => {
                            eof = true;
                            break;
                        }
                    }
                }
            }
        }
        let reply = self.dns_tcp.get(&token).and_then(|j| {
            take_dns_tcp_response(&j.resp_buf).map(|msg| (j.reply_src, j.app, msg.to_vec()))
        });
        if let Some((reply_src, app, message)) = reply {
            if let Some(packet) = udp::build_reply(reply_src, app, &message) {
                self.outbox.push(packet);
            }
            self.stats.upstream_reply += 1;
            self.teardown_dns_tcp(token);
        } else if eof {
            // Upstream closed before a full response arrived: drop (fail-closed).
            self.teardown_dns_tcp(token);
        }
    }

    fn teardown_dns_tcp(&mut self, token: Token) {
        if let Some(mut job) = self.dns_tcp.remove(&token) {
            let _ = self.registry.deregister(job.io.source());
            self.routes.remove(&token);
        }
    }

    fn reap_dns_tcp(&mut self, now: i64) {
        let stale: Vec<Token> = self
            .dns_tcp
            .iter()
            .filter(|(_, j)| now - j.created_ms > DNS_TCP_TIMEOUT_MS)
            .map(|(k, _)| *k)
            .collect();
        for token in stale {
            self.teardown_dns_tcp(token);
        }
    }
}

/// Build the shared rustls configs for TLS interception, or `None` when it's
/// disabled or the CA is missing/unloadable (interception then simply doesn't
/// engage — flows relay raw as before).
fn build_tls_factory(config: &Config) -> Option<MitmConfigs> {
    if !config.intercept_tls {
        return None;
    }
    let (Some(cert), Some(key)) = (config.ca_cert_pem.as_ref(), config.ca_key_pem.as_ref()) else {
        crate::alog!("intercept_tls set but CA PEM missing; interception disabled");
        return None;
    };
    match MitmConfigs::build(cert, key) {
        Ok(factory) => {
            crate::alog!("TLS interception enabled");
            Some(factory)
        }
        Err(e) => {
            crate::alog!("TLS interception disabled ({e})");
            None
        }
    }
}

/// Outcome of pumping a plaintext SOCKS control handshake ([`pump_ctrl_handshake`]).
enum CtrlStep {
    /// Still in progress; resume on the next readiness event.
    Pending,
    /// Complete; carries the relay bound address from the ASSOCIATE reply.
    Ready(Option<SocketAddr>),
    /// Failed; the caller tears the session down (fail-closed).
    Failed,
}

/// Drive a SOCKS handshake over a plaintext control socket (SOCKS5 is never TLS-
/// wrapped). Mirrors [`Forwarder::drive_proxy_handshake`] but for the UDP-associate
/// control connection: on completion it yields the relay bound address.
fn pump_ctrl_handshake(stream: &mut TcpStream, hs: &mut Handshake, hs_out: &mut Vec<u8>) -> CtrlStep {
    if !flush_plain(stream, hs_out) {
        return CtrlStep::Failed;
    }
    if !hs_out.is_empty() {
        return CtrlStep::Pending; // socket backed up; retry on writable
    }
    let mut input = Vec::new();
    let mut eof = false;
    let mut buf = [0u8; 2048];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(n) => input.extend_from_slice(&buf[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => return CtrlStep::Failed,
        }
    }
    let mut first = true;
    loop {
        let step = {
            let feed: &[u8] = if first { &input } else { &[] };
            hs.step(feed)
        };
        first = false;
        match step {
            Ok(ProxyStep::Write(bytes)) => {
                hs_out.extend_from_slice(&bytes);
                if !flush_plain(stream, hs_out) {
                    return CtrlStep::Failed;
                }
                if !hs_out.is_empty() {
                    return CtrlStep::Pending;
                }
            }
            Ok(ProxyStep::Read) => {
                return if eof { CtrlStep::Failed } else { CtrlStep::Pending };
            }
            // The control channel carries no post-associate data, so `leftover`
            // (if any) is discarded.
            Ok(ProxyStep::Done { .. }) => return CtrlStep::Ready(hs.bound_addr()),
            Err(e) => {
                crate::alog!("SOCKS5 UDP associate handshake failed: {e}");
                return CtrlStep::Failed;
            }
        }
    }
}

/// Outcome of pumping a proxy handshake over an [`UpstreamIo`] ([`pump_handshake_io`]).
enum HsPump {
    Pending,
    Done { leftover: Vec<u8> },
    Failed,
}

/// Drive an HTTP CONNECT / SOCKS handshake over an [`UpstreamIo`] (plain or a TLS
/// session to an HTTPS proxy). The `UpstreamIo`-based sibling of
/// [`pump_ctrl_handshake`], used by DNS-over-TCP jobs which may run over a TLS
/// proxy transport. On completion yields any bytes already past the reply.
fn pump_handshake_io(io: &mut UpstreamIo, hs: &mut Handshake, hs_out: &mut Vec<u8>) -> HsPump {
    // Complete the TLS handshake to an HTTPS proxy first.
    if io.tls_handshaking() {
        if io.pump_tls().is_err() {
            return HsPump::Failed;
        }
        if io.tls_handshaking() {
            return HsPump::Pending;
        }
    }
    if !flush_io(io, hs_out) {
        return HsPump::Failed;
    }
    if !hs_out.is_empty() {
        return HsPump::Pending;
    }
    let mut input = Vec::new();
    let mut eof = false;
    let mut buf = [0u8; 4096];
    loop {
        match io.read(&mut buf) {
            Ok(0) => {
                eof = true;
                break;
            }
            Ok(n) => input.extend_from_slice(&buf[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => return HsPump::Failed,
        }
    }
    let mut first = true;
    loop {
        let step = {
            let feed: &[u8] = if first { &input } else { &[] };
            hs.step(feed)
        };
        first = false;
        match step {
            Ok(ProxyStep::Write(bytes)) => {
                hs_out.extend_from_slice(&bytes);
                if !flush_io(io, hs_out) {
                    return HsPump::Failed;
                }
                if !hs_out.is_empty() {
                    return HsPump::Pending;
                }
            }
            Ok(ProxyStep::Read) => return if eof { HsPump::Failed } else { HsPump::Pending },
            Ok(ProxyStep::Done { leftover }) => return HsPump::Done { leftover },
            Err(e) => {
                crate::alog!("DNS-over-TCP proxy handshake failed: {e}");
                return HsPump::Failed;
            }
        }
    }
}

/// Write as much of `out` as an [`UpstreamIo`] accepts, retaining the unsent tail.
/// Returns false on a hard write error.
fn flush_io(io: &mut UpstreamIo, out: &mut Vec<u8>) -> bool {
    if out.is_empty() {
        return true;
    }
    let data = std::mem::take(out);
    let mut written = 0;
    let mut ok = true;
    while written < data.len() {
        match io.write(&data[written..]) {
            Ok(0) => break,
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                ok = false;
                break;
            }
        }
    }
    *out = data[written..].to_vec();
    ok
}

/// Extract one complete DNS-over-TCP message from the front of `buf` — RFC 7766
/// framing: a 2-byte big-endian length prefix then that many bytes. `None` until a
/// full message is buffered. Any bytes past the first message are ignored (a DNS
/// query yields exactly one response, after which the job is torn down).
fn take_dns_tcp_response(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return None;
    }
    Some(&buf[2..2 + len])
}

/// Write as much of `out` as a plaintext socket accepts, retaining the unsent tail
/// in `out`. Returns false on a hard write error.
fn flush_plain(stream: &mut TcpStream, out: &mut Vec<u8>) -> bool {
    if out.is_empty() {
        return true;
    }
    let data = std::mem::take(out);
    let mut written = 0;
    let mut ok = true;
    while written < data.len() {
        match stream.write(&data[written..]) {
            Ok(0) => break,
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(_) => {
                ok = false;
                break;
            }
        }
    }
    *out = data[written..].to_vec();
    ok
}

/// Resolve the proxy config into `(proxy, broken)`:
///  - `(None, false)` — no proxy configured; dial origins directly.
///  - `(Some(p), false)` — an active, dialable proxy.
///  - `(None, true)` — a proxy is configured but couldn't be set up (bad/unresolvable
///    address). The datapath then fails **closed** (blocks all forwarding) rather
///    than leaking around it — so a broken proxy never silently degrades to direct.
///
/// The host may be a name: it's resolved here, on the datapath *startup* thread
/// (before the poll loop), which is safe because our process bypasses the tunnel
/// so `getaddrinfo` egresses normally. Resolution happens once per session.
fn build_proxy(config: &Config) -> (Option<Proxy>, bool) {
    use std::net::ToSocketAddrs;
    let pc = &config.proxy;
    if pc.kind == crate::proxy::ProxyKind::None {
        return (None, false); // no proxy → direct
    }
    // Fast path: the address is already a literal IP (in `ip` or `host`).
    if let Some(proxy) = Proxy::from_config(pc) {
        crate::alog!("upstream proxy enabled: {:?} {}", proxy.kind, proxy.addr);
        return (Some(proxy), false);
    }
    // Otherwise resolve the hostname.
    let host = pc.host.trim();
    if pc.port != 0 && !host.is_empty() {
        if let Ok(mut addrs) = (host, pc.port).to_socket_addrs() {
            if let Some(addr) = addrs.next() {
                let clean = |s: &Option<String>| s.as_ref().filter(|v| !v.is_empty()).cloned();
                let proxy = Proxy {
                    kind: pc.kind,
                    addr,
                    server_name: host.to_string(),
                    username: clean(&pc.username),
                    password: clean(&pc.password),
                };
                crate::alog!("upstream proxy enabled: {:?} {} (resolved {})", proxy.kind, addr, host);
                return (Some(proxy), false);
            }
        }
    }
    // Configured but unusable: fail closed rather than leak around the proxy.
    crate::alog!("proxy configured but address unresolved/invalid; blocking (fail closed)");
    (None, true)
}

/// Pick the first IPv4 and IPv6 upstream resolvers from the config, falling back
/// to Cloudflare when unspecified or unparseable.
fn parse_dns_upstreams(servers: &[String]) -> (IpAddr, IpAddr) {
    let mut v4 = IpAddr::V4(DEFAULT_DNS_V4);
    let mut v6 = IpAddr::V6(DEFAULT_DNS_V6);
    let mut got_v4 = false;
    let mut got_v6 = false;
    for server in servers {
        match server.parse::<IpAddr>() {
            Ok(ip @ IpAddr::V4(_)) if !got_v4 => {
                v4 = ip;
                got_v4 = true;
            }
            Ok(ip @ IpAddr::V6(_)) if !got_v6 => {
                v6 = ip;
                got_v6 = true;
            }
            _ => {}
        }
    }
    (v4, v6)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream as StdTcpStream};
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn parses_dns_upstreams_with_fallback() {
        let (v4, v6) = parse_dns_upstreams(&["9.9.9.9".into(), "2620:fe::fe".into()]);
        assert_eq!(v4, "9.9.9.9".parse::<IpAddr>().unwrap());
        assert_eq!(v6, "2620:fe::fe".parse::<IpAddr>().unwrap());

        // Empty config falls back to Cloudflare.
        let (v4, v6) = parse_dns_upstreams(&[]);
        assert_eq!(v4, IpAddr::V4(DEFAULT_DNS_V4));
        assert_eq!(v6, IpAddr::V6(DEFAULT_DNS_V6));
    }

    #[test]
    fn take_dns_tcp_response_framing() {
        // Not enough for even the 2-byte length prefix.
        assert!(take_dns_tcp_response(&[]).is_none());
        assert!(take_dns_tcp_response(&[0x00]).is_none());
        // Length says 10 but only 3 payload bytes present ⇒ wait for more.
        assert!(take_dns_tcp_response(&[0x00, 0x0A, 1, 2, 3]).is_none());
        // Exactly one 4-byte message.
        assert_eq!(take_dns_tcp_response(&[0x00, 0x04, b'a', b'b', b'c', b'd']), Some(&b"abcd"[..]));
        // Bytes past the first message are ignored (one query ⇒ one response).
        assert_eq!(take_dns_tcp_response(&[0x00, 0x02, 0xAA, 0xBB, 0xCC]), Some(&[0xAA, 0xBB][..]));
        // Zero-length message.
        assert_eq!(take_dns_tcp_response(&[0x00, 0x00]), Some(&[][..]));
    }

    #[test]
    fn build_proxy_direct_active_broken() {
        // No proxy configured ⇒ direct.
        let (p, broken) = build_proxy(&Config::default());
        assert!(p.is_none() && !broken, "no proxy → direct");

        // A literal IP ⇒ active (no resolution needed).
        let active = Config {
            proxy: proxy::ProxyConfig {
                kind: proxy::ProxyKind::Http,
                host: "10.0.0.1".into(),
                ip: String::new(),
                port: 8080,
                username: None,
                password: None,
            },
            ..Default::default()
        };
        let (p, broken) = build_proxy(&active);
        assert!(p.is_some() && !broken, "literal IP → active");

        // Configured but invalid (port 0) ⇒ broken (fail closed), no DNS attempted.
        let bad = Config {
            proxy: proxy::ProxyConfig {
                kind: proxy::ProxyKind::Http,
                host: "10.0.0.1".into(),
                port: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let (p, broken) = build_proxy(&bad);
        assert!(p.is_none() && broken, "configured but invalid → broken");
    }

    // --- Loopback handshake tests (real socket glue over 127.0.0.1) -------

    /// Spawn a one-shot fake proxy on 127.0.0.1; `handler` runs on the accepted
    /// (blocking) socket. Returns the bound address to dial.
    fn fake_proxy<F: FnOnce(StdTcpStream) + Send + 'static>(handler: F) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((sock, _)) = listener.accept() {
                handler(sock);
            }
        });
        addr
    }

    /// A non-blocking mio client stream connected to `addr` (loopback connect is
    /// synchronous, so no connect race in the test).
    fn dial(addr: SocketAddr) -> TcpStream {
        let s = StdTcpStream::connect(addr).unwrap();
        s.set_nonblocking(true).unwrap();
        TcpStream::from_std(s)
    }

    fn test_proxy(addr: SocketAddr, kind: proxy::ProxyKind) -> Proxy {
        Proxy::from_config(&proxy::ProxyConfig {
            kind,
            host: addr.ip().to_string(),
            ip: String::new(),
            port: addr.port(),
            username: None,
            password: None,
        })
        .unwrap()
    }

    #[test]
    fn loopback_http_connect_succeeds() {
        let addr = fake_proxy(|mut sock| {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 512];
            loop {
                let n = sock.read(&mut tmp).unwrap();
                if n == 0 {
                    return;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            assert!(buf.starts_with(b"CONNECT 1.2.3.4:443 "), "unexpected CONNECT: {buf:?}");
            let _ = sock.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
            thread::sleep(Duration::from_millis(50));
        });
        let proxy = test_proxy(addr, proxy::ProxyKind::Http);
        let mut io = UpstreamIo::Plain(dial(addr));
        let mut hs = Handshake::connect(&proxy, "1.2.3.4:443".parse().unwrap());
        let mut hs_out = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match pump_handshake_io(&mut io, &mut hs, &mut hs_out) {
                HsPump::Done { .. } => break,
                HsPump::Failed => panic!("HTTP CONNECT handshake failed"),
                HsPump::Pending => {
                    assert!(Instant::now() < deadline, "handshake timed out");
                    thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }

    #[test]
    fn loopback_socks5_associate_succeeds() {
        let addr = fake_proxy(|mut sock| {
            let mut buf = [0u8; 512];
            let n = sock.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], &[0x05, 0x01, 0x00], "greeting (no-auth)");
            let _ = sock.write_all(&[0x05, 0x00]);
            let _ = sock.read(&mut buf).unwrap();
            assert_eq!(buf[0], 0x05);
            assert_eq!(buf[1], 0x03, "UDP ASSOCIATE command");
            // Reply: success, relay bound at 10.0.0.9:5555.
            let _ = sock.write_all(&[0x05, 0x00, 0x00, 0x01, 10, 0, 0, 9, 0x15, 0xB3]);
            thread::sleep(Duration::from_millis(50));
        });
        let proxy = test_proxy(addr, proxy::ProxyKind::Socks5);
        let mut stream = dial(addr);
        let mut hs = Handshake::udp_associate(&proxy);
        let mut hs_out = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match pump_ctrl_handshake(&mut stream, &mut hs, &mut hs_out) {
                CtrlStep::Ready(bound) => {
                    assert_eq!(bound, Some("10.0.0.9:5555".parse().unwrap()));
                    break;
                }
                CtrlStep::Failed => panic!("SOCKS5 associate failed"),
                CtrlStep::Pending => {
                    assert!(Instant::now() < deadline, "handshake timed out");
                    thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }

    #[test]
    fn loopback_socks5_refused_fails() {
        let addr = fake_proxy(|mut sock| {
            let mut buf = [0u8; 512];
            let _ = sock.read(&mut buf).unwrap(); // greeting
            let _ = sock.write_all(&[0x05, 0x00]);
            let _ = sock.read(&mut buf).unwrap(); // CONNECT request
            // REP 0x05 = connection refused.
            let _ = sock.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            thread::sleep(Duration::from_millis(50));
        });
        let proxy = test_proxy(addr, proxy::ProxyKind::Socks5);
        let mut stream = dial(addr);
        let mut hs = Handshake::connect(&proxy, "1.2.3.4:80".parse().unwrap());
        let mut hs_out = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match pump_ctrl_handshake(&mut stream, &mut hs, &mut hs_out) {
                CtrlStep::Failed => break, // expected: proxy refused
                CtrlStep::Ready(_) => panic!("should have failed on REP 5"),
                CtrlStep::Pending => {
                    assert!(Instant::now() < deadline, "handshake timed out");
                    thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }
}
