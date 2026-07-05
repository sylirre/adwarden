//! Transparent forwarding: relays intercepted flows to real upstream servers
//! over `protect()`ed sockets so allowed traffic reaches the internet instead of
//! being black-holed.
//!
//! TCP rides the smoltcp proxy in `adwarden_netstack::NetStack`; the upstream
//! side is a `protect()`ed non-blocking `TcpStream`. UDP is a small NAT table of
//! `protect()`ed connected `UdpSocket`s. All sockets share the datapath thread's
//! mio `Poll` via tokens allocated here.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
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

use crate::bridge::Bridge;
use crate::config::Config;
use crate::event::{Batcher, Event};

const DOT_PORT: u16 = 853;
const PROTO_TCP: i32 = 6;
const PROTO_UDP: i32 = 17;
const VERDICT_CACHE_CAP: usize = 4096;

/// Current default network transport, matching Kotlin's NetworkStateMonitor.
pub const TRANSPORT_OTHER: u8 = 0;
pub const TRANSPORT_WIFI: u8 = 1;
pub const TRANSPORT_CELLULAR: u8 = 2;

/// Per-app firewall policy: allowed on Wi-Fi / cellular.
#[derive(Clone, Copy)]
pub struct AppPolicy {
    pub allow_wifi: bool,
    pub allow_cellular: bool,
}

/// First token handed to an upstream socket (0/1 are reserved for TUN/waker).
const FIRST_DYNAMIC_TOKEN: usize = 16;
const UDP_IDLE_MS: i64 = 60_000;
const MAX_DATAGRAM: usize = 65_535;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct UdpKey {
    app: SocketAddr,
    server: SocketAddr,
}

enum Route {
    Tcp(FlowId),
    Udp(UdpKey),
}

struct TcpUpstream {
    stream: TcpStream,
    token: Token,
    connecting: bool,
    to_upstream: Vec<u8>,
    write_closed: bool,
}

struct UdpSession {
    socket: UdpSocket,
    token: Token,
    app: SocketAddr,
    server: SocketAddr,
    last_used_ms: i64,
}

pub struct Forwarder {
    stack: NetStack,
    registry: Registry,
    tcp: HashMap<FlowId, TcpUpstream>,
    udp: HashMap<UdpKey, UdpSession>,
    routes: HashMap<Token, Route>,
    next_token: usize,
    outbox: Vec<Vec<u8>>,
    start: StdInstant,
    engine: Option<FilterEngine>,
    block_encrypted_dns: bool,
    firewall: HashMap<i32, AppPolicy>,
    transport: u8,
    verdicts: FlowTable<Verdict>,
    pcap: Option<PcapWriter<File>>,
    dns_upstream_v4: IpAddr,
    dns_upstream_v6: IpAddr,
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
        Forwarder {
            stack: NetStack::new(config.mtu),
            registry,
            tcp: HashMap::new(),
            udp: HashMap::new(),
            routes: HashMap::new(),
            next_token: FIRST_DYNAMIC_TOKEN,
            outbox: Vec::new(),
            start: StdInstant::now(),
            engine: None,
            block_encrypted_dns: config.block_encrypted_dns,
            firewall: HashMap::new(),
            transport: TRANSPORT_OTHER,
            verdicts: FlowTable::new(VERDICT_CACHE_CAP),
            pcap: None,
            dns_upstream_v4: dns_v4,
            dns_upstream_v6: dns_v6,
        }
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

    /// Write a packet to the capture, if one is active.
    fn tap(&mut self, packet: &[u8]) {
        if let Some(writer) = self.pcap.as_mut() {
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
            let _ = writer.write_packet(ts, packet);
        }
    }

    /// Load (or replace) the filter engine from its serialized cache file.
    pub fn load_engine(&mut self, path: &str) {
        if let Ok(bytes) = std::fs::read(path) {
            self.engine = FilterEngine::from_serialized(&bytes);
        }
    }

    pub fn set_block_encrypted_dns(&mut self, block: bool) {
        self.block_encrypted_dns = block;
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

    /// Resolve (and cache) the firewall verdict for a flow. Unknown UIDs and
    /// unruled apps are allowed.
    fn verdict(&mut self, decoded: &Decoded, proto: i32, env: &mut jni::JNIEnv, bridge: &Bridge) -> Verdict {
        let key = FlowKey::new(proto as u8, decoded.src, decoded.src_port, decoded.dst, decoded.dst_port);
        if let Some(cached) = self.verdicts.get(&key) {
            return *cached;
        }
        let uid = bridge.lookup_uid(
            env,
            proto,
            std::net::SocketAddr::new(decoded.src, decoded.src_port),
            std::net::SocketAddr::new(decoded.dst, decoded.dst_port),
        );
        let blocked = self.policy_blocks(uid);
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
        self.tap(packet); // capture every inbound packet, whatever its verdict
        let Some(decoded) = adwarden_netstack::decode(packet) else { return };
        match decoded.proto {
            L4::Tcp => {
                if self.block_encrypted_dns && decoded.dst_port == DOT_PORT {
                    batcher.push(Event::blocked(&decoded)); // DoT: drop, app connect fails
                    return;
                }
                let verdict = self.verdict(&decoded, PROTO_TCP, env, bridge);
                if verdict.blocked {
                    // RST the app so it fails fast instead of timing out.
                    if let Some(rst) = reset_for_syn(packet) {
                        self.outbox.push(rst);
                    }
                    batcher.push(Event::blocked(&decoded).with_uid(verdict.uid));
                    return;
                }
                batcher.push(Event::flow(&decoded).with_uid(verdict.uid));
                if let Some((id, server)) = self.stack.on_tcp_packet(packet) {
                    self.open_tcp(id, server, env, bridge);
                }
            }
            L4::Udp => {
                if self.block_encrypted_dns && decoded.dst_port == DOT_PORT {
                    batcher.push(Event::blocked(&decoded));
                    return;
                }
                let verdict = self.verdict(&decoded, PROTO_UDP, env, bridge);
                if verdict.blocked {
                    batcher.push(Event::blocked(&decoded).with_uid(verdict.uid));
                    return; // firewall drop (covers this app's DNS too)
                }
                let is_dns = decoded.dst_port == 53 || decoded.dst_port == 5353;
                if let Some(dgram) = udp::parse(packet) {
                    if is_dns && self.handle_dns(&decoded, &dgram, batcher) {
                        return; // sinkholed: NXDOMAIN already injected
                    }
                    batcher.push(Event::flow(&decoded).with_uid(verdict.uid));
                    // Allowed DNS goes to the real upstream (the app targeted a
                    // tunnel-local placeholder); everything else keeps its dst.
                    let upstream = if is_dns {
                        self.dns_upstream(dgram.dst)
                    } else {
                        dgram.dst
                    };
                    self.forward_udp(dgram, upstream, env, bridge);
                } else {
                    batcher.push(Event::flow(&decoded).with_uid(verdict.uid));
                }
            }
            _ => {
                batcher.push(Event::flow(&decoded)); // ICMP / other: logged, dropped
            }
        }
    }

    /// Intercept a DNS query: if the engine blocks the name, inject an NXDOMAIN
    /// response toward the app and report a block. Returns true when sinkholed.
    fn handle_dns(&mut self, decoded: &Decoded, dgram: &udp::UdpDatagram, batcher: &mut Batcher) -> bool {
        let Some(query) = adwarden_dns::parse_query(&dgram.payload) else { return false };
        let blocked = self
            .engine
            .as_ref()
            .map_or(false, |engine| engine.is_blocked_domain(&query.name));
        if !blocked {
            return false;
        }
        let response = adwarden_dns::synthesize_nxdomain(&dgram.payload, &query);
        if let Some(packet) = udp::build_reply(dgram.dst, dgram.src, &response) {
            self.outbox.push(packet);
        }
        batcher.push(Event::blocked_domain(decoded, query.name));
        true
    }

    /// Advance the stack and pump both directions of every flow.
    pub fn service(&mut self, _env: &mut jni::JNIEnv, _bridge: &Bridge, _batcher: &mut Batcher) {
        let now = self.now_ms();
        let outcome = self.stack.poll(now);
        for id in outcome.closed {
            self.teardown_tcp(id);
            self.stack.remove_flow(id);
        }

        // App -> upstream for each active flow.
        for id in self.stack.active_flows() {
            let data = self.stack.tcp_take_app_data(id);
            if !data.is_empty() {
                if let Some(up) = self.tcp.get_mut(&id) {
                    up.to_upstream.extend_from_slice(&data);
                }
            }
            self.flush_to_upstream(id);
            // Propagate the app's half-close once its data is drained.
            if self.stack.tcp_app_finished(id) {
                if let Some(up) = self.tcp.get_mut(&id) {
                    if up.to_upstream.is_empty() && !up.write_closed {
                        let _ = up.stream.shutdown(std::net::Shutdown::Write);
                        up.write_closed = true;
                    }
                }
            }
        }

        self.reap_udp(now);
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
                    if let Some(up) = self.tcp.get_mut(&id) {
                        up.connecting = false;
                    }
                    self.flush_to_upstream(id);
                }
                if event.is_readable() {
                    self.pump_upstream_to_app(id);
                }
                if event.is_read_closed() || event.is_write_closed() {
                    self.pump_upstream_to_app(id);
                    self.stack.tcp_close_app(id);
                }
            }
            Some(Route::Udp(key)) => {
                let key = *key;
                self.pump_udp_reply(key, batcher);
            }
            None => {}
        }
    }

    // --- TCP -------------------------------------------------------------

    fn open_tcp(&mut self, id: FlowId, server: SocketAddr, env: &mut jni::JNIEnv, bridge: &Bridge) {
        match self.connect_tcp(server, env, bridge) {
            Some((stream, token)) => {
                self.routes.insert(token, Route::Tcp(id));
                self.tcp.insert(
                    id,
                    TcpUpstream { stream, token, connecting: true, to_upstream: Vec::new(), write_closed: false },
                );
            }
            None => {
                // Couldn't reach upstream: RST the app so it fails fast.
                self.stack.tcp_abort(id);
            }
        }
    }

    fn connect_tcp(&mut self, server: SocketAddr, env: &mut jni::JNIEnv, bridge: &Bridge) -> Option<(TcpStream, Token)> {
        let domain = if server.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::STREAM, None).ok()?;
        socket.set_nonblocking(true).ok()?;
        if !bridge.protect(env, socket.as_raw_fd()) {
            return None;
        }
        // Non-blocking connect returns EINPROGRESS; that's expected.
        let _ = socket.connect(&server.into());
        let std_stream: std::net::TcpStream = socket.into();
        let mut stream = TcpStream::from_std(std_stream);
        let token = self.alloc_token();
        self.registry
            .register(&mut stream, token, Interest::READABLE | Interest::WRITABLE)
            .ok()?;
        Some((stream, token))
    }

    fn flush_to_upstream(&mut self, id: FlowId) {
        let Some(up) = self.tcp.get_mut(&id) else { return };
        if up.connecting || up.to_upstream.is_empty() {
            return;
        }
        let mut written = 0;
        while written < up.to_upstream.len() {
            match up.stream.write(&up.to_upstream[written..]) {
                Ok(0) => break,
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.stack.tcp_abort(id);
                    return;
                }
            }
        }
        if written > 0 {
            up.to_upstream.drain(..written);
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
            match up.stream.read(&mut buf) {
                Ok(0) => {
                    // Upstream EOF -> half-close toward the app.
                    self.stack.tcp_close_app(id);
                    break;
                }
                Ok(n) => {
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
        if let Some(mut up) = self.tcp.remove(&id) {
            let _ = self.registry.deregister(&mut up.stream);
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
                self.routes.insert(token, Route::Udp(key));
                self.udp.insert(
                    key,
                    UdpSession { socket, token, app: dgram.src, server: dgram.dst, last_used_ms: now },
                );
            } else {
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
        if !bridge.protect(env, socket.as_raw_fd()) {
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
}
