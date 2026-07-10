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
use adwarden_tls::{peek_sni, write_har, DnsKind, HttpTransaction, MitmConfigs, SniPeek, TlsMitm};

use crate::bridge::Bridge;
use crate::config::{Config, EncryptedDnsMode};
use crate::event::{Batcher, Event};

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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct UdpKey {
    app: SocketAddr,
    server: SocketAddr,
}

enum Route {
    Tcp(FlowId),
    Udp(UdpKey),
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

struct TcpUpstream {
    stream: TcpStream,
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
    /// Deferred DoH classification state (P3). `Settled` for every flow except a
    /// 443 flow under Filter mode, which peeks the SNI before deciding.
    classify: Classify,
}

struct UdpSession {
    socket: UdpSocket,
    token: Token,
    app: SocketAddr,
    server: SocketAddr,
    last_used_ms: i64,
}

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
    encrypted_dns_mode: EncryptedDnsMode,
    firewall: HashMap<i32, AppPolicy>,
    transport: u8,
    verdicts: FlowTable<Verdict>,
    pcap: Option<PcapWriter<File>>,
    dns_upstream_v4: IpAddr,
    dns_upstream_v6: IpAddr,
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
            encrypted_dns_mode: config.encrypted_dns_mode,
            firewall: HashMap::new(),
            transport: TRANSPORT_OTHER,
            verdicts: FlowTable::new(VERDICT_CACHE_CAP),
            pcap: None,
            dns_upstream_v4: dns_v4,
            dns_upstream_v6: dns_v6,
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
        (self.tcp.len(), self.udp.len())
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
        // No per-app rules -> allow everything without the (per-flow, binder)
        // getConnectionOwnerUid upcall. This keeps DNS/browsing off the JNI path
        // entirely in the common case.
        if self.firewall.is_empty() {
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
                let is_dns = decoded.dst_port == 53 || decoded.dst_port == 5353;
                if let Some(dgram) = udp::parse(packet) {
                    if is_dns && self.handle_dns(&decoded, &dgram, batcher) {
                        return; // sinkholed: NXDOMAIN already injected
                    }
                    if self.coarse_mode(verdict.uid) {
                        self.coarse_add(decoded.length, L4::Udp, is_dns);
                    } else {
                        batcher.push(Event::flow(&decoded).with_uid(verdict.uid));
                    }
                    // Allowed DNS goes to the real upstream (the app targeted a
                    // tunnel-local placeholder); everything else keeps its dst.
                    let upstream = if is_dns {
                        self.dns_upstream(dgram.dst)
                    } else {
                        dgram.dst
                    };
                    self.forward_udp(dgram, upstream, env, bridge);
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
    pub fn service(&mut self, _env: &mut jni::JNIEnv, _bridge: &Bridge, batcher: &mut Batcher) {
        let now = self.now_ms();
        let outcome = self.stack.poll(now);
        for id in outcome.closed {
            self.teardown_tcp(id);
            self.stack.remove_flow(id);
        }

        // App -> upstream for each active flow.
        for id in self.stack.active_flows() {
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
                    let was_connecting = self.tcp.get(&id).map_or(false, |up| up.connecting);
                    if was_connecting {
                        if let Some(up) = self.tcp.get_mut(&id) {
                            up.connecting = false;
                        }
                        // A non-blocking connect that failed still reports
                        // writable, with the error latched on the socket.
                        let err = self
                            .tcp
                            .get(&id)
                            .and_then(|up| up.stream.take_error().ok().flatten());
                        if err.is_some() {
                            self.stats.connect_fail += 1;
                            self.stack.tcp_abort(id);
                            return;
                        }
                    }
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
            Some((stream, token)) => {
                self.stats.tcp_new += 1;
                self.routes.insert(token, Route::Tcp(id));
                self.tcp.insert(
                    id,
                    TcpUpstream {
                        stream,
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
                        classify,
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

        // Not DoH: fall back to today's behavior for a 443 flow — cosmetic
        // interception for an opted-in app, otherwise raw relay.
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

    /// Feed buffered app bytes into a just-attached splice and advance it.
    fn feed_and_drive(&mut self, id: FlowId, data: &[u8], batcher: &mut Batcher) {
        if !data.is_empty() {
            if let Some(mitm) = self.tcp.get_mut(&id).and_then(|up| up.mitm.as_mut()) {
                mitm.recv_from_app(data);
            }
        }
        self.drive_mitm(id, batcher);
    }

    fn connect_tcp(&mut self, server: SocketAddr, env: &mut jni::JNIEnv, bridge: &Bridge) -> Option<(TcpStream, Token)> {
        let domain = if server.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::STREAM, None).ok()?;
        socket.set_nonblocking(true).ok()?;
        if bridge.protect(env, socket.as_raw_fd()) {
            self.stats.protect_ok += 1;
        } else {
            self.stats.protect_fail += 1;
            crate::alog!("protect() failed for upstream TCP socket -> {}", server);
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
        let mut failed = false;
        while written < up.to_upstream.len() {
            match up.stream.write(&up.to_upstream[written..]) {
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
                    let _ = up.stream.shutdown(std::net::Shutdown::Write);
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
            match up.stream.read(&mut buf) {
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
            match up.stream.read(&mut buf) {
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
