// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! Upstream proxy support (P5): forward allowed flows through an HTTP, HTTPS
//! (TLS-to-proxy), or SOCKS5 proxy instead of dialing the origin directly.
//!
//! This module is the *protocol* layer only — pure, sans-I/O, host-testable. The
//! byte pump that drives these state machines over a real (`protect()`ed) socket
//! lives in [`crate::forward`], which also wraps an HTTPS proxy's transport in a
//! rustls session. Keeping the wire logic here means it can be unit-tested with
//! plain buffers, no sockets or JVM.
//!
//! Handshake model: [`Handshake::step`] is fed the bytes received from the proxy
//! so far and returns the next [`Step`] — write these bytes, read more, or the
//! tunnel is open. The same machine drives a SOCKS5 CONNECT (TCP) or UDP
//! ASSOCIATE; HTTP/HTTPS use the `CONNECT` request/response.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::Deserialize;

/// Which proxy protocol (if any) upstream flows are forwarded through. Serialized
/// from the native config JSON as the lowercase variant name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    /// No proxy — dial the origin directly (today's behavior).
    #[default]
    None,
    /// HTTP `CONNECT` over a plaintext connection to the proxy.
    Http,
    /// HTTP `CONNECT` tunneled inside a TLS session to the proxy.
    Https,
    /// SOCKS5 (RFC 1928) with optional username/password auth (RFC 1929).
    Socks5,
}

/// Proxy configuration as received from Kotlin.
///
/// Hostnames are resolved on the Kotlin side (the app is excluded from its own
/// tunnel via `addDisallowedApplication`, so its resolution egresses normally),
/// avoiding a blocking `getaddrinfo` on the datapath thread. `ip` carries the
/// resolved dial address; `host` carries the user's original input, used as the
/// TLS SNI / verification name for an HTTPS proxy. When `ip` is empty, `host` is
/// parsed as the literal IP (so a user who typed an IP needs no resolution step).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ProxyConfig {
    #[serde(default)]
    pub kind: ProxyKind,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// A validated, ready-to-dial proxy. Built from [`ProxyConfig`] once at session
/// start; `None` when disabled or misconfigured (the caller then dials direct and
/// logs — a config typo must not brick connectivity, whereas a *reachable* proxy
/// that fails a flow is handled fail-closed by the datapath).
#[derive(Debug, Clone)]
pub struct Proxy {
    pub kind: ProxyKind,
    pub addr: SocketAddr,
    /// TLS SNI / verification name for an HTTPS proxy (the user's original host).
    pub server_name: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Proxy {
    /// Validate a config into a dialable proxy, or `None` when disabled/invalid.
    pub fn from_config(c: &ProxyConfig) -> Option<Proxy> {
        if c.kind == ProxyKind::None {
            return None;
        }
        // Dial the resolved IP when present, else parse the host as a literal IP.
        let dial = if c.ip.trim().is_empty() { c.host.trim() } else { c.ip.trim() };
        let ip: IpAddr = dial.parse().ok()?;
        if c.port == 0 {
            return None;
        }
        let server_name = if c.host.trim().is_empty() { dial } else { c.host.trim() };
        let clean = |s: &Option<String>| s.as_ref().filter(|v| !v.is_empty()).cloned();
        Some(Proxy {
            kind: c.kind,
            addr: SocketAddr::new(ip, c.port),
            server_name: server_name.to_string(),
            username: clean(&c.username),
            password: clean(&c.password),
        })
    }

    /// Whether the transport to the proxy itself is TLS (an HTTPS proxy).
    pub fn is_tls(&self) -> bool {
        self.kind == ProxyKind::Https
    }

    /// Whether this proxy can carry UDP (only SOCKS5, via UDP ASSOCIATE).
    pub fn supports_udp(&self) -> bool {
        self.kind == ProxyKind::Socks5
    }
}

/// A proxy handshake failed; the flow must be torn down (fail-closed). Rendered
/// into the datapath log, never surfaced to the app beyond a connection reset.
#[derive(Debug, PartialEq, Eq)]
pub enum ProxyError {
    /// HTTP proxy answered with a non-2xx status.
    HttpStatus(u16),
    /// HTTP proxy response wasn't a parseable status line.
    HttpMalformed,
    /// Response headers exceeded the buffer cap without terminating.
    HeaderTooLarge,
    /// SOCKS reply carried an unexpected version byte.
    Socks5Version(u8),
    /// SOCKS server offered no authentication method we support (0xFF, or asked
    /// for user/pass when we have no credentials).
    Socks5NoAcceptableAuth,
    /// SOCKS username/password auth was rejected (non-zero status).
    Socks5AuthFailed(u8),
    /// SOCKS CONNECT/ASSOCIATE reply carried a non-success REP code.
    Socks5Reply(u8),
    /// SOCKS reply was structurally invalid (bad ATYP, etc.).
    Socks5Malformed,
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::HttpStatus(c) => write!(f, "HTTP proxy refused CONNECT (status {c})"),
            ProxyError::HttpMalformed => write!(f, "malformed HTTP proxy response"),
            ProxyError::HeaderTooLarge => write!(f, "HTTP proxy response headers too large"),
            ProxyError::Socks5Version(v) => write!(f, "unexpected SOCKS version {v}"),
            ProxyError::Socks5NoAcceptableAuth => write!(f, "SOCKS proxy: no acceptable auth method"),
            ProxyError::Socks5AuthFailed(s) => write!(f, "SOCKS proxy auth rejected (status {s})"),
            ProxyError::Socks5Reply(r) => write!(f, "SOCKS proxy refused request (rep {r})"),
            ProxyError::Socks5Malformed => write!(f, "malformed SOCKS proxy reply"),
        }
    }
}

/// One turn of the handshake driver's loop.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// Send these bytes to the proxy, then read more.
    Write(Vec<u8>),
    /// Nothing to send yet; read more from the proxy.
    Read,
    /// The tunnel is established. `leftover` is any already-received data that
    /// belongs to the tunneled stream (bytes from the origin) — normally empty
    /// for CONNECT/SOCKS, forwarded toward the app if present.
    Done { leftover: Vec<u8> },
}

/// SOCKS5 command: TCP CONNECT vs. UDP ASSOCIATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5Command {
    Connect,
    UdpAssociate,
}

impl Socks5Command {
    fn code(self) -> u8 {
        match self {
            Socks5Command::Connect => 0x01,
            Socks5Command::UdpAssociate => 0x03,
        }
    }
}

/// Per-protocol handshake progress (what we've already sent).
enum Machine {
    /// HTTP `CONNECT`; `sent` once the request has been emitted.
    Http { sent: bool },
    /// SOCKS5; `phase` tracks the last message we sent.
    Socks5 { phase: Socks5Phase, command: Socks5Command },
}

#[derive(PartialEq, Eq)]
enum Socks5Phase {
    /// Nothing sent yet — the next step emits the greeting.
    Start,
    /// Greeting sent; awaiting the method selection.
    Greeted,
    /// Username/password auth sent; awaiting its status.
    Authed,
    /// CONNECT/ASSOCIATE request sent; awaiting the final reply.
    Requested,
}

/// Cap on buffered proxy-response bytes before a handshake is abandoned. Bounds
/// memory against a hostile/broken proxy that never terminates its reply.
const HANDSHAKE_BUF_CAP: usize = 8 * 1024;

/// Drives a single flow's proxy handshake. Fed the bytes received from the proxy
/// via [`Handshake::step`]; emits [`Step`]s until the tunnel opens or it errors.
pub struct Handshake {
    target: SocketAddr,
    username: Option<String>,
    password: Option<String>,
    machine: Machine,
    inbuf: Vec<u8>,
    /// The relay/bound address from a SOCKS reply — the UDP relay endpoint after a
    /// successful ASSOCIATE. Set when the reply parses.
    bound: Option<SocketAddr>,
}

impl Handshake {
    /// Start a TCP-CONNECT handshake toward `target` through `proxy`. HTTPS uses
    /// the same `CONNECT` machine as HTTP — the TLS wrapping is the caller's job.
    pub fn connect(proxy: &Proxy, target: SocketAddr) -> Handshake {
        let machine = match proxy.kind {
            ProxyKind::Socks5 => Machine::Socks5 { phase: Socks5Phase::Start, command: Socks5Command::Connect },
            _ => Machine::Http { sent: false },
        };
        Handshake {
            target,
            username: proxy.username.clone(),
            password: proxy.password.clone(),
            machine,
            inbuf: Vec::new(),
            bound: None,
        }
    }

    /// Start a SOCKS5 UDP-ASSOCIATE handshake. Only valid for a SOCKS5 proxy; the
    /// `target` field is the advertised client source (all-zero — "unknown yet").
    pub fn udp_associate(proxy: &Proxy) -> Handshake {
        Handshake {
            target: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            username: proxy.username.clone(),
            password: proxy.password.clone(),
            machine: Machine::Socks5 { phase: Socks5Phase::Start, command: Socks5Command::UdpAssociate },
            inbuf: Vec::new(),
            bound: None,
        }
    }

    /// The UDP relay endpoint learned from a successful ASSOCIATE reply. When the
    /// proxy returned an all-zero bound address it means "same host as the control
    /// connection" — the caller substitutes the proxy's own IP.
    pub fn bound_addr(&self) -> Option<SocketAddr> {
        self.bound
    }

    /// Advance the handshake with newly-received `input` bytes (empty on the first
    /// call, which produces the opening message).
    pub fn step(&mut self, input: &[u8]) -> Result<Step, ProxyError> {
        self.inbuf.extend_from_slice(input);
        if self.inbuf.len() > HANDSHAKE_BUF_CAP {
            return Err(ProxyError::HeaderTooLarge);
        }
        match &mut self.machine {
            Machine::Http { sent } => {
                if !*sent {
                    *sent = true;
                    return Ok(Step::Write(self.build_http_connect()));
                }
                Self::parse_http_reply(&self.inbuf)
            }
            Machine::Socks5 { phase, command } => {
                let command = *command;
                Self::socks5_step(
                    phase,
                    command,
                    self.target,
                    self.username.as_deref(),
                    self.password.as_deref(),
                    &mut self.inbuf,
                    &mut self.bound,
                )
            }
        }
    }

    fn build_http_connect(&self) -> Vec<u8> {
        // `SocketAddr` Display already brackets IPv6 (`[::1]:443`), which is
        // exactly the authority-form CONNECT expects.
        let authority = self.target.to_string();
        let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some(user) = &self.username {
            let pass = self.password.as_deref().unwrap_or("");
            let token = base64_encode(format!("{user}:{pass}").as_bytes());
            req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
        }
        req.push_str("Proxy-Connection: keep-alive\r\n\r\n");
        req.into_bytes()
    }

    fn parse_http_reply(buf: &[u8]) -> Result<Step, ProxyError> {
        let Some(end) = find_headers_end(buf) else {
            return Ok(Step::Read);
        };
        // Status line: "HTTP/1.1 200 Connection established".
        let line_end = buf.iter().position(|&b| b == b'\r').unwrap_or(end);
        let line = &buf[..line_end];
        let mut parts = line.split(|&b| b == b' ');
        let _version = parts.next().ok_or(ProxyError::HttpMalformed)?;
        let code = parts.next().ok_or(ProxyError::HttpMalformed)?;
        let code: u16 = std::str::from_utf8(code)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(ProxyError::HttpMalformed)?;
        if (200..300).contains(&code) {
            Ok(Step::Done { leftover: buf[end..].to_vec() })
        } else {
            Err(ProxyError::HttpStatus(code))
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn socks5_step(
        phase: &mut Socks5Phase,
        command: Socks5Command,
        target: SocketAddr,
        username: Option<&str>,
        password: Option<&str>,
        inbuf: &mut Vec<u8>,
        bound: &mut Option<SocketAddr>,
    ) -> Result<Step, ProxyError> {
        match phase {
            Socks5Phase::Start => {
                *phase = Socks5Phase::Greeted;
                Ok(Step::Write(socks5_greeting(username.is_some())))
            }
            Socks5Phase::Greeted => {
                if inbuf.len() < 2 {
                    return Ok(Step::Read);
                }
                if inbuf[0] != 0x05 {
                    return Err(ProxyError::Socks5Version(inbuf[0]));
                }
                let method = inbuf[1];
                inbuf.drain(..2);
                match method {
                    0x00 => {
                        *phase = Socks5Phase::Requested;
                        Ok(Step::Write(socks5_request(command, target)))
                    }
                    0x02 if username.is_some() => {
                        *phase = Socks5Phase::Authed;
                        Ok(Step::Write(socks5_userpass(
                            username.unwrap_or(""),
                            password.unwrap_or(""),
                        )))
                    }
                    _ => Err(ProxyError::Socks5NoAcceptableAuth),
                }
            }
            Socks5Phase::Authed => {
                if inbuf.len() < 2 {
                    return Ok(Step::Read);
                }
                // RFC 1929 reply: VER(0x01) STATUS. STATUS 0 = success.
                let status = inbuf[1];
                inbuf.drain(..2);
                if status != 0 {
                    return Err(ProxyError::Socks5AuthFailed(status));
                }
                *phase = Socks5Phase::Requested;
                Ok(Step::Write(socks5_request(command, target)))
            }
            Socks5Phase::Requested => {
                let Some(reply_len) = socks5_reply_len(inbuf)? else {
                    return Ok(Step::Read);
                };
                if inbuf[0] != 0x05 {
                    return Err(ProxyError::Socks5Version(inbuf[0]));
                }
                let rep = inbuf[1];
                if rep != 0x00 {
                    return Err(ProxyError::Socks5Reply(rep));
                }
                *bound = parse_socks5_bound(&inbuf[..reply_len]);
                let leftover = inbuf.split_off(reply_len);
                Ok(Step::Done { leftover })
            }
        }
    }
}

/// SOCKS5 greeting: version, method count, methods. Always offers no-auth; adds
/// username/password when credentials are configured.
fn socks5_greeting(with_auth: bool) -> Vec<u8> {
    if with_auth {
        vec![0x05, 0x02, 0x00, 0x02]
    } else {
        vec![0x05, 0x01, 0x00]
    }
}

/// RFC 1929 username/password auth message.
fn socks5_userpass(user: &str, pass: &str) -> Vec<u8> {
    // Field lengths are single-byte; clamp defensively (a >255-char credential is
    // nonsensical and the wire format can't express it).
    let ub = user.as_bytes();
    let pb = pass.as_bytes();
    let ulen = ub.len().min(255);
    let plen = pb.len().min(255);
    let mut out = Vec::with_capacity(3 + ulen + plen);
    out.push(0x01);
    out.push(ulen as u8);
    out.extend_from_slice(&ub[..ulen]);
    out.push(plen as u8);
    out.extend_from_slice(&pb[..plen]);
    out
}

/// SOCKS5 request: VER CMD RSV ATYP DST.ADDR DST.PORT.
fn socks5_request(command: Socks5Command, target: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.push(0x05);
    out.push(command.code());
    out.push(0x00);
    push_socks_addr(&mut out, target);
    out
}

/// Append an ATYP + address + big-endian port to a SOCKS message.
fn push_socks_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

/// Total byte length of the SOCKS5 reply at the front of `buf`, or `None` if more
/// bytes are needed. Errors only on a structurally impossible ATYP.
fn socks5_reply_len(buf: &[u8]) -> Result<Option<usize>, ProxyError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let addr_len = match buf[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            // Domain: one length byte then that many address bytes.
            if buf.len() < 5 {
                return Ok(None);
            }
            1 + buf[4] as usize
        }
        _ => return Err(ProxyError::Socks5Malformed),
    };
    let total = 4 + addr_len + 2;
    if buf.len() < total {
        Ok(None)
    } else {
        Ok(Some(total))
    }
}

/// Extract the bound address from a full SOCKS5 reply (length already validated).
fn parse_socks5_bound(reply: &[u8]) -> Option<SocketAddr> {
    match reply.get(3)? {
        0x01 => {
            let ip = Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7]);
            let port = u16::from_be_bytes([reply[8], reply[9]]);
            Some(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x04 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&reply[4..20]);
            let port = u16::from_be_bytes([reply[20], reply[21]]);
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        // A domain bound address can't be dialed without resolution; the caller
        // falls back to the proxy IP (the RFC-blessed reading of an unusable BND).
        _ => None,
    }
}

/// Wrap a UDP payload in a SOCKS5 request header (RSV RSV FRAG ATYP ADDR PORT)
/// for sending to the UDP relay after an ASSOCIATE.
pub fn socks5_udp_encapsulate(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 22);
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV(2) + FRAG(0)
    push_socks_addr(&mut out, target);
    out.extend_from_slice(payload);
    out
}

/// Strip the SOCKS5 UDP header off a relayed datagram, yielding the origin
/// address and the inner payload. `None` on a fragment (FRAG != 0, unsupported)
/// or malformed/domain header.
pub fn socks5_udp_decapsulate(dgram: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if dgram.len() < 4 || dgram[2] != 0x00 {
        return None;
    }
    let (ip, addr_end) = match dgram[3] {
        0x01 => {
            if dgram.len() < 10 {
                return None;
            }
            (IpAddr::V4(Ipv4Addr::new(dgram[4], dgram[5], dgram[6], dgram[7])), 8)
        }
        0x04 => {
            if dgram.len() < 22 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&dgram[4..20]);
            (IpAddr::V6(Ipv6Addr::from(octets)), 20)
        }
        _ => return None,
    };
    let port = u16::from_be_bytes([dgram[addr_end], dgram[addr_end + 1]]);
    Some((SocketAddr::new(ip, port), &dgram[addr_end + 2..]))
}

/// Find the byte offset just past the `\r\n\r\n` header terminator, if present.
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Standard-alphabet base64 (for `Proxy-Authorization: Basic`). Kept local so the
/// core crate needs no base64 dependency.
fn base64_encode(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 { T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(b2 & 0x3f) as usize] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socks5_proxy() -> Proxy {
        Proxy::from_config(&ProxyConfig {
            kind: ProxyKind::Socks5,
            host: "127.0.0.1".into(),
            ip: String::new(),
            port: 1080,
            username: None,
            password: None,
        })
        .unwrap()
    }

    #[test]
    fn from_config_validates_and_disables() {
        assert!(Proxy::from_config(&ProxyConfig::default()).is_none());
        // Enabled but no address.
        assert!(Proxy::from_config(&ProxyConfig { kind: ProxyKind::Http, ..Default::default() }).is_none());
        // Hostname (not an IP) is rejected here — Kotlin resolves before passing.
        assert!(Proxy::from_config(&ProxyConfig {
            kind: ProxyKind::Http,
            host: "proxy.example".into(),
            port: 8080,
            ..Default::default()
        })
        .is_none());
        // Zero port is invalid.
        assert!(Proxy::from_config(&ProxyConfig {
            kind: ProxyKind::Http,
            host: "10.0.0.1".into(),
            port: 0,
            ..Default::default()
        })
        .is_none());
        let p = Proxy::from_config(&ProxyConfig {
            kind: ProxyKind::Https,
            host: "10.0.0.1".into(),
            ip: String::new(),
            port: 3128,
            username: Some("".into()), // empty ⇒ treated as no auth
            password: None,
        })
        .unwrap();
        assert!(p.is_tls());
        assert!(!p.supports_udp());
        assert!(p.username.is_none());
    }

    #[test]
    fn http_connect_request_shape_and_auth() {
        let proxy = Proxy::from_config(&ProxyConfig {
            kind: ProxyKind::Http,
            host: "10.0.0.1".into(),
            ip: String::new(),
            port: 8080,
            username: Some("user".into()),
            password: Some("pw".into()),
        })
        .unwrap();
        let target: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let mut hs = Handshake::connect(&proxy, target);
        let Step::Write(bytes) = hs.step(&[]).unwrap() else { panic!("expected initial write") };
        let req = String::from_utf8(bytes).unwrap();
        assert!(req.starts_with("CONNECT 93.184.216.34:443 HTTP/1.1\r\n"), "{req:?}");
        assert!(req.contains("Host: 93.184.216.34:443\r\n"));
        // base64("user:pw") == "dXNlcjpwdw=="
        assert!(req.contains("Proxy-Authorization: Basic dXNlcjpwdw==\r\n"), "{req:?}");
        assert!(req.ends_with("\r\n\r\n"));
    }

    #[test]
    fn http_connect_success_and_leftover() {
        let proxy = Proxy::from_config(&ProxyConfig {
            kind: ProxyKind::Http,
            host: "10.0.0.1".into(),
            port: 8080,
            ..Default::default()
        })
        .unwrap();
        let mut hs = Handshake::connect(&proxy, "1.2.3.4:443".parse().unwrap());
        assert!(matches!(hs.step(&[]).unwrap(), Step::Write(_)));
        // Split response across two reads; trailing bytes are tunnel data.
        assert_eq!(hs.step(b"HTTP/1.1 200 Conn").unwrap(), Step::Read);
        let done = hs.step(b"ection established\r\n\r\nHELLO").unwrap();
        assert_eq!(done, Step::Done { leftover: b"HELLO".to_vec() });
    }

    #[test]
    fn http_connect_rejected() {
        let proxy = Proxy::from_config(&ProxyConfig {
            kind: ProxyKind::Http,
            host: "10.0.0.1".into(),
            port: 8080,
            ..Default::default()
        })
        .unwrap();
        let mut hs = Handshake::connect(&proxy, "1.2.3.4:443".parse().unwrap());
        let _ = hs.step(&[]).unwrap();
        assert_eq!(
            hs.step(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"),
            Err(ProxyError::HttpStatus(407)),
        );
    }

    #[test]
    fn socks5_no_auth_connect() {
        let proxy = socks5_proxy();
        let target: SocketAddr = "1.2.3.4:443".parse().unwrap();
        let mut hs = Handshake::connect(&proxy, target);
        // Greeting: no-auth only.
        assert_eq!(hs.step(&[]).unwrap(), Step::Write(vec![0x05, 0x01, 0x00]));
        // Server selects no-auth ⇒ we send the CONNECT request.
        let Step::Write(req) = hs.step(&[0x05, 0x00]).unwrap() else { panic!() };
        assert_eq!(req, vec![0x05, 0x01, 0x00, 0x01, 1, 2, 3, 4, 0x01, 0xBB]);
        // Partial reply → Read; then a full success reply → Done.
        assert_eq!(hs.step(&[0x05, 0x00, 0x00]).unwrap(), Step::Read);
        let done = hs.step(&[0x01, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(done, Step::Done { leftover: Vec::new() });
    }

    #[test]
    fn socks5_userpass_flow() {
        let proxy = Proxy::from_config(&ProxyConfig {
            kind: ProxyKind::Socks5,
            host: "127.0.0.1".into(),
            ip: String::new(),
            port: 1080,
            username: Some("u".into()),
            password: Some("p".into()),
        })
        .unwrap();
        let mut hs = Handshake::connect(&proxy, "1.2.3.4:80".parse().unwrap());
        // Greeting offers no-auth AND user/pass.
        assert_eq!(hs.step(&[]).unwrap(), Step::Write(vec![0x05, 0x02, 0x00, 0x02]));
        // Server selects user/pass ⇒ we send RFC1929 auth.
        assert_eq!(
            hs.step(&[0x05, 0x02]).unwrap(),
            Step::Write(vec![0x01, 1, b'u', 1, b'p']),
        );
        // Auth OK ⇒ CONNECT request.
        assert!(matches!(hs.step(&[0x01, 0x00]).unwrap(), Step::Write(_)));
        // Reply OK.
        assert_eq!(
            hs.step(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).unwrap(),
            Step::Done { leftover: Vec::new() },
        );
    }

    #[test]
    fn socks5_auth_rejected_and_unacceptable() {
        let proxy = Proxy::from_config(&ProxyConfig {
            kind: ProxyKind::Socks5,
            host: "127.0.0.1".into(),
            ip: String::new(),
            port: 1080,
            username: Some("u".into()),
            password: Some("p".into()),
        })
        .unwrap();
        let mut hs = Handshake::connect(&proxy, "1.2.3.4:80".parse().unwrap());
        let _ = hs.step(&[]).unwrap();
        let _ = hs.step(&[0x05, 0x02]).unwrap();
        assert_eq!(hs.step(&[0x01, 0x01]), Err(ProxyError::Socks5AuthFailed(1)));

        // Server demands user/pass but we have none ⇒ unacceptable.
        let mut hs2 = Handshake::connect(&socks5_proxy(), "1.2.3.4:80".parse().unwrap());
        let _ = hs2.step(&[]).unwrap();
        assert_eq!(hs2.step(&[0x05, 0x02]), Err(ProxyError::Socks5NoAcceptableAuth));

        // 0xFF (no acceptable methods).
        let mut hs3 = Handshake::connect(&socks5_proxy(), "1.2.3.4:80".parse().unwrap());
        let _ = hs3.step(&[]).unwrap();
        assert_eq!(hs3.step(&[0x05, 0xFF]), Err(ProxyError::Socks5NoAcceptableAuth));
    }

    #[test]
    fn socks5_connect_refused() {
        let mut hs = Handshake::connect(&socks5_proxy(), "1.2.3.4:80".parse().unwrap());
        let _ = hs.step(&[]).unwrap();
        let _ = hs.step(&[0x05, 0x00]).unwrap();
        // REP 0x05 = connection refused.
        assert_eq!(
            hs.step(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
            Err(ProxyError::Socks5Reply(0x05)),
        );
    }

    #[test]
    fn socks5_udp_associate_returns_relay() {
        let mut hs = Handshake::udp_associate(&socks5_proxy());
        assert_eq!(hs.step(&[]).unwrap(), Step::Write(vec![0x05, 0x01, 0x00]));
        // ASSOCIATE request advertises 0.0.0.0:0 as the source.
        let Step::Write(req) = hs.step(&[0x05, 0x00]).unwrap() else { panic!() };
        assert_eq!(req, vec![0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        // Reply: relay at 10.0.0.9:5555.
        let done = hs.step(&[0x05, 0x00, 0x00, 0x01, 10, 0, 0, 9, 0x15, 0xB3]).unwrap();
        assert_eq!(done, Step::Done { leftover: Vec::new() });
        assert_eq!(hs.bound_addr().unwrap(), "10.0.0.9:5555".parse().unwrap());
    }

    #[test]
    fn socks5_reply_ipv6_bound_len() {
        // A v6 bound address (ATYP 4) needs 22 bytes total.
        let mut reply = vec![0x05, 0x00, 0x00, 0x04];
        reply.extend_from_slice(&[0u8; 16]);
        reply.extend_from_slice(&[0x00, 0x50]);
        assert_eq!(socks5_reply_len(&reply).unwrap(), Some(22));
        assert_eq!(socks5_reply_len(&reply[..10]).unwrap(), None);
    }

    #[test]
    fn udp_encapsulate_round_trip() {
        let target: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let payload = b"\x12\x34dns-query";
        let wire = socks5_udp_encapsulate(target, payload);
        assert_eq!(&wire[..4], &[0x00, 0x00, 0x00, 0x01]);
        let (src, data) = socks5_udp_decapsulate(&wire).unwrap();
        assert_eq!(src, target);
        assert_eq!(data, payload);
        // A fragmented datagram is rejected.
        let mut frag = wire.clone();
        frag[2] = 0x01;
        assert!(socks5_udp_decapsulate(&frag).is_none());
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"user:pw"), "dXNlcjpwdw==");
    }
}
