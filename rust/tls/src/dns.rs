// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! Encrypted-DNS filtering over an intercepted TLS splice (P1/P3).
//!
//! A [`DnsStream`] handles the decrypted plaintext of an intercepted DoT or DoH
//! flow: it reads the DNS queries the client sends, asks the datapath's blocklist
//! whether each name is blocked, and either
//!  - synthesizes an `NXDOMAIN` straight back to the client (blocked), or
//!  - forwards the query to the real resolver (allowed) and relays its answer.
//!
//! **DoT** ([`DnsKind::Dot`]) is 2-byte length-prefixed DNS messages, no HTTP.
//!
//! **DoH** ([`DnsKind::Doh`]) is HTTP. The app side may be HTTP/2 (Chrome,
//! Firefox — see [`crate::h2`]) or HTTP/1.1; the resolver side is always
//! re-originated as HTTP/1.1 (the mitm's upstream config offers only `http/1.1`),
//! so allowed queries become a simple `POST /dns-query` and the response is
//! relayed back. Anything we can't parse is proxied through unfiltered rather
//! than broken.
//!
//! The block decision is supplied by the caller as a closure, so this crate needs
//! no dependency on the (heavy) filter engine.

use std::collections::VecDeque;

use crate::h2::{H2Server, PREFACE};
use crate::har::{
    find_header_end, header, parse_head_fields, parse_request_line, parse_status_line,
    request_framing, response_framing, Framing, Step,
};

/// Which encrypted-DNS transport a [`DnsStream`] is framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsKind {
    /// DNS over TLS (RFC 7858).
    Dot,
    /// DNS over HTTPS (RFC 8484).
    Doh,
}

/// Output of feeding one direction of plaintext through the filter.
#[derive(Default)]
pub struct DnsCross {
    /// Plaintext to forward to the real resolver (allowed queries).
    pub to_upstream: Vec<u8>,
    /// Plaintext to send back to the client (synthesized answers / protocol).
    pub to_app: Vec<u8>,
}

/// Largest buffered-but-incomplete message we'll hold before falling back to
/// verbatim passthrough (a DoT length prefix addresses at most 64 KiB).
const MAX_PENDING: usize = 128 * 1024;

/// Per-flow encrypted-DNS filter state.
pub struct DnsStream {
    /// Names sinkholed since the last drain, for the datapath's block events.
    blocked: Vec<String>,
    inner: Inner,
}

enum Inner {
    Dot(Dot),
    Doh(Doh),
}

impl DnsStream {
    pub fn new(kind: DnsKind) -> Self {
        let inner = match kind {
            DnsKind::Dot => Inner::Dot(Dot::default()),
            DnsKind::Doh => Inner::Doh(Doh::default()),
        };
        DnsStream { blocked: Vec::new(), inner }
    }

    /// Take the domains sinkholed since the last call (for `blocked` events).
    pub fn take_blocked(&mut self) -> Vec<String> {
        std::mem::take(&mut self.blocked)
    }

    /// Feed client→resolver plaintext.
    pub fn on_app_data(
        &mut self,
        data: &[u8],
        is_blocked: &mut dyn FnMut(&str) -> bool,
    ) -> DnsCross {
        let mut out = DnsCross::default();
        match &mut self.inner {
            Inner::Dot(dot) => dot.on_app_data(data, is_blocked, &mut self.blocked, &mut out),
            Inner::Doh(doh) => doh.on_app_data(data, is_blocked, &mut self.blocked, &mut out),
        }
        out
    }

    /// Feed resolver→client plaintext.
    pub fn on_upstream_data(&mut self, data: &[u8]) -> Vec<u8> {
        match &mut self.inner {
            Inner::Dot(_) => data.to_vec(), // DoT responses relay verbatim
            Inner::Doh(doh) => doh.on_upstream_data(data),
        }
    }
}

// ---------------------------------------------------------------------------
// DoT
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Dot {
    app_buf: Vec<u8>,
    passthrough: bool,
}

impl Dot {
    fn on_app_data(
        &mut self,
        data: &[u8],
        is_blocked: &mut dyn FnMut(&str) -> bool,
        blocked: &mut Vec<String>,
        out: &mut DnsCross,
    ) {
        if self.passthrough {
            out.to_upstream.extend_from_slice(data);
            return;
        }
        self.app_buf.extend_from_slice(data);
        loop {
            if self.app_buf.len() < 2 {
                break;
            }
            let len = ((self.app_buf[0] as usize) << 8) | self.app_buf[1] as usize;
            let total = 2 + len;
            if self.app_buf.len() < total {
                if total > MAX_PENDING {
                    self.passthrough = true;
                    out.to_upstream.append(&mut self.app_buf);
                }
                break;
            }
            let framed: Vec<u8> = self.app_buf.drain(..total).collect();
            let msg = &framed[2..];
            match adwarden_dns::parse_query(msg) {
                Some(q) if is_blocked(&q.name) => {
                    let answer = adwarden_dns::synthesize_nxdomain(msg, &q);
                    push_framed(&mut out.to_app, &answer);
                    blocked.push(q.name);
                }
                _ => out.to_upstream.extend_from_slice(&framed),
            }
        }
    }
}

/// Prepend the DNS-over-TCP 2-byte big-endian length and append the message.
fn push_framed(out: &mut Vec<u8>, msg: &[u8]) {
    let len = msg.len().min(u16::MAX as usize) as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&msg[..len as usize]);
}

// ---------------------------------------------------------------------------
// DoH
// ---------------------------------------------------------------------------

#[derive(Default, PartialEq, Eq)]
enum Proto {
    #[default]
    Undecided,
    H2,
    H1,
}

#[derive(Default)]
struct Doh {
    proto: Proto,
    /// Pre-decision buffer, then (for H1) the request stream buffer.
    app_buf: Vec<u8>,
    h2: Option<H2Server>,
    /// Upstream HTTP/1.1 response parser (used for the H2 app side).
    up: H1Responses,
    /// FIFO of app streams awaiting an upstream reply (H2 side; `None` marks a
    /// bare relay for the H1 side, which never enqueues).
    pending: VecDeque<u32>,
    /// The resolver host, learned from the first request's authority/Host.
    authority: String,
    /// Set on an unrecoverable H1 parse: stop filtering, relay verbatim.
    h1_passthrough: bool,
}

impl Doh {
    fn on_app_data(
        &mut self,
        data: &[u8],
        is_blocked: &mut dyn FnMut(&str) -> bool,
        blocked: &mut Vec<String>,
        out: &mut DnsCross,
    ) {
        if self.proto == Proto::Undecided {
            self.app_buf.extend_from_slice(data);
            match decide_proto(&self.app_buf) {
                Some(Proto::H2) => {
                    self.proto = Proto::H2;
                    self.h2 = Some(H2Server::new());
                    let buffered = std::mem::take(&mut self.app_buf);
                    self.h2_feed(&buffered, is_blocked, blocked, out);
                }
                Some(Proto::H1) => {
                    self.proto = Proto::H1;
                    // app_buf already holds the buffered request bytes.
                    self.h1_feed(&[], is_blocked, blocked, out);
                }
                _ => {} // Undecided: keep buffering.
            }
            return;
        }
        match self.proto {
            Proto::H2 => self.h2_feed(data, is_blocked, blocked, out),
            Proto::H1 => self.h1_feed(data, is_blocked, blocked, out),
            Proto::Undecided => unreachable!(),
        }
    }

    fn on_upstream_data(&mut self, data: &[u8]) -> Vec<u8> {
        match self.proto {
            // H1 app side relays resolver bytes verbatim (both ends are h1).
            Proto::H1 | Proto::Undecided => data.to_vec(),
            Proto::H2 => {
                let responses = self.up.feed(data);
                let Some(h2) = self.h2.as_mut() else { return Vec::new() };
                for resp in responses {
                    if let Some(sid) = self.pending.pop_front() {
                        let ct = if resp.content_type.is_empty() {
                            "application/dns-message"
                        } else {
                            &resp.content_type
                        };
                        h2.respond(sid, resp.status, ct, &resp.body);
                    }
                }
                h2.take_out()
            }
        }
    }

    // --- HTTP/2 app side ---------------------------------------------------

    fn h2_feed(
        &mut self,
        data: &[u8],
        is_blocked: &mut dyn FnMut(&str) -> bool,
        blocked: &mut Vec<String>,
        out: &mut DnsCross,
    ) {
        let Some(h2) = self.h2.as_mut() else { return };
        h2.on_input(data);
        if h2.failed() {
            // Unrecoverable framing/HPACK error: flush any protocol bytes already
            // queued and stop. The flow then idles out rather than risk corruption.
            out.to_app.extend_from_slice(&h2.take_out());
            return;
        }
        for req in h2.take_requests() {
            if self.authority.is_empty() && !req.authority.is_empty() {
                self.authority = req.authority.clone();
            }
            match extract_query(&req.method, &req.path, &req.content_type, &req.body) {
                Extracted::Wire(wire) => match block_wire(&wire, is_blocked) {
                    Some((name, answer)) => {
                        blocked.push(name);
                        h2.respond(req.stream_id, 200, "application/dns-message", &answer);
                    }
                    None => {
                        out.to_upstream.extend_from_slice(&post_wire(&self.authority, &req.path, &wire));
                        self.pending.push_back(req.stream_id);
                    }
                },
                Extracted::JsonName(name) => {
                    if is_blocked(&name) {
                        blocked.push(name.clone());
                        let body = json_nxdomain(&name);
                        h2.respond(req.stream_id, 200, "application/dns-json", body.as_bytes());
                    } else {
                        out.to_upstream.extend_from_slice(&get_path(&self.authority, &req.path, "application/dns-json"));
                        self.pending.push_back(req.stream_id);
                    }
                }
                // Can't parse the query: proxy it through unfiltered.
                Extracted::Unknown => {
                    out.to_upstream.extend_from_slice(&reconstruct(&self.authority, &req));
                    self.pending.push_back(req.stream_id);
                }
            }
        }
        out.to_app.extend_from_slice(&h2.take_out());
    }

    // --- HTTP/1.1 app side -------------------------------------------------

    fn h1_feed(
        &mut self,
        data: &[u8],
        is_blocked: &mut dyn FnMut(&str) -> bool,
        blocked: &mut Vec<String>,
        out: &mut DnsCross,
    ) {
        self.app_buf.extend_from_slice(data);
        if self.h1_passthrough {
            out.to_upstream.append(&mut self.app_buf);
            return;
        }
        loop {
            let Some(hend) = find_header_end(&self.app_buf) else { break };
            let Some((start, headers)) = parse_head_fields(&self.app_buf[..hend]) else {
                self.enter_h1_passthrough(out);
                return;
            };
            let Some((method, target, _)) = parse_request_line(&start) else {
                self.enter_h1_passthrough(out);
                return;
            };
            // Only Content-Length bodies are filtered inline; chunked/other →
            // passthrough (rare for DoH POST).
            let body_len = match request_framing(&headers) {
                None => 0,
                Some(Framing::Length(n)) => n,
                Some(_) => {
                    self.enter_h1_passthrough(out);
                    return;
                }
            };
            let total = hend + body_len;
            if self.app_buf.len() < total {
                break; // await the full body
            }
            let req: Vec<u8> = self.app_buf.drain(..total).collect();
            let body = req[hend..].to_vec();
            let ct = header(&headers, "content-type").unwrap_or("").to_string();
            if self.authority.is_empty() {
                self.authority = header(&headers, "host").unwrap_or("").to_string();
            }
            match extract_query(&method, &target, &ct, &body) {
                Extracted::Wire(wire) => match block_wire(&wire, is_blocked) {
                    Some((name, answer)) => {
                        blocked.push(name);
                        out.to_app.extend_from_slice(&h1_response("application/dns-message", &answer));
                    }
                    None => out.to_upstream.extend_from_slice(&req), // forward as-is
                },
                Extracted::JsonName(name) => {
                    if is_blocked(&name) {
                        blocked.push(name.clone());
                        out.to_app
                            .extend_from_slice(&h1_response("application/dns-json", json_nxdomain(&name).as_bytes()));
                    } else {
                        out.to_upstream.extend_from_slice(&req);
                    }
                }
                Extracted::Unknown => out.to_upstream.extend_from_slice(&req),
            }
        }
    }

    fn enter_h1_passthrough(&mut self, out: &mut DnsCross) {
        self.h1_passthrough = true;
        out.to_upstream.append(&mut self.app_buf);
    }
}

/// Decide the app-side protocol from its first bytes: HTTP/2 opens with the
/// connection preface; anything else is treated as HTTP/1.1.
fn decide_proto(buf: &[u8]) -> Option<Proto> {
    if buf.len() >= PREFACE.len() {
        return if &buf[..PREFACE.len()] == PREFACE { Some(Proto::H2) } else { Some(Proto::H1) };
    }
    // Still short: only keep waiting if it could still become the preface.
    if PREFACE.starts_with(buf) {
        None
    } else {
        Some(Proto::H1)
    }
}

/// What we extracted from a DoH request.
enum Extracted {
    /// Wire-format DNS query (RFC 8484 `application/dns-message`).
    Wire(Vec<u8>),
    /// JSON DoH: the queried name from a `?name=` parameter.
    JsonName(String),
    /// Couldn't parse a query — proxy the request through unfiltered.
    Unknown,
}

fn extract_query(method: &str, path: &str, content_type: &str, body: &[u8]) -> Extracted {
    if method.eq_ignore_ascii_case("POST") {
        if content_type.starts_with("application/dns-message") || !body.is_empty() {
            return Extracted::Wire(body.to_vec());
        }
        return Extracted::Unknown;
    }
    // GET: the query rides in the URL.
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
    for kv in query.split('&') {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        if k == "dns" {
            if let Some(wire) = b64url_decode(v) {
                return Extracted::Wire(wire);
            }
        } else if k == "name" {
            return Extracted::JsonName(percent_decode(v).to_ascii_lowercase());
        }
    }
    Extracted::Unknown
}

/// If the wire query's name is blocked, return `(name, NXDOMAIN answer)`.
fn block_wire(wire: &[u8], is_blocked: &mut dyn FnMut(&str) -> bool) -> Option<(String, Vec<u8>)> {
    let q = adwarden_dns::parse_query(wire)?;
    if is_blocked(&q.name) {
        let answer = adwarden_dns::synthesize_nxdomain(wire, &q);
        Some((q.name, answer))
    } else {
        None
    }
}

/// A minimal JSON DoH `NXDOMAIN` (`Status: 3`) response body.
fn json_nxdomain(name: &str) -> String {
    // Escape only what a hostname could contain that's JSON-significant.
    let name = name.replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "{{\"Status\":3,\"TC\":false,\"RD\":true,\"RA\":true,\"AD\":false,\"CD\":false,\
         \"Question\":[{{\"name\":\"{name}\",\"type\":1}}],\"Answer\":[]}}"
    )
}

/// Build an upstream HTTP/1.1 `POST /dns-query` carrying a wire query.
fn post_wire(authority: &str, path: &str, wire: &[u8]) -> Vec<u8> {
    let path = path.split_once('?').map(|(p, _)| p).unwrap_or(path);
    let path = if path.is_empty() { "/dns-query" } else { path };
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: application/dns-message\r\n\
         Content-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        wire.len()
    )
    .into_bytes();
    req.extend_from_slice(wire);
    req
}

/// Build an upstream HTTP/1.1 `GET` preserving the request's path (JSON DoH).
fn get_path(authority: &str, path: &str, accept: &str) -> Vec<u8> {
    let path = if path.is_empty() { "/dns-query" } else { path };
    format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: {accept}\r\nConnection: keep-alive\r\n\r\n"
    )
    .into_bytes()
}

/// Reconstruct an HTTP/1.1 request for an h2 request we couldn't classify.
fn reconstruct(authority: &str, req: &crate::h2::H2Request) -> Vec<u8> {
    if req.method.eq_ignore_ascii_case("POST") {
        let mut out = format!(
            "POST {} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: {}\r\nContent-Length: {}\r\n\
             Connection: keep-alive\r\n\r\n",
            req.path,
            if req.content_type.is_empty() { "application/dns-message" } else { &req.content_type },
            req.body.len(),
        )
        .into_bytes();
        out.extend_from_slice(&req.body);
        out
    } else {
        get_path(authority, &req.path, "application/dns-message")
    }
}

/// Build an HTTP/1.1 200 response toward an h1 app.
fn h1_response(content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Connection: keep-alive\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// One HTTP/1.1 response parsed from the upstream stream.
struct UpResponse {
    status: u16,
    content_type: String,
    body: Vec<u8>,
}

/// Incremental HTTP/1.1 response parser for the resolver side (H2 app path).
#[derive(Default)]
struct H1Responses {
    buf: Vec<u8>,
    body: Option<BodyAcc>,
}

struct BodyAcc {
    status: u16,
    content_type: String,
    framing: Framing,
    captured: Vec<u8>,
    wire: usize,
    trunc: bool,
}

impl H1Responses {
    fn feed(&mut self, data: &[u8]) -> Vec<UpResponse> {
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        loop {
            if self.body.is_none() {
                let Some(hend) = find_header_end(&self.buf) else { break };
                let head: Vec<u8> = self.buf.drain(..hend).collect();
                let Some((start, headers)) = parse_head_fields(&head) else { break };
                let Some((_, status, _)) = parse_status_line(&start) else { break };
                let ct = header(&headers, "content-type").unwrap_or("").to_string();
                match response_framing(status, false, &headers) {
                    None => {
                        out.push(UpResponse { status, content_type: ct, body: Vec::new() });
                        continue;
                    }
                    Some(framing) => {
                        self.body = Some(BodyAcc {
                            status,
                            content_type: ct,
                            framing,
                            captured: Vec::new(),
                            wire: 0,
                            trunc: false,
                        });
                    }
                }
            }
            let acc = self.body.as_mut().unwrap();
            match consume_body(&mut acc.framing, &mut self.buf, &mut acc.captured, &mut acc.wire, &mut acc.trunc) {
                Step::Done => {
                    let b = self.body.take().unwrap();
                    out.push(UpResponse { status: b.status, content_type: b.content_type, body: b.captured });
                }
                Step::NeedMore => break,
                Step::Error => {
                    self.body = None;
                    break;
                }
            }
        }
        out
    }
}

/// Consume as much of `buf` as belongs to the current response body.
fn consume_body(
    framing: &mut Framing,
    buf: &mut Vec<u8>,
    captured: &mut Vec<u8>,
    wire: &mut usize,
    trunc: &mut bool,
) -> Step {
    match framing {
        Framing::Length(remaining) => {
            if *remaining == 0 {
                return Step::Done;
            }
            let n = (*remaining).min(buf.len());
            if n > 0 {
                let chunk: Vec<u8> = buf.drain(..n).collect();
                captured.extend_from_slice(&chunk);
                *wire += n;
                *remaining -= n;
            }
            if *remaining == 0 {
                Step::Done
            } else {
                Step::NeedMore
            }
        }
        Framing::Chunked(reader) => reader.consume(buf, captured, wire, trunc),
        Framing::UntilClose => {
            if !buf.is_empty() {
                let chunk: Vec<u8> = std::mem::take(buf);
                captured.extend_from_slice(&chunk);
            }
            Step::NeedMore
        }
    }
}

/// Decode unpadded base64url (RFC 4648 §5), as DoH `?dns=` uses.
fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        } as u32)
    }
    let s = s.trim_end_matches('=');
    if s.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in s.as_bytes() {
        acc = (acc << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// Minimal percent-decoding for a `?name=` value.
fn percent_decode(s: &str) -> String {
    fn hex(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a length-prefixed (DoT) type-A query for `name`.
    fn dot_query(name: &str) -> Vec<u8> {
        let msg = wire_query(name);
        let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&msg);
        framed
    }

    /// Bare wire-format type-A query for `name`.
    fn wire_query(name: &str) -> Vec<u8> {
        let mut msg = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg
    }

    #[test]
    fn dot_blocks_and_forwards_by_name() {
        let mut s = DnsStream::new(DnsKind::Dot);
        let mut is_blocked = |name: &str| name == "ads.example.com";

        let out = s.on_app_data(&dot_query("ads.example.com"), &mut is_blocked);
        assert!(out.to_upstream.is_empty());
        assert_eq!(out.to_app[2 + 3] & 0x0F, 3, "NXDOMAIN");
        assert_eq!(s.take_blocked(), vec!["ads.example.com".to_string()]);

        let allowed = dot_query("good.example.com");
        let out = s.on_app_data(&allowed, &mut is_blocked);
        assert_eq!(out.to_upstream, allowed);
        assert!(out.to_app.is_empty());
    }

    #[test]
    fn dot_reassembles_across_chunks() {
        let mut s = DnsStream::new(DnsKind::Dot);
        let mut is_blocked = |name: &str| name == "ads.example.com";
        let framed = dot_query("ads.example.com");
        assert!(s.on_app_data(&framed[..1], &mut is_blocked).to_app.is_empty());
        assert!(!s.on_app_data(&framed[1..], &mut is_blocked).to_app.is_empty());
        assert_eq!(s.take_blocked().len(), 1);
    }

    #[test]
    fn doh_h1_post_blocks_and_forwards() {
        let mut s = DnsStream::new(DnsKind::Doh);
        let mut is_blocked = |name: &str| name == "ads.example.com";

        // Blocked POST: 200 dns-message answered locally, nothing upstream.
        let wire = wire_query("ads.example.com");
        let req = [
            format!(
                "POST /dns-query HTTP/1.1\r\nHost: cloudflare-dns.com\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                wire.len()
            )
            .into_bytes(),
            wire,
        ]
        .concat();
        let out = s.on_app_data(&req, &mut is_blocked);
        assert!(out.to_upstream.is_empty(), "blocked query not forwarded");
        assert!(
            String::from_utf8_lossy(&out.to_app).contains("200 OK"),
            "local 200 response"
        );
        assert_eq!(s.take_blocked(), vec!["ads.example.com".to_string()]);

        // Allowed POST: forwarded to the resolver verbatim.
        let wire2 = wire_query("good.example.com");
        let req2 = [
            format!(
                "POST /dns-query HTTP/1.1\r\nHost: cloudflare-dns.com\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                wire2.len()
            )
            .into_bytes(),
            wire2,
        ]
        .concat();
        let out = s.on_app_data(&req2, &mut is_blocked);
        assert!(!out.to_upstream.is_empty(), "allowed query forwarded");
        assert!(out.to_app.is_empty());
    }

    #[test]
    fn doh_h1_get_dns_param() {
        // base64url of a wire query with no padding.
        let wire = wire_query("ads.example.com");
        let b64 = b64url_encode(&wire);
        let mut s = DnsStream::new(DnsKind::Doh);
        let mut is_blocked = |name: &str| name == "ads.example.com";
        let req = format!(
            "GET /dns-query?dns={b64} HTTP/1.1\r\nHost: dns.google\r\nAccept: application/dns-message\r\n\r\n"
        )
        .into_bytes();
        let out = s.on_app_data(&req, &mut is_blocked);
        assert!(out.to_upstream.is_empty());
        assert!(String::from_utf8_lossy(&out.to_app).contains("200 OK"));
        assert_eq!(s.take_blocked(), vec!["ads.example.com".to_string()]);
    }

    #[test]
    fn doh_h1_upstream_relays_verbatim() {
        let mut s = DnsStream::new(DnsKind::Doh);
        // Force H1 by feeding a request first.
        let mut is_blocked = |_: &str| false;
        let _ = s.on_app_data(b"GET /dns-query?name=good.example.com HTTP/1.1\r\nHost: dns.google\r\n\r\n", &mut is_blocked);
        assert_eq!(s.on_upstream_data(b"HTTP/1.1 200 OK\r\n\r\n"), b"HTTP/1.1 200 OK\r\n\r\n");
    }

    #[test]
    fn base64url_roundtrips() {
        for name in ["a.com", "ads.example.com", "x"] {
            let wire = wire_query(name);
            let b = b64url_encode(&wire);
            assert_eq!(b64url_decode(&b).unwrap(), wire);
        }
    }

    fn h2_frame(ty: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let len = payload.len();
        out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8, ty, flags]);
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn doh_h2_blocks_and_forwards() {
        use fluke_hpack::Encoder;
        let mut s = DnsStream::new(DnsKind::Doh);
        let mut is_blocked = |name: &str| name == "ads.example.com";
        let mut enc = Encoder::new();

        // Connection preface + client SETTINGS opens the h2 connection.
        let mut input = Vec::new();
        input.extend_from_slice(PREFACE);
        input.extend_from_slice(&h2_frame(0x4, 0, 0, &[])); // SETTINGS
        // Blocked POST on stream 1.
        let block = enc.encode(
            [
                (b":method".as_ref(), b"POST".as_ref()),
                (b":path", b"/dns-query"),
                (b":authority", b"cloudflare-dns.com"),
                (b"content-type", b"application/dns-message"),
            ]
            .into_iter(),
        );
        input.extend_from_slice(&h2_frame(0x1, 0x4, 1, &block)); // HEADERS END_HEADERS
        input.extend_from_slice(&h2_frame(0x0, 0x1, 1, &wire_query("ads.example.com"))); // DATA END_STREAM

        let out = s.on_app_data(&input, &mut is_blocked);
        assert!(out.to_upstream.is_empty(), "blocked query not forwarded upstream");
        // Response HEADERS(+DATA) went back to the app as h2 frames on stream 1.
        assert!(out.to_app.iter().any(|&b| b == 0x1), "an h2 HEADERS frame is present");
        assert_eq!(s.take_blocked(), vec!["ads.example.com".to_string()]);

        // Allowed POST on stream 3 → re-originated as HTTP/1.1 upstream.
        let block2 = enc.encode(
            [
                (b":method".as_ref(), b"POST".as_ref()),
                (b":path", b"/dns-query"),
                (b":authority", b"cloudflare-dns.com"),
                (b"content-type", b"application/dns-message"),
            ]
            .into_iter(),
        );
        let mut input2 = h2_frame(0x1, 0x4, 3, &block2);
        input2.extend_from_slice(&h2_frame(0x0, 0x1, 3, &wire_query("good.example.com")));
        let out = s.on_app_data(&input2, &mut is_blocked);
        assert!(
            String::from_utf8_lossy(&out.to_upstream).contains("POST /dns-query HTTP/1.1"),
            "allowed query re-originated as h1: {:?}",
            String::from_utf8_lossy(&out.to_upstream)
        );

        // The resolver's h1 answer is wrapped back into an h2 response.
        let up = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 4\r\n\r\nWXYZ";
        let to_app = s.on_upstream_data(up);
        assert!(!to_app.is_empty(), "resolver answer wrapped into an h2 response");
    }

    fn b64url_encode(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for &b in data {
            acc = (acc << 8) | b as u32;
            bits += 8;
            while bits >= 6 {
                bits -= 6;
                out.push(A[((acc >> bits) & 0x3f) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(A[((acc << (6 - bits)) & 0x3f) as usize] as char);
        }
        out
    }
}
