// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! Active HTTP/1.1 rewriter for cosmetic filtering (P4-2).
//!
//! Where [`crate::har::HttpTap`] passively parses the decrypted plaintext for HAR
//! export, the `HttpRewriter` *edits* it: on the request stream it forces
//! `Accept-Encoding: identity` (so responses arrive uncompressed and injectable);
//! on the response stream it injects hostname cosmetic CSS/JS into `text/html`
//! documents and strips `Content-Security-Policy` so the injection isn't blocked.
//!
//! **Safety invariant.** The rewriter is a byte-exact identity function in every
//! case except one: a fully-parsed, injectable `text/html` response. Every
//! uncertainty — no payload, non-HTTP/1.1, a compressed or UTF-16 body, an anchor
//! we can't find, a 1xx/204/304/206/HEAD/SSE/websocket message — degrades to
//! verbatim passthrough. It never drops or reorders bytes.
//!
//! **Payload timing.** `set_cosmetic` is always called before the first byte
//! crosses: the datapath learns the SNI from the ClientHello and provisions the
//! payload on that pump, while the upstream session — and therefore any response —
//! doesn't exist until a later pump, and the app's HTTP request can't be sent
//! until its handshake completes a pump later still. So `active` is settled before
//! `feed_*` ever sees data; the default (`active == false`) is pure passthrough.

use std::collections::VecDeque;

use crate::har::{
    content_length, find_header_end, parse_head_fields, parse_request_line, parse_status_line,
    request_framing, response_framing, ChunkReader, Framing, Step,
};

/// Max body prefix buffered while hunting for the injection anchor before giving
/// up and passing the response through un-injected.
const MAX_ANCHOR_SCAN: usize = 64 * 1024;
/// Max header block buffered before deciding a stream isn't HTTP/1.1.
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Idempotency / injection marker.
const MARKER: &[u8] = b"adw-cosmetic";

pub struct HttpRewriter {
    /// Cosmetics live only when a payload is present (see module docs). Until then,
    /// or when the feature is off, both directions pass through byte-for-byte.
    active: bool,
    /// Precomputed injection blob: `<!--adw-cosmetic-->[<script>js</script>][<style id=…>css</style>]`.
    blob: Vec<u8>,
    /// Hard-disabled after a protocol we can't model (101 upgrade, parse error,
    /// chunked request body): everything afterwards is copied verbatim, forever.
    disabled: bool,
    req: ReqState,
    req_buf: Vec<u8>,
    resp: RespState,
    resp_buf: Vec<u8>,
    /// HEAD-ness of requests awaiting a response, in order (mirrors `HttpTap`).
    pending_head: VecDeque<bool>,
}

enum ReqState {
    /// Between messages: looking for a request head.
    Head,
    /// Forwarding a Content-Length request body of N remaining bytes, verbatim.
    Body(usize),
}

enum RespState {
    /// Accumulating the response head (held, not emitted).
    Head,
    /// Head parsed & injectable: buffering the body prefix to find the anchor.
    Buffer(BodyScan),
    /// Anchor resolved: streaming the remaining body.
    Stream(BodyKind),
    /// This message isn't injectable: forwarding its body verbatim per framing.
    Pass(BodyKind),
}

/// State while scanning an injectable response body for the anchor.
struct BodyScan {
    /// Original head bytes, held until we decide (edited on inject, verbatim on abandon).
    orig_head: Vec<u8>,
    /// Buffered body prefix: raw bytes for Length/Close, decoded bytes for Chunked.
    scan: Vec<u8>,
    body: BodyKind,
    /// `Content-Length` value for mode A, so it can be rewritten to `+ blob.len()`.
    cl_original: Option<usize>,
    /// The upstream body has been seen in full (terminator/CL reached).
    body_done: bool,
}

/// How the remaining body is framed. `Length` counts raw bytes still to come;
/// `Chunked` continues the decoder; `Close` runs until the connection closes.
enum BodyKind {
    Length(usize),
    Chunked(ChunkReader),
    Close,
}

impl HttpRewriter {
    pub fn new() -> Self {
        HttpRewriter {
            active: false,
            blob: Vec::new(),
            disabled: false,
            req: ReqState::Head,
            req_buf: Vec::new(),
            resp: RespState::Head,
            resp_buf: Vec::new(),
            pending_head: VecDeque::new(),
        }
    }

    /// Provision the cosmetic payload for this flow's host (P4-2). Empty `css` and
    /// `js` mean "cosmetics off" → the rewriter is a pure identity passthrough
    /// (both directions byte-for-byte, `Accept-Encoding` untouched). Called once,
    /// before any plaintext crosses.
    pub fn set_cosmetic(&mut self, css: String, js: String) {
        let has_css = !css.is_empty();
        let has_js = !js.is_empty();
        self.active = has_css || has_js;
        if self.active {
            let mut blob = Vec::with_capacity(css.len() + js.len() + 64);
            blob.extend_from_slice(b"<!--adw-cosmetic-->");
            if has_js {
                blob.extend_from_slice(b"<script>");
                blob.extend_from_slice(js.as_bytes());
                blob.extend_from_slice(b"</script>");
            }
            if has_css {
                blob.extend_from_slice(b"<style id=\"adw-cosmetic\">");
                blob.extend_from_slice(css.as_bytes());
                blob.extend_from_slice(b"</style>");
            }
            self.blob = blob;
        }
    }

    /// Feed app→upstream (request) plaintext; returns the bytes to forward upstream.
    pub fn feed_request(&mut self, data: &[u8]) -> Vec<u8> {
        if !self.active || self.disabled {
            let mut out = std::mem::take(&mut self.req_buf);
            out.extend_from_slice(data);
            return out;
        }
        self.req_buf.extend_from_slice(data);
        let mut out = Vec::new();
        self.drive_request(&mut out);
        out
    }

    /// Feed upstream→app (response) plaintext; returns the bytes to forward to the app.
    pub fn feed_response(&mut self, data: &[u8]) -> Vec<u8> {
        if !self.active || self.disabled {
            let mut out = std::mem::take(&mut self.resp_buf);
            out.extend_from_slice(data);
            return out;
        }
        self.resp_buf.extend_from_slice(data);
        let mut out = Vec::new();
        self.drive_response(&mut out);
        out
    }

    // --- request side ----------------------------------------------------

    fn drive_request(&mut self, out: &mut Vec<u8>) {
        loop {
            match std::mem::replace(&mut self.req, ReqState::Head) {
                ReqState::Head => {
                    let Some(end) = find_header_end(&self.req_buf) else {
                        if self.req_buf.len() > MAX_HEADER_BYTES {
                            return self.disable_flush_req(out);
                        }
                        return; // need more of the head
                    };
                    let Some((start_line, headers)) = parse_head_fields(&self.req_buf[..end - 4])
                    else {
                        return self.disable_flush_req(out);
                    };
                    let Some((method, _, _)) = parse_request_line(&start_line) else {
                        return self.disable_flush_req(out);
                    };
                    self.pending_head.push_back(method.eq_ignore_ascii_case("HEAD"));
                    let edited = edit_request_head(&self.req_buf[..end]);
                    out.extend_from_slice(&edited);
                    self.req_buf.drain(..end);
                    match request_framing(&headers) {
                        None => self.req = ReqState::Head,
                        Some(Framing::Length(n)) => self.req = ReqState::Body(n),
                        // Chunked/until-close request bodies are rare (streaming
                        // uploads, never a browser page load). Rather than track
                        // their framing, hand the rest of the connection through raw.
                        Some(_) => return self.disable_flush_req(out),
                    }
                }
                ReqState::Body(mut remaining) => {
                    let take = remaining.min(self.req_buf.len());
                    out.extend(self.req_buf.drain(..take));
                    remaining -= take;
                    if remaining == 0 {
                        self.req = ReqState::Head;
                    } else {
                        self.req = ReqState::Body(remaining);
                        return;
                    }
                }
            }
        }
    }

    fn disable_flush_req(&mut self, out: &mut Vec<u8>) {
        self.disabled = true;
        out.append(&mut self.req_buf);
    }

    // --- response side ---------------------------------------------------

    fn drive_response(&mut self, out: &mut Vec<u8>) {
        loop {
            let state = std::mem::replace(&mut self.resp, RespState::Head);
            match state {
                RespState::Head => {
                    if !self.step_response_head(out) {
                        return;
                    }
                }
                RespState::Buffer(scan) => {
                    if !self.step_response_buffer(scan, out) {
                        return;
                    }
                }
                RespState::Stream(kind) => {
                    if !self.step_response_stream(kind, out) {
                        return;
                    }
                }
                RespState::Pass(kind) => {
                    if !self.step_response_pass(kind, out) {
                        return;
                    }
                }
            }
        }
    }

    /// Parse the next response head and route it. Returns `true` to keep draining.
    fn step_response_head(&mut self, out: &mut Vec<u8>) -> bool {
        let Some(end) = find_header_end(&self.resp_buf) else {
            if self.resp_buf.len() > MAX_HEADER_BYTES {
                self.disable_flush_resp(out);
            }
            return false;
        };
        let raw_head = self.resp_buf[..end].to_vec();
        let Some((start_line, headers)) = parse_head_fields(&self.resp_buf[..end - 4]) else {
            self.disable_flush_resp(out);
            return false;
        };
        let Some((_, status, _)) = parse_status_line(&start_line) else {
            self.disable_flush_resp(out);
            return false;
        };
        self.resp_buf.drain(..end);

        // 1xx informational (not 101) carry no body and don't consume the request.
        if (100..=199).contains(&status) && status != 101 {
            out.extend_from_slice(&raw_head);
            self.resp = RespState::Head;
            return true;
        }
        let method_is_head = self.pending_head.pop_front().unwrap_or(false);
        // A 101 switch turns the connection into a non-HTTP protocol (websocket).
        if status == 101 {
            out.extend_from_slice(&raw_head);
            self.disable_flush_resp(out);
            return false;
        }

        match response_framing(status, method_is_head, &headers) {
            None => {
                // No body (HEAD, 204, 304, …). Emit the head; next message follows.
                out.extend_from_slice(&raw_head);
                self.resp = RespState::Head;
                true
            }
            Some(framing) => {
                let cl_original = content_length(&headers);
                let body = framing_to_kind(framing);
                if injectable(status, &headers) {
                    // Hold the head; buffer the body prefix to find the anchor.
                    self.resp = RespState::Buffer(BodyScan {
                        orig_head: raw_head,
                        scan: Vec::new(),
                        body,
                        cl_original,
                        body_done: false,
                    });
                } else {
                    out.extend_from_slice(&raw_head);
                    self.resp = RespState::Pass(body);
                }
                true
            }
        }
    }

    /// Buffer an injectable body prefix and, once the anchor (or a give-up
    /// condition) is reached, emit head + prefix (+ blob) and switch to streaming.
    fn step_response_buffer(&mut self, mut bs: BodyScan, out: &mut Vec<u8>) -> bool {
        // Pull whatever body is available into the scan buffer (decoding chunks).
        match &mut bs.body {
            BodyKind::Length(remaining) => {
                let take = (*remaining).min(self.resp_buf.len());
                bs.scan.extend(self.resp_buf.drain(..take));
                *remaining -= take;
                if *remaining == 0 {
                    bs.body_done = true;
                }
            }
            BodyKind::Chunked(reader) => {
                let mut decoded = Vec::new();
                match chunked_decode(reader, &mut self.resp_buf, &mut decoded) {
                    Step::NeedMore => {}
                    Step::Done => bs.body_done = true,
                    Step::Error => {
                        // Malformed chunking: close the (partial) body cleanly.
                        bs.scan.extend_from_slice(&decoded);
                        out.extend_from_slice(&bs.orig_head);
                        rechunk(&bs.scan, out);
                        out.extend_from_slice(b"0\r\n\r\n");
                        self.disabled = true;
                        return false;
                    }
                }
                bs.scan.extend_from_slice(&decoded);
            }
            BodyKind::Close => {
                bs.scan.append(&mut self.resp_buf);
            }
        }

        // A UTF-16 document can't take ASCII injection safely; an already-marked
        // document must not be injected twice. Either way: abandon (verbatim).
        let bom16 = bs.scan.starts_with(&[0xFF, 0xFE]) || bs.scan.starts_with(&[0xFE, 0xFF]);
        let already = contains(&bs.scan, MARKER);
        let anchor = if bom16 || already {
            None
        } else if let Some(a) = anchor_streaming(&bs.scan) {
            Some(a)
        } else if bs.body_done || bs.scan.len() >= MAX_ANCHOR_SCAN {
            anchor_final(&bs.scan)
        } else {
            // Not yet resolvable and no give-up trigger: keep buffering.
            self.resp = RespState::Buffer(bs);
            return false;
        };

        // Emit the head (edited on inject, verbatim on abandon) + prefix (+ blob).
        match anchor {
            Some(a) => {
                let new_cl = bs.cl_original.map(|cl| cl + self.blob.len());
                let head = edit_response_head(&bs.orig_head, new_cl);
                out.extend_from_slice(&head);
                let (pre, post) = bs.scan.split_at(a);
                match &bs.body {
                    BodyKind::Chunked(_) => {
                        let mut chunk = Vec::with_capacity(pre.len() + self.blob.len() + post.len());
                        chunk.extend_from_slice(pre);
                        chunk.extend_from_slice(&self.blob);
                        chunk.extend_from_slice(post);
                        rechunk(&chunk, out);
                    }
                    _ => {
                        out.extend_from_slice(pre);
                        out.extend_from_slice(&self.blob);
                        out.extend_from_slice(post);
                    }
                }
            }
            None => {
                out.extend_from_slice(&bs.orig_head);
                match &bs.body {
                    BodyKind::Chunked(_) => rechunk(&bs.scan, out),
                    _ => out.extend_from_slice(&bs.scan),
                }
            }
        }

        // Continue with the remaining body, or finish this message.
        match bs.body {
            BodyKind::Length(remaining) => {
                if remaining == 0 {
                    self.resp = RespState::Head;
                } else {
                    self.resp = RespState::Stream(BodyKind::Length(remaining));
                }
            }
            BodyKind::Chunked(reader) => {
                if bs.body_done {
                    out.extend_from_slice(b"0\r\n\r\n");
                    self.resp = RespState::Head;
                } else {
                    self.resp = RespState::Stream(BodyKind::Chunked(reader));
                }
            }
            BodyKind::Close => self.resp = RespState::Stream(BodyKind::Close),
        }
        true
    }

    /// Stream the tail of an injected/abandoned body (re-chunking for chunked).
    fn step_response_stream(&mut self, kind: BodyKind, out: &mut Vec<u8>) -> bool {
        match kind {
            BodyKind::Length(mut remaining) => {
                let take = remaining.min(self.resp_buf.len());
                out.extend(self.resp_buf.drain(..take));
                remaining -= take;
                if remaining == 0 {
                    self.resp = RespState::Head;
                    true
                } else {
                    self.resp = RespState::Stream(BodyKind::Length(remaining));
                    false
                }
            }
            BodyKind::Chunked(mut reader) => {
                let mut decoded = Vec::new();
                let step = chunked_decode(&mut reader, &mut self.resp_buf, &mut decoded);
                rechunk(&decoded, out);
                match step {
                    Step::NeedMore => {
                        self.resp = RespState::Stream(BodyKind::Chunked(reader));
                        false
                    }
                    Step::Done => {
                        out.extend_from_slice(b"0\r\n\r\n");
                        self.resp = RespState::Head;
                        true
                    }
                    Step::Error => {
                        out.extend_from_slice(b"0\r\n\r\n");
                        self.disabled = true;
                        false
                    }
                }
            }
            BodyKind::Close => {
                out.append(&mut self.resp_buf);
                self.resp = RespState::Stream(BodyKind::Close);
                false
            }
        }
    }

    /// Forward a non-injected message body verbatim, detecting its end.
    fn step_response_pass(&mut self, kind: BodyKind, out: &mut Vec<u8>) -> bool {
        match kind {
            BodyKind::Length(mut remaining) => {
                let take = remaining.min(self.resp_buf.len());
                out.extend(self.resp_buf.drain(..take));
                remaining -= take;
                if remaining == 0 {
                    self.resp = RespState::Head;
                    true
                } else {
                    self.resp = RespState::Pass(BodyKind::Length(remaining));
                    false
                }
            }
            BodyKind::Chunked(mut reader) => {
                let step = chunked_verbatim(&mut reader, &mut self.resp_buf, out);
                match step {
                    Step::NeedMore => {
                        self.resp = RespState::Pass(BodyKind::Chunked(reader));
                        false
                    }
                    Step::Done => {
                        self.resp = RespState::Head;
                        true
                    }
                    Step::Error => {
                        self.disable_flush_resp(out);
                        false
                    }
                }
            }
            BodyKind::Close => {
                out.append(&mut self.resp_buf);
                self.resp = RespState::Pass(BodyKind::Close);
                false
            }
        }
    }

    fn disable_flush_resp(&mut self, out: &mut Vec<u8>) {
        self.disabled = true;
        out.append(&mut self.resp_buf);
    }
}

impl Default for HttpRewriter {
    fn default() -> Self {
        Self::new()
    }
}

fn framing_to_kind(framing: Framing) -> BodyKind {
    match framing {
        Framing::Length(n) => BodyKind::Length(n),
        Framing::Chunked(r) => BodyKind::Chunked(r),
        Framing::UntilClose => BodyKind::Close,
    }
}

/// Whether an HTML response should be injected into. Requires a `text/html`
/// media type, an identity (or absent) content-encoding, a non-UTF-16 charset,
/// and a non-partial (`206`) status.
fn injectable(status: u16, headers: &[(String, String)]) -> bool {
    if status == 206 {
        return false;
    }
    let ct = crate::har::header(headers, "content-type").unwrap_or("");
    let media = ct.split(';').next().unwrap_or("").trim();
    if !media.eq_ignore_ascii_case("text/html") {
        return false;
    }
    if let Some(ce) = crate::har::header(headers, "content-encoding") {
        let ce = ce.trim();
        if !ce.is_empty() && !ce.eq_ignore_ascii_case("identity") {
            return false;
        }
    }
    if let Some(charset) = charset_of(ct) {
        if charset.to_ascii_lowercase().starts_with("utf-16") {
            return false;
        }
    }
    true
}

/// Extract the `charset` parameter value from a Content-Type header value.
fn charset_of(content_type: &str) -> Option<&str> {
    for param in content_type.split(';').skip(1) {
        let param = param.trim();
        if let Some(rest) = param.strip_prefix("charset") {
            let rest = rest.trim_start();
            if let Some(val) = rest.strip_prefix('=') {
                return Some(val.trim().trim_matches('"'));
            }
        }
    }
    None
}

// --- anchor search -------------------------------------------------------

/// The injection offset we can commit to *now* while streaming, or `None` to keep
/// buffering. Prefers just-after `<head …>`; failing that, before `<body`.
fn anchor_streaming(scan: &[u8]) -> Option<usize> {
    let head = tag_open_end(scan, b"head");
    let body = tag_start(scan, b"body");
    match (head, body) {
        (Some(h), Some(b)) => Some(if h <= b { h } else { b }),
        (Some(h), None) => Some(h),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// The best anchor available once we've hit the scan cap or the body's end:
/// `<head>` > `<body>` > `<html>` > `<!doctype>`. `None` ⇒ don't inject.
fn anchor_final(scan: &[u8]) -> Option<usize> {
    tag_open_end(scan, b"head")
        .or_else(|| tag_start(scan, b"body"))
        .or_else(|| tag_open_end(scan, b"html"))
        .or_else(|| doctype_end(scan))
}

/// Index just past the `>` of the first complete `<name …>` open tag.
fn tag_open_end(hay: &[u8], name: &[u8]) -> Option<usize> {
    let start = tag_start(hay, name)?;
    let gt = hay[start..].iter().position(|&b| b == b'>')?;
    Some(start + gt + 1)
}

/// Index of the `<` of the first `<name` whose name is properly terminated
/// (so `<head` doesn't match inside `<header>`).
fn tag_start(hay: &[u8], name: &[u8]) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = find_ci(&hay[from..], name, true) {
        let at = from + rel; // index just after '<' + name
        let tag_at = at - name.len() - 1; // index of '<'
        match hay.get(at) {
            Some(&c) if is_name_end(c) => return Some(tag_at),
            None => return None, // name at the very end; wait for the terminator
            _ => from = at,      // e.g. matched "head" inside "header": keep looking
        }
    }
    None
}

/// Index just past the `>` of a leading `<!doctype …>`.
fn doctype_end(hay: &[u8]) -> Option<usize> {
    let rel = find_ci(hay, b"<!doctype", false)?;
    let gt = hay[rel..].iter().position(|&b| b == b'>')?;
    Some(rel + gt + 1)
}

fn is_name_end(c: u8) -> bool {
    matches!(c, b'>' | b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'/')
}

/// ASCII case-insensitive search. When `tag` is true, `needle` is a tag name and
/// the match must be preceded by `<`; the returned index points just past the
/// matched needle (so the caller can inspect the following byte). When `tag` is
/// false, `needle` is matched literally and the returned index points at its start.
fn find_ci(hay: &[u8], needle: &[u8], tag: bool) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= hay.len() {
        let matches = hay[i..i + needle.len()].eq_ignore_ascii_case(needle);
        let lt_ok = !tag || (i > 0 && hay[i - 1] == b'<');
        if matches && (!tag || (lt_ok && first.eq_ignore_ascii_case(&hay[i]))) {
            return Some(if tag { i + needle.len() } else { i });
        }
        i += 1;
    }
    None
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// --- head editing (surgical, byte-preserving) ----------------------------

/// Split a header block's fields (no trailing CRLFCRLF) into raw line slices.
fn crlf_lines(fields: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i + 1 < fields.len() {
        if fields[i] == b'\r' && fields[i + 1] == b'\n' {
            lines.push(&fields[start..i]);
            i += 2;
            start = i;
        } else {
            i += 1;
        }
    }
    if start < fields.len() {
        lines.push(&fields[start..]);
    }
    lines
}

fn line_name(line: &[u8]) -> &[u8] {
    match line.iter().position(|&b| b == b':') {
        Some(c) => &line[..c],
        None => line,
    }
}

fn name_is(line: &[u8], target: &[u8]) -> bool {
    ascii_trim(line_name(line)).eq_ignore_ascii_case(target)
}

fn ascii_trim(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if first.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if last.is_ascii_whitespace() {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn is_continuation(line: &[u8]) -> bool {
    matches!(line.first(), Some(b' ') | Some(b'\t'))
}

fn is_csp(line: &[u8]) -> bool {
    name_is(line, b"content-security-policy")
        || name_is(line, b"content-security-policy-report-only")
        || name_is(line, b"x-content-security-policy")
}

/// Rebuild a request head with `Accept-Encoding` forced to `identity`. All other
/// bytes are preserved verbatim.
fn edit_request_head(raw_head: &[u8]) -> Vec<u8> {
    let fields = &raw_head[..raw_head.len().saturating_sub(4)];
    let lines = crlf_lines(fields);
    let mut out = Vec::with_capacity(raw_head.len() + 32);
    let mut dropped_prev = false;
    for (idx, line) in lines.iter().enumerate() {
        if idx == 0 {
            emit_line(&mut out, line);
            dropped_prev = false;
        } else if is_continuation(line) {
            if !dropped_prev {
                emit_line(&mut out, line);
            }
        } else if name_is(line, b"accept-encoding") {
            dropped_prev = true; // drop; we add a single identity below
        } else {
            emit_line(&mut out, line);
            dropped_prev = false;
        }
    }
    out.extend_from_slice(b"Accept-Encoding: identity\r\n\r\n");
    out
}

/// Rebuild a response head: drop CSP headers, and (mode A) rewrite `Content-Length`
/// to `set_cl`. All other bytes are preserved verbatim.
fn edit_response_head(raw_head: &[u8], set_cl: Option<usize>) -> Vec<u8> {
    let fields = &raw_head[..raw_head.len().saturating_sub(4)];
    let lines = crlf_lines(fields);
    let mut out = Vec::with_capacity(raw_head.len());
    let mut dropped_prev = false;
    for (idx, line) in lines.iter().enumerate() {
        if idx == 0 {
            emit_line(&mut out, line);
            dropped_prev = false;
        } else if is_continuation(line) {
            if !dropped_prev {
                emit_line(&mut out, line);
            }
        } else if is_csp(line) {
            dropped_prev = true;
        } else if set_cl.is_some() && name_is(line, b"content-length") {
            out.extend_from_slice(line_name(line));
            out.extend_from_slice(b": ");
            out.extend_from_slice(set_cl.unwrap().to_string().as_bytes());
            out.extend_from_slice(b"\r\n");
            dropped_prev = false;
        } else {
            emit_line(&mut out, line);
            dropped_prev = false;
        }
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn emit_line(out: &mut Vec<u8>, line: &[u8]) {
    out.extend_from_slice(line);
    out.extend_from_slice(b"\r\n");
}

// --- chunked helpers -----------------------------------------------------

/// Decode as much chunked body as is available into `decoded` (draining `buf`).
fn chunked_decode(reader: &mut ChunkReader, buf: &mut Vec<u8>, decoded: &mut Vec<u8>) -> Step {
    let (mut wire_len, mut truncated) = (0usize, false);
    reader.consume(buf, decoded, &mut wire_len, &mut truncated)
}

/// Consume chunked body for framing, emitting the consumed bytes to `out`
/// verbatim (used for non-injected passthrough of a chunked message).
fn chunked_verbatim(reader: &mut ChunkReader, buf: &mut Vec<u8>, out: &mut Vec<u8>) -> Step {
    let snapshot = buf.clone();
    let before = buf.len();
    let (mut junk, mut wire_len, mut truncated) = (Vec::new(), 0usize, false);
    let step = reader.consume(buf, &mut junk, &mut wire_len, &mut truncated);
    let consumed = before - buf.len();
    out.extend_from_slice(&snapshot[..consumed]);
    step
}

/// Emit `data` as a single HTTP chunk (`{hex-len}\r\n{data}\r\n`). Empty → nothing.
fn rechunk(data: &[u8], out: &mut Vec<u8>) {
    if data.is_empty() {
        return;
    }
    out.extend_from_slice(format!("{:x}\r\n", data.len()).as_bytes());
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    const CSS: &str = ".ad,.sponsored{display:none!important;}";

    /// A rewriter with element-hiding on (no scriptlets).
    fn hiding() -> HttpRewriter {
        let mut r = HttpRewriter::new();
        r.set_cosmetic(CSS.to_string(), String::new());
        r
    }

    /// Reconstruct the blob the rewriter builds, for length/marker assertions.
    fn blob(css: &str, js: &str) -> String {
        let mut b = String::from("<!--adw-cosmetic-->");
        if !js.is_empty() {
            b.push_str("<script>");
            b.push_str(js);
            b.push_str("</script>");
        }
        if !css.is_empty() {
            b.push_str("<style id=\"adw-cosmetic\">");
            b.push_str(css);
            b.push_str("</style>");
        }
        b
    }

    fn split_body(out: &[u8]) -> (&[u8], &[u8]) {
        let end = find_header_end(out).expect("head");
        (&out[..end], &out[end..])
    }

    fn dechunk(mut b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let nl = b.iter().position(|&c| c == b'\n').expect("size line");
            let hex = String::from_utf8_lossy(&b[..nl]);
            let size = usize::from_str_radix(hex.trim(), 16).expect("hex size");
            b = &b[nl + 1..];
            if size == 0 {
                break;
            }
            out.extend_from_slice(&b[..size]);
            b = &b[size + 2..]; // data + CRLF
        }
        out
    }

    const HTML: &str = "<html><head></head><body>x</body></html>";

    fn cl_response(ct: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn injects_into_content_length_html() {
        let mut r = hiding();
        let out = r.feed_response(&cl_response("text/html", HTML));
        let s = String::from_utf8_lossy(&out).to_string();
        let n = blob(CSS, "").len();

        assert!(s.contains(&format!("Content-Length: {}", HTML.len() + n)), "CL rewritten: {s}");
        assert!(!s.contains("Connection: close"), "keep-alive preserved: {s}");
        // Injected right after <head>, containing the CSS.
        assert!(s.contains("<head><!--adw-cosmetic-->"), "anchored after <head>: {s}");
        assert!(s.contains(CSS), "css present: {s}");
        let (_, body) = split_body(&out);
        assert_eq!(body.len(), HTML.len() + n, "body byte count matches CL");
    }

    #[test]
    fn injects_into_chunked_html() {
        let mut r = hiding();
        let mut resp =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n"
                .to_vec();
        resp.extend_from_slice(format!("{:x}\r\n{HTML}\r\n0\r\n\r\n", HTML.len()).as_bytes());
        let out = r.feed_response(&resp);
        let s = String::from_utf8_lossy(&out).to_string();

        assert!(s.contains("Transfer-Encoding: chunked"), "TE preserved: {s}");
        assert!(!s.contains("Content-Length"), "no CL added for chunked: {s}");
        let (_, body) = split_body(&out);
        let decoded = dechunk(body);
        let ds = String::from_utf8_lossy(&decoded);
        assert!(ds.contains("<head><!--adw-cosmetic-->"), "decoded injects at head: {ds}");
        assert!(ds.starts_with("<html><head>") && ds.ends_with("</body></html>"), "{ds}");
    }

    #[test]
    fn strips_csp_only_when_injecting() {
        let mut r = hiding();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Security-Policy: default-src 'self'\r\nX-Content-Security-Policy: x\r\nContent-Length: {}\r\n\r\n{HTML}",
            HTML.len()
        );
        let out = r.feed_response(resp.as_bytes());
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("Content-Security-Policy"), "CSP stripped on inject: {s}");
        assert!(!s.contains("X-Content-Security-Policy"), "x-CSP stripped: {s}");

        // A non-injected (JSON) response keeps its CSP.
        let mut r2 = hiding();
        let json = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Security-Policy: default-src 'self'\r\nContent-Length: 2\r\n\r\n{}";
        let out2 = r2.feed_response(json.as_bytes());
        assert_eq!(out2, json.as_bytes(), "non-injected passthrough keeps CSP byte-for-byte");
    }

    #[test]
    fn non_html_passthrough_byte_for_byte() {
        for ct in ["application/json", "image/png", "text/plain"] {
            let mut r = hiding();
            let resp = cl_response(ct, "some-body-bytes");
            let out = r.feed_response(&resp);
            assert_eq!(out, resp, "{ct} must pass through unchanged");
        }
    }

    #[test]
    fn idempotent_when_marker_present() {
        let mut r = hiding();
        let body = "<html><head><!--adw-cosmetic--></head><body>x</body></html>";
        let resp = cl_response("text/html", body);
        let out = r.feed_response(&resp);
        assert_eq!(out, resp, "already-marked doc is not re-injected");
    }

    #[test]
    fn content_encoding_gzip_passthrough() {
        let mut r = hiding();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n{HTML}",
            HTML.len()
        );
        let out = r.feed_response(resp.as_bytes());
        assert_eq!(out, resp.as_bytes(), "compressed html is never injected");
    }

    #[test]
    fn request_accept_encoding_forced_identity() {
        let mut r = hiding();
        let req = "GET / HTTP/1.1\r\nHost: h\r\nAccept-Encoding: gzip, br\r\nIf-None-Match: \"abc\"\r\n\r\n";
        let out = r.feed_request(req.as_bytes());
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("Accept-Encoding: identity"), "forced identity: {s}");
        assert!(!s.contains("gzip"), "old AE removed: {s}");
        assert!(s.contains("Host: h"), "other headers kept: {s}");
        assert!(s.contains("If-None-Match: \"abc\""), "conditional headers kept: {s}");
    }

    #[test]
    fn request_post_body_preserved() {
        let mut r = hiding();
        let req = "POST /f HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nAccept-Encoding: gzip\r\n\r\nhello";
        let out = r.feed_request(req.as_bytes());
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("Accept-Encoding: identity"));
        assert!(s.ends_with("\r\n\r\nhello"), "body preserved verbatim: {s}");
    }

    #[test]
    fn anchor_not_found_passthrough() {
        let mut r = hiding();
        let resp = cl_response("text/html", "plain text, no tags at all");
        let out = r.feed_response(&resp);
        assert_eq!(out, resp, "no anchor -> verbatim, CL unchanged");
    }

    #[test]
    fn head_response_then_get_keepalive() {
        let mut r = hiding();
        r.feed_request(b"HEAD /a HTTP/1.1\r\nHost: h\r\n\r\n");
        r.feed_request(b"GET /b HTTP/1.1\r\nHost: h\r\n\r\n");
        // HEAD response advertises a length but has no body; the GET's HTML follows.
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 100\r\n\r\n".to_vec();
        resp.extend_from_slice(&cl_response("text/html", HTML));
        let out = r.feed_response(&resp);
        let s = String::from_utf8_lossy(&out);
        // Exactly one injection (the GET), and the HEAD head passed through.
        assert_eq!(s.matches("adw-cosmetic").count(), 2, "one blob (marker+style id): {s}");
        assert!(s.contains("Content-Length: 100\r\n"), "HEAD head verbatim: {s}");
    }

    #[test]
    fn no_body_statuses_passthrough() {
        for status in ["304 Not Modified", "204 No Content"] {
            let mut r = hiding();
            let resp = format!("HTTP/1.1 {status}\r\nContent-Type: text/html\r\n\r\n").into_bytes();
            let out = r.feed_response(&resp);
            assert_eq!(out, resp, "{status} has no body");
        }
    }

    #[test]
    fn partial_206_passthrough() {
        let mut r = hiding();
        let resp = "HTTP/1.1 206 Partial Content\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\nabc";
        let out = r.feed_response(resp.as_bytes());
        assert_eq!(out, resp.as_bytes(), "ranged responses are not injected");
    }

    #[test]
    fn websocket_101_disables_forever() {
        let mut r = hiding();
        let resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x00\x01\x02rawframe";
        let out = r.feed_response(resp);
        assert_eq!(out, resp, "101 + trailing frame verbatim");
        // Subsequent bytes (either direction) stay verbatim.
        assert_eq!(r.feed_response(b"\xde\xad"), b"\xde\xad");
        assert_eq!(r.feed_request(b"anything"), b"anything");
    }

    #[test]
    fn sse_passthrough() {
        let mut r = hiding();
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: hi\n\n";
        let out = r.feed_response(resp.as_bytes());
        assert_eq!(out, resp.as_bytes(), "SSE stream untouched");
    }

    #[test]
    fn scriptlet_runs_before_page_scripts() {
        let mut r = HttpRewriter::new();
        r.set_cosmetic(CSS.to_string(), "window.x=1;".to_string());
        let body = "<html><head><script>page()</script></head><body>x</body></html>";
        let out = r.feed_response(&cl_response("text/html", body));
        let s = String::from_utf8_lossy(&out);
        let injected = s.find("window.x=1;").expect("scriptlet present");
        let page = s.find("page()").expect("page script present");
        assert!(injected < page, "scriptlet injected before the page's own script: {s}");
        // Script precedes style in the blob.
        assert!(s.find("<script>window.x=1;").unwrap() < s.find("<style id=").unwrap());
    }

    #[test]
    fn anchor_split_across_feeds() {
        let mut r = hiding();
        let mut out = Vec::new();
        // Head first, then the body dribbled across feeds that split the <head> tag.
        out.extend(r.feed_response(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 40\r\n\r\n"));
        out.extend(r.feed_response(b"<htm"));
        out.extend(r.feed_response(b"l><he"));
        out.extend(r.feed_response(b"ad></head><body>x</body></html>"));
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("<head><!--adw-cosmetic-->"), "single injection at head across feeds: {s}");
        assert_eq!(s.matches("adw-cosmetic").count(), 2, "injected exactly once: {s}");
    }

    #[test]
    fn utf16_charset_passthrough() {
        let mut r = hiding();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-16\r\nContent-Length: {}\r\n\r\n{HTML}",
            HTML.len()
        );
        let out = r.feed_response(resp.as_bytes());
        assert_eq!(out, resp.as_bytes(), "utf-16 documents are not injected");
    }

    #[test]
    fn utf16_bom_body_passthrough() {
        let mut r = hiding();
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 6\r\n\r\n".to_vec();
        resp.extend_from_slice(&[0xFF, 0xFE, b'<', 0x00, b'h', 0x00]);
        let out = r.feed_response(&resp);
        assert_eq!(out, resp, "BOM-led utf-16 body is not injected");
    }

    #[test]
    fn cosmetics_off_is_identity() {
        let mut r = HttpRewriter::new();
        r.set_cosmetic(String::new(), String::new());
        let req = b"GET / HTTP/1.1\r\nHost: h\r\nAccept-Encoding: gzip\r\n\r\n";
        assert_eq!(r.feed_request(req), req, "request untouched incl. Accept-Encoding");
        let resp = cl_response("text/html", HTML);
        assert_eq!(r.feed_response(&resp), resp, "response untouched");
    }

    #[test]
    fn passthrough_before_payload_then_injects_next() {
        // Defensive: a response fed before set_cosmetic passes through; a later
        // response (after the payload lands) is injected. Ordering guarantees this
        // never happens for the first message in practice.
        let mut r = HttpRewriter::new();
        let resp1 = cl_response("text/html", HTML);
        assert_eq!(r.feed_response(&resp1), resp1, "pre-payload passthrough");
        r.set_cosmetic(CSS.to_string(), String::new());
        let out = r.feed_response(&cl_response("text/html", HTML));
        assert!(String::from_utf8_lossy(&out).contains("adw-cosmetic"), "injects after payload set");
    }
}
