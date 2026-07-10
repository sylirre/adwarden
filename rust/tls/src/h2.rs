// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! A minimal HTTP/2 *server*, just enough to filter DoH (P3).
//!
//! DoH clients (Chrome, Firefox, Android) speak HTTP/2, so to filter the DNS
//! inside an intercepted DoH flow we must terminate h2 on the app-facing side:
//! read the request streams, and answer each either with a synthesized response
//! (blocked) or by relaying the real resolver's answer (allowed). The resolver
//! side is re-originated as HTTP/1.1 (see [`crate::dns`]), so only the *server*
//! half of h2 lives here.
//!
//! Scope is deliberately small and DoH-shaped: requests and responses are tiny
//! (one HEADERS, optionally one DATA), so we grant a generous initial window and
//! don't actively manage outbound flow control. HPACK (with its connection-wide
//! dynamic table and Huffman coding) is handled by `fluke-hpack`; this module
//! owns only the framing and stream bookkeeping. Anything malformed fails the
//! connection rather than risk corrupting it.

use std::collections::HashMap;

use fluke_hpack::{Decoder, Encoder};

/// The client connection preface that opens every h2 connection.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_HEADER: usize = 9;
/// Our advertised SETTINGS_MAX_FRAME_SIZE and the cap we chunk responses to.
const MAX_FRAME: usize = 16_384;
/// Refuse to buffer an unreasonably large header block / body (DoH is tiny).
const MAX_STREAM_BYTES: usize = 64 * 1024;

// Frame types.
const T_DATA: u8 = 0x0;
const T_HEADERS: u8 = 0x1;
const T_RST_STREAM: u8 = 0x3;
const T_SETTINGS: u8 = 0x4;
const T_PING: u8 = 0x6;
const T_GOAWAY: u8 = 0x7;
const T_WINDOW_UPDATE: u8 = 0x8;
const T_CONTINUATION: u8 = 0x9;

// Frame flags.
const F_ACK: u8 = 0x1;
const F_END_STREAM: u8 = 0x1;
const F_END_HEADERS: u8 = 0x4;
const F_PADDED: u8 = 0x8;
const F_PRIORITY: u8 = 0x20;

/// A completed request stream, ready to filter.
pub struct H2Request {
    pub stream_id: u32,
    pub method: String,
    pub path: String,
    pub authority: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

#[derive(Default)]
struct Stream {
    method: String,
    path: String,
    authority: String,
    content_type: String,
    body: Vec<u8>,
    /// Accumulated HEADERS(+CONTINUATION) fragments awaiting END_HEADERS.
    header_block: Vec<u8>,
    headers_done: bool,
    end_stream: bool,
    /// Emitted to `ready` already (so a stray extra frame can't double-count).
    dispatched: bool,
}

pub struct H2Server {
    inbuf: Vec<u8>,
    preface_seen: bool,
    settings_sent: bool,
    dec: Decoder<'static>,
    enc: Encoder<'static>,
    streams: HashMap<u32, Stream>,
    /// Stream currently mid-header-block (between HEADERS and its END_HEADERS);
    /// only CONTINUATION frames for it are legal until then.
    continuation: Option<u32>,
    out: Vec<u8>,
    ready: Vec<H2Request>,
    failed: bool,
}

impl Default for H2Server {
    fn default() -> Self {
        Self::new()
    }
}

impl H2Server {
    pub fn new() -> Self {
        H2Server {
            inbuf: Vec::new(),
            preface_seen: false,
            settings_sent: false,
            dec: Decoder::new(),
            enc: Encoder::new(),
            streams: HashMap::new(),
            continuation: None,
            out: Vec::new(),
            ready: Vec::new(),
            failed: false,
        }
    }

    pub fn failed(&self) -> bool {
        self.failed
    }

    /// Drain the plaintext bytes to send to the app (frames we've produced).
    pub fn take_out(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// Drain the request streams that have completed since the last call.
    pub fn take_requests(&mut self) -> Vec<H2Request> {
        std::mem::take(&mut self.ready)
    }

    /// Feed decrypted bytes received from the app.
    pub fn on_input(&mut self, data: &[u8]) {
        if self.failed {
            return;
        }
        if !self.settings_sent {
            // Server connection preface: an (empty) SETTINGS frame, sent before
            // anything else, then a large connection-level WINDOW_UPDATE so a
            // long-lived DoH connection never stalls on flow control (we don't
            // track per-frame windows; request bodies are tiny and streams close
            // immediately, so the default per-stream window suffices).
            self.write_frame(T_SETTINGS, 0, 0, &[]);
            self.write_frame(T_WINDOW_UPDATE, 0, 0, &0x7fff_0000u32.to_be_bytes());
            self.settings_sent = true;
        }
        self.inbuf.extend_from_slice(data);
        if !self.preface_seen {
            if self.inbuf.len() < PREFACE.len() {
                return;
            }
            if &self.inbuf[..PREFACE.len()] != PREFACE {
                self.failed = true;
                return;
            }
            self.inbuf.drain(..PREFACE.len());
            self.preface_seen = true;
        }
        self.parse_frames();
    }

    /// Queue a full response (HEADERS + DATA, END_STREAM) for `stream_id`.
    pub fn respond(&mut self, stream_id: u32, status: u16, content_type: &str, body: &[u8]) {
        let status = status.to_string();
        let len = body.len().to_string();
        let headers: Vec<(&[u8], &[u8])> = vec![
            (b":status", status.as_bytes()),
            (b"content-type", content_type.as_bytes()),
            (b"content-length", len.as_bytes()),
        ];
        let block = self.enc.encode(headers.into_iter());
        let end_on_headers = body.is_empty();
        self.write_frame(
            T_HEADERS,
            if end_on_headers { F_END_HEADERS | F_END_STREAM } else { F_END_HEADERS },
            stream_id,
            &block,
        );
        if !body.is_empty() {
            // DoH bodies are small, but chunk defensively at MAX_FRAME.
            let mut off = 0;
            while off < body.len() {
                let end = (off + MAX_FRAME).min(body.len());
                let last = end == body.len();
                self.write_frame(
                    T_DATA,
                    if last { F_END_STREAM } else { 0 },
                    stream_id,
                    &body[off..end],
                );
                off = end;
            }
        }
        self.streams.remove(&stream_id);
    }

    /// Serialize one frame into the outbound buffer.
    fn write_frame(&mut self, ty: u8, flags: u8, stream_id: u32, payload: &[u8]) {
        let len = payload.len();
        self.out.push((len >> 16) as u8);
        self.out.push((len >> 8) as u8);
        self.out.push(len as u8);
        self.out.push(ty);
        self.out.push(flags);
        self.out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        self.out.extend_from_slice(payload);
    }

    fn parse_frames(&mut self) {
        while !self.failed {
            if self.inbuf.len() < FRAME_HEADER {
                break;
            }
            let len = ((self.inbuf[0] as usize) << 16)
                | ((self.inbuf[1] as usize) << 8)
                | self.inbuf[2] as usize;
            if len > MAX_STREAM_BYTES {
                self.failed = true;
                break;
            }
            if self.inbuf.len() < FRAME_HEADER + len {
                break; // frame still arriving
            }
            let ty = self.inbuf[3];
            let flags = self.inbuf[4];
            let stream_id =
                u32::from_be_bytes([self.inbuf[5], self.inbuf[6], self.inbuf[7], self.inbuf[8]])
                    & 0x7fff_ffff;
            let payload: Vec<u8> = self.inbuf[FRAME_HEADER..FRAME_HEADER + len].to_vec();
            self.inbuf.drain(..FRAME_HEADER + len);

            // A header block must be a contiguous HEADERS + CONTINUATION run.
            if let Some(open) = self.continuation {
                if ty != T_CONTINUATION || stream_id != open {
                    self.failed = true;
                    break;
                }
            }

            match ty {
                T_SETTINGS => self.on_settings(flags),
                T_PING => self.on_ping(flags, &payload),
                T_HEADERS => self.on_headers(flags, stream_id, &payload),
                T_CONTINUATION => self.on_continuation(flags, stream_id, &payload),
                T_DATA => self.on_data(flags, stream_id, &payload),
                T_RST_STREAM => {
                    self.streams.remove(&stream_id);
                }
                T_GOAWAY => {
                    // Client is closing; stop accepting new work.
                    self.failed = true;
                }
                // WINDOW_UPDATE / PRIORITY / PUSH_PROMISE: ignored (our responses
                // fit in the default window; we never push or prioritize).
                T_WINDOW_UPDATE => {}
                _ => {}
            }
        }
    }

    fn on_settings(&mut self, flags: u8) {
        if flags & F_ACK == 0 {
            // Acknowledge the client's SETTINGS (we don't act on the values —
            // DoH responses fit within defaults).
            self.write_frame(T_SETTINGS, F_ACK, 0, &[]);
        }
    }

    fn on_ping(&mut self, flags: u8, payload: &[u8]) {
        if flags & F_ACK == 0 && payload.len() == 8 {
            self.write_frame(T_PING, F_ACK, 0, payload);
        }
    }

    fn on_headers(&mut self, flags: u8, stream_id: u32, payload: &[u8]) {
        if stream_id == 0 {
            self.failed = true;
            return;
        }
        let mut p = payload;
        // Strip padding (PADDED) and the priority prefix (PRIORITY) if present.
        let mut pad = 0usize;
        if flags & F_PADDED != 0 {
            if p.is_empty() {
                self.failed = true;
                return;
            }
            pad = p[0] as usize;
            p = &p[1..];
        }
        if flags & F_PRIORITY != 0 {
            if p.len() < 5 {
                self.failed = true;
                return;
            }
            p = &p[5..];
        }
        if pad > p.len() {
            self.failed = true;
            return;
        }
        let fragment = &p[..p.len() - pad];

        let stream = self.streams.entry(stream_id).or_default();
        if stream.header_block.len() + fragment.len() > MAX_STREAM_BYTES {
            self.failed = true;
            return;
        }
        stream.header_block.extend_from_slice(fragment);
        stream.end_stream = flags & F_END_STREAM != 0;
        if flags & F_END_HEADERS != 0 {
            self.finish_headers(stream_id);
        } else {
            self.continuation = Some(stream_id);
        }
    }

    fn on_continuation(&mut self, flags: u8, stream_id: u32, payload: &[u8]) {
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            self.failed = true;
            return;
        };
        if stream.header_block.len() + payload.len() > MAX_STREAM_BYTES {
            self.failed = true;
            return;
        }
        stream.header_block.extend_from_slice(payload);
        if flags & F_END_HEADERS != 0 {
            self.continuation = None;
            self.finish_headers(stream_id);
        }
    }

    /// Decode a completed header block (keeps the HPACK dynamic table in sync)
    /// and record the request pseudo-headers.
    fn finish_headers(&mut self, stream_id: u32) {
        let block = match self.streams.get_mut(&stream_id) {
            Some(s) => std::mem::take(&mut s.header_block),
            None => return,
        };
        let decoded = match self.dec.decode(&block) {
            Ok(h) => h,
            Err(_) => {
                self.failed = true;
                return;
            }
        };
        let Some(stream) = self.streams.get_mut(&stream_id) else { return };
        stream.headers_done = true;
        for (name, value) in decoded {
            let v = String::from_utf8_lossy(&value).into_owned();
            match name.as_slice() {
                b":method" => stream.method = v,
                b":path" => stream.path = v,
                b":authority" => stream.authority = v,
                b"content-type" => stream.content_type = v,
                _ => {}
            }
        }
        self.maybe_dispatch(stream_id);
    }

    fn on_data(&mut self, flags: u8, stream_id: u32, payload: &[u8]) {
        let mut p = payload;
        if flags & F_PADDED != 0 {
            if p.is_empty() {
                self.failed = true;
                return;
            }
            let pad = p[0] as usize;
            p = &p[1..];
            if pad > p.len() {
                self.failed = true;
                return;
            }
            p = &p[..p.len() - pad];
        }
        let Some(stream) = self.streams.get_mut(&stream_id) else {
            // DATA for an unknown/closed stream: ignore.
            return;
        };
        if stream.body.len() + p.len() > MAX_STREAM_BYTES {
            self.failed = true;
            return;
        }
        stream.body.extend_from_slice(p);
        if flags & F_END_STREAM != 0 {
            stream.end_stream = true;
        }
        self.maybe_dispatch(stream_id);
    }

    /// If a stream has its headers and its end-of-stream, surface it once.
    fn maybe_dispatch(&mut self, stream_id: u32) {
        let ready = match self.streams.get(&stream_id) {
            Some(s) => s.headers_done && s.end_stream && !s.dispatched,
            None => false,
        };
        if !ready {
            return;
        }
        let stream = self.streams.get_mut(&stream_id).unwrap();
        stream.dispatched = true;
        self.ready.push(H2Request {
            stream_id,
            method: stream.method.clone(),
            path: stream.path.clone(),
            authority: stream.authority.clone(),
            content_type: stream.content_type.clone(),
            body: std::mem::take(&mut stream.body),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode one client HEADERS block with the given headers.
    fn client_headers(enc: &mut Encoder, headers: &[(&[u8], &[u8])]) -> Vec<u8> {
        enc.encode(headers.iter().copied())
    }

    fn frame(ty: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let len = payload.len();
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
        out.push(ty);
        out.push(flags);
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Parse the server's outbound bytes into (type, flags, stream_id, payload).
    fn parse_out(mut buf: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
        let mut frames = Vec::new();
        while buf.len() >= FRAME_HEADER {
            let len = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | buf[2] as usize;
            let ty = buf[3];
            let flags = buf[4];
            let sid = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
            let payload = buf[FRAME_HEADER..FRAME_HEADER + len].to_vec();
            frames.push((ty, flags, sid, payload));
            buf = &buf[FRAME_HEADER + len..];
        }
        frames
    }

    #[test]
    fn parses_a_get_request_and_acks_settings() {
        let mut server = H2Server::new();
        let mut enc = Encoder::new();

        let mut input = Vec::new();
        input.extend_from_slice(PREFACE);
        input.extend_from_slice(&frame(T_SETTINGS, 0, 0, &[]));
        let block = client_headers(
            &mut enc,
            &[
                (b":method", b"GET"),
                (b":path", b"/dns-query?dns=AAAA"),
                (b":authority", b"dns.google"),
                (b":scheme", b"https"),
            ],
        );
        input.extend_from_slice(&frame(T_HEADERS, F_END_HEADERS | F_END_STREAM, 1, &block));

        server.on_input(&input);
        let reqs = server.take_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "GET");
        assert_eq!(reqs[0].path, "/dns-query?dns=AAAA");
        assert_eq!(reqs[0].authority, "dns.google");
        assert!(!server.failed());

        // Server should have emitted its SETTINGS and an ACK of the client's.
        let out = parse_out(&server.take_out());
        assert!(out.iter().any(|(t, f, _, _)| *t == T_SETTINGS && *f == 0), "own SETTINGS");
        assert!(out.iter().any(|(t, f, _, _)| *t == T_SETTINGS && *f == F_ACK), "SETTINGS ACK");
    }

    #[test]
    fn parses_post_with_body() {
        let mut server = H2Server::new();
        let mut enc = Encoder::new();
        let mut input = Vec::new();
        input.extend_from_slice(PREFACE);
        let block = client_headers(
            &mut enc,
            &[
                (b":method", b"POST"),
                (b":path", b"/dns-query"),
                (b":authority", b"cloudflare-dns.com"),
                (b"content-type", b"application/dns-message"),
            ],
        );
        input.extend_from_slice(&frame(T_HEADERS, F_END_HEADERS, 1, &block));
        input.extend_from_slice(&frame(T_DATA, F_END_STREAM, 1, b"\xab\xcdwire"));
        server.on_input(&input);
        let reqs = server.take_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].method, "POST");
        assert_eq!(reqs[0].content_type, "application/dns-message");
        assert_eq!(reqs[0].body, b"\xab\xcdwire");
    }

    #[test]
    fn respond_roundtrips_through_a_client_decoder() {
        let mut server = H2Server::new();
        let mut enc = Encoder::new();
        let mut input = Vec::new();
        input.extend_from_slice(PREFACE);
        let block = client_headers(&mut enc, &[(b":method", b"POST"), (b":path", b"/dns-query")]);
        input.extend_from_slice(&frame(T_HEADERS, F_END_HEADERS, 1, &block));
        input.extend_from_slice(&frame(T_DATA, F_END_STREAM, 1, b"q"));
        server.on_input(&input);
        let _ = server.take_requests();
        let _ = server.take_out();

        server.respond(1, 200, "application/dns-message", b"answer");
        let out = server.take_out();
        let frames = parse_out(&out);
        // HEADERS then DATA on stream 1, DATA carrying the body with END_STREAM.
        let headers = frames.iter().find(|(t, _, s, _)| *t == T_HEADERS && *s == 1).unwrap();
        let mut dec = Decoder::new();
        let decoded = dec.decode(&headers.3).unwrap();
        assert!(decoded.iter().any(|(n, v)| n == b":status" && v == b"200"));
        let data = frames.iter().find(|(t, _, s, _)| *t == T_DATA && *s == 1).unwrap();
        assert_eq!(data.1 & F_END_STREAM, F_END_STREAM);
        assert_eq!(data.3, b"answer");
    }

    #[test]
    fn bad_preface_fails() {
        let mut server = H2Server::new();
        server.on_input(b"NOT-AN-H2-PREFACE-AT-ALL-XXXX");
        assert!(server.failed());
    }
}
