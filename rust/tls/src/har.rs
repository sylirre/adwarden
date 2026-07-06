//! Cleartext HTTP capture off intercepted flows, exported as HAR 1.2 (P2-3).
//!
//! For a flow being TLS-intercepted, [`crate::TlsMitm`] decrypts both directions
//! and shuttles plaintext between the two rustls sessions. An [`HttpTap`] observes
//! that plaintext — app→upstream is the request stream, upstream→app is the
//! response stream — parses HTTP/1.1 messages, pairs each request with its
//! response (keep-alive responses arrive in request order), and hands completed
//! [`HttpTransaction`]s up to the datapath, which buffers them for a HAR export.
//!
//! **HTTP/1.1 only, by construction.** The interception server config advertises
//! no ALPN, so a cooperating app negotiates HTTP/1.1 with us (never h2); the
//! upstream client likewise. Anything that isn't parseable HTTP/1.1 (h2 preface,
//! WebSocket frames after an upgrade, raw TLS-in-TLS, gRPC, …) trips the tap into
//! a disabled state: it stops capturing that flow and emits nothing further,
//! rather than fabricating garbage entries. Bodies and headers are size-capped so
//! a large download can't grow the datapath's memory without bound.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

/// Max header block we'll buffer before deciding a stream isn't HTTP.
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Max body bytes stored per message (the rest is counted but discarded).
const MAX_BODY_CAPTURE: usize = 512 * 1024;

/// A captured request/response pair for one HTTP transaction.
#[derive(Clone)]
pub struct HttpTransaction {
    /// Authority for the URL: the request's `Host` header, else the SNI.
    pub host: Option<String>,
    /// Wall-clock start (unix millis), stamped when the request headers arrived.
    pub started_unix_ms: u64,
    /// Elapsed millis from request start to response completion.
    pub duration_ms: u64,
    pub request: HttpRequest,
    pub response: HttpResponse,
}

/// A parsed HTTP request (headers plus a size-capped body copy).
#[derive(Clone)]
pub struct HttpRequest {
    pub method: String,
    /// Request-target as sent (origin-form, e.g. `/path?q=1`).
    pub target: String,
    pub http_version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Bytes seen on the wire for the body (may exceed `body.len()` if truncated).
    pub body_size: i64,
    pub headers_size: i64,
    pub body_truncated: bool,
}

/// A parsed HTTP response (headers plus a size-capped body copy).
#[derive(Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub status_text: String,
    pub http_version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub body_size: i64,
    pub headers_size: i64,
    pub body_truncated: bool,
}

/// How a message body is delimited on the wire.
enum Framing {
    /// `Content-Length`: this many bytes remain.
    Length(usize),
    /// `Transfer-Encoding: chunked`.
    Chunked(ChunkReader),
    /// No length and no chunking: the body runs until the connection closes
    /// (finalized by [`HttpTap::finish`]). Responses only.
    UntilClose,
}

/// Accumulates a body, storing up to [`MAX_BODY_CAPTURE`] and counting the rest.
struct BodyReader {
    framing: Framing,
    captured: Vec<u8>,
    wire_len: usize,
    truncated: bool,
}

enum Step {
    NeedMore,
    Done,
    Error,
}

/// Append body bytes to `captured` up to [`MAX_BODY_CAPTURE`], counting all of
/// them on the wire and flagging truncation once the cap is hit.
fn push_capped(captured: &mut Vec<u8>, wire_len: &mut usize, truncated: &mut bool, data: &[u8]) {
    *wire_len += data.len();
    let room = MAX_BODY_CAPTURE.saturating_sub(captured.len());
    if room >= data.len() {
        captured.extend_from_slice(data);
    } else {
        captured.extend_from_slice(&data[..room]);
        *truncated = true;
    }
}

impl BodyReader {
    fn new(framing: Framing) -> Self {
        BodyReader { framing, captured: Vec::new(), wire_len: 0, truncated: false }
    }

    /// Consume as much of `buf` as belongs to this body. Drains what it uses.
    fn consume(&mut self, buf: &mut Vec<u8>) -> Step {
        let BodyReader { framing, captured, wire_len, truncated } = self;
        match framing {
            Framing::Length(remaining) => {
                if *remaining == 0 {
                    return Step::Done;
                }
                let n = (*remaining).min(buf.len());
                if n > 0 {
                    let chunk: Vec<u8> = buf.drain(..n).collect();
                    push_capped(captured, wire_len, truncated, &chunk);
                    *remaining -= n;
                }
                if *remaining == 0 {
                    Step::Done
                } else {
                    Step::NeedMore
                }
            }
            Framing::UntilClose => {
                if !buf.is_empty() {
                    let chunk: Vec<u8> = std::mem::take(buf);
                    push_capped(captured, wire_len, truncated, &chunk);
                }
                Step::NeedMore // only completes on finish()
            }
            Framing::Chunked(reader) => reader.consume(buf, captured, wire_len, truncated),
        }
    }
}

/// Incremental `Transfer-Encoding: chunked` decoder.
enum ChunkState {
    /// Reading the hex size line (accumulated, sans CRLF).
    Size(Vec<u8>),
    /// Reading `n` remaining data bytes of the current chunk.
    Data(usize),
    /// Consuming the CRLF that terminates a chunk's data.
    DataCrlf,
    /// After the terminating 0-chunk: consuming trailer lines to the blank line.
    Trailer(Vec<u8>),
}

struct ChunkReader {
    state: ChunkState,
}

impl ChunkReader {
    fn new() -> Self {
        ChunkReader { state: ChunkState::Size(Vec::new()) }
    }

    fn consume(
        &mut self,
        buf: &mut Vec<u8>,
        captured: &mut Vec<u8>,
        wire_len: &mut usize,
        truncated: &mut bool,
    ) -> Step {
        loop {
            match &mut self.state {
                ChunkState::Size(line) => {
                    let Some(pos) = buf.iter().position(|&b| b == b'\n') else {
                        // No full line yet; buffer it (bounded) and wait.
                        if buf.len() > MAX_HEADER_BYTES {
                            return Step::Error;
                        }
                        line.extend_from_slice(buf);
                        buf.clear();
                        return Step::NeedMore;
                    };
                    line.extend(buf.drain(..=pos));
                    let text = trim_crlf(line);
                    // A chunk-size line may carry `;ext` extensions.
                    let hex = text.split(|&b| b == b';').next().unwrap_or(&[]);
                    let Some(size) = parse_hex(hex) else { return Step::Error };
                    if size == 0 {
                        self.state = ChunkState::Trailer(Vec::new());
                    } else {
                        self.state = ChunkState::Data(size);
                    }
                }
                ChunkState::Data(remaining) => {
                    if *remaining == 0 {
                        self.state = ChunkState::DataCrlf;
                        continue;
                    }
                    let n = (*remaining).min(buf.len());
                    if n == 0 {
                        return Step::NeedMore;
                    }
                    let chunk: Vec<u8> = buf.drain(..n).collect();
                    push_capped(captured, wire_len, truncated, &chunk);
                    *remaining -= n;
                }
                ChunkState::DataCrlf => {
                    // Expect CRLF (or bare LF) after the chunk data.
                    if buf.is_empty() {
                        return Step::NeedMore;
                    }
                    if buf[0] == b'\r' {
                        if buf.len() < 2 {
                            return Step::NeedMore;
                        }
                        buf.drain(..2);
                    } else {
                        buf.drain(..1);
                    }
                    self.state = ChunkState::Size(Vec::new());
                }
                ChunkState::Trailer(line) => {
                    let Some(pos) = buf.iter().position(|&b| b == b'\n') else {
                        if buf.len() > MAX_HEADER_BYTES {
                            return Step::Error;
                        }
                        line.extend_from_slice(buf);
                        buf.clear();
                        return Step::NeedMore;
                    };
                    line.extend(buf.drain(..=pos));
                    let done = trim_crlf(line).is_empty();
                    line.clear();
                    if done {
                        return Step::Done;
                    }
                    // else: a trailer header line; keep consuming.
                }
            }
        }
    }
}

/// A completed request awaiting its response.
struct Pending {
    request: HttpRequest,
    method_is_head: bool,
    start_ms: u64,
}

/// Per-flow HTTP capture state. Fed decrypted bytes from both directions.
pub struct HttpTap {
    sni: Option<String>,
    disabled: bool,
    req_buf: Vec<u8>,
    req_partial: Option<(HttpRequest, BodyReader)>,
    resp_buf: Vec<u8>,
    /// (response-so-far, body reader) while a response body streams.
    resp_partial: Option<(HttpResponse, BodyReader)>,
    pending: VecDeque<Pending>,
    completed: Vec<HttpTransaction>,
}

impl HttpTap {
    pub fn new() -> Self {
        HttpTap {
            sni: None,
            disabled: false,
            req_buf: Vec::new(),
            req_partial: None,
            resp_buf: Vec::new(),
            resp_partial: None,
            pending: VecDeque::new(),
            completed: Vec::new(),
        }
    }

    /// Record the connection's SNI (used as the URL authority absent a Host header).
    pub fn set_host(&mut self, host: &str) {
        if self.sni.is_none() {
            self.sni = Some(host.to_string());
        }
    }

    /// Feed decrypted request-direction (app→upstream) bytes.
    pub fn feed_request(&mut self, data: &[u8]) {
        if self.disabled || data.is_empty() {
            return;
        }
        self.req_buf.extend_from_slice(data);
        self.drain_requests();
    }

    /// Feed decrypted response-direction (upstream→app) bytes.
    pub fn feed_response(&mut self, data: &[u8]) {
        if self.disabled || data.is_empty() {
            return;
        }
        self.resp_buf.extend_from_slice(data);
        self.drain_responses();
    }

    /// Drain completed transactions for the datapath to buffer.
    pub fn take_transactions(&mut self) -> Vec<HttpTransaction> {
        std::mem::take(&mut self.completed)
    }

    /// The connection closed: finalize a response whose body ran until EOF.
    pub fn finish(&mut self) {
        if self.disabled {
            return;
        }
        if let Some((mut response, body)) = self.resp_partial.take() {
            if matches!(body.framing, Framing::UntilClose) {
                Self::attach_body_resp(&mut response, body);
                self.complete_response(response);
            }
        }
        self.disabled = true;
    }

    fn disable(&mut self) {
        self.disabled = true;
        self.req_buf.clear();
        self.resp_buf.clear();
        self.req_partial = None;
        self.resp_partial = None;
    }

    // --- request side ----------------------------------------------------

    fn drain_requests(&mut self) {
        loop {
            if self.req_partial.is_none() {
                let head = match take_head(&mut self.req_buf) {
                    HeadStep::NeedMore => return,
                    HeadStep::Error => return self.disable(),
                    HeadStep::Head(h) => h,
                };
                let Some((method, target, version)) = parse_request_line(&head.start_line) else {
                    return self.disable();
                };
                let request = HttpRequest {
                    method,
                    target,
                    http_version: version,
                    headers: head.headers,
                    body: Vec::new(),
                    body_size: 0,
                    headers_size: head.size as i64,
                    body_truncated: false,
                };
                match request_framing(&request.headers) {
                    Some(framing) => self.req_partial = Some((request, BodyReader::new(framing))),
                    None => {
                        self.push_pending(request);
                        continue;
                    }
                }
            }
            let (_, body) = self.req_partial.as_mut().unwrap();
            match body.consume(&mut self.req_buf) {
                Step::NeedMore => return,
                Step::Error => return self.disable(),
                Step::Done => {
                    let (mut request, body) = self.req_partial.take().unwrap();
                    Self::attach_body_req(&mut request, body);
                    self.push_pending(request);
                }
            }
        }
    }

    fn attach_body_req(request: &mut HttpRequest, body: BodyReader) {
        request.body_size = body.wire_len as i64;
        request.body_truncated = body.truncated;
        request.body = body.captured;
    }

    fn push_pending(&mut self, request: HttpRequest) {
        let method_is_head = request.method.eq_ignore_ascii_case("HEAD");
        self.pending.push_back(Pending { request, method_is_head, start_ms: now_ms() });
    }

    // --- response side ---------------------------------------------------

    fn drain_responses(&mut self) {
        loop {
            if self.resp_partial.is_none() {
                let head = match take_head(&mut self.resp_buf) {
                    HeadStep::NeedMore => return,
                    HeadStep::Error => return self.disable(),
                    HeadStep::Head(h) => h,
                };
                let Some((version, status, status_text)) = parse_status_line(&head.start_line) else {
                    return self.disable();
                };
                let response = HttpResponse {
                    status,
                    status_text,
                    http_version: version,
                    headers: head.headers,
                    body: Vec::new(),
                    body_size: 0,
                    headers_size: head.size as i64,
                    body_truncated: false,
                };

                // 1xx (except the WebSocket 101) are informational: no body, and
                // they don't consume the pending request — the real response follows.
                if (100..=199).contains(&status) && status != 101 {
                    continue;
                }
                let method_is_head = self.pending.front().map_or(false, |p| p.method_is_head);
                match response_framing(status, method_is_head, &response.headers) {
                    None => {
                        let switching = status == 101;
                        self.complete_response(response);
                        if switching {
                            // Post-upgrade bytes aren't HTTP; stop capturing.
                            return self.disable();
                        }
                        continue;
                    }
                    Some(framing) => self.resp_partial = Some((response, BodyReader::new(framing))),
                }
            }
            let (_, body) = self.resp_partial.as_mut().unwrap();
            match body.consume(&mut self.resp_buf) {
                Step::NeedMore => return,
                Step::Error => return self.disable(),
                Step::Done => {
                    let (mut response, body) = self.resp_partial.take().unwrap();
                    Self::attach_body_resp(&mut response, body);
                    self.complete_response(response);
                }
            }
        }
    }

    fn attach_body_resp(response: &mut HttpResponse, body: BodyReader) {
        response.body_size = body.wire_len as i64;
        response.body_truncated = body.truncated;
        response.body = body.captured;
    }

    /// Pair a finished response with the front pending request and emit it.
    fn complete_response(&mut self, response: HttpResponse) {
        let Some(pending) = self.pending.pop_front() else {
            // Response with no request in flight — not something we can model.
            return self.disable();
        };
        let host = host_of(&pending.request).or_else(|| self.sni.clone());
        self.completed.push(HttpTransaction {
            host,
            started_unix_ms: pending.start_ms,
            duration_ms: now_ms().saturating_sub(pending.start_ms),
            request: pending.request,
            response,
        });
    }
}

impl Default for HttpTap {
    fn default() -> Self {
        Self::new()
    }
}

// --- header parsing ------------------------------------------------------

struct ParsedHead {
    start_line: Vec<u8>,
    headers: Vec<(String, String)>,
    /// Byte length of the whole header block including the terminating CRLFCRLF.
    size: usize,
}

enum HeadStep {
    NeedMore,
    Error,
    Head(ParsedHead),
}

/// If `buf` holds a complete header block (up to `\r\n\r\n`), parse and drain it.
fn take_head(buf: &mut Vec<u8>) -> HeadStep {
    let Some(end) = find_header_end(buf) else {
        if buf.len() > MAX_HEADER_BYTES {
            return HeadStep::Error;
        }
        return HeadStep::NeedMore;
    };
    let block: Vec<u8> = buf.drain(..end).collect();
    // `end` includes the trailing CRLFCRLF; split off the header lines.
    let body = &block[..block.len() - 4];
    let mut lines = split_crlf_lines(body);
    let Some(start_line) = lines.next() else { return HeadStep::Error };
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return HeadStep::Error;
        };
        let name = String::from_utf8_lossy(&line[..colon]).trim().to_string();
        let value = String::from_utf8_lossy(&line[colon + 1..]).trim().to_string();
        if !name.is_empty() {
            headers.push((name, value));
        }
    }
    HeadStep::Head(ParsedHead { start_line: start_line.to_vec(), headers, size: end })
}

/// Index just past the first `\r\n\r\n`, or None if not present.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn split_crlf_lines(body: &[u8]) -> impl Iterator<Item = &[u8]> {
    body.split(|&b| b == b'\n').map(|line| {
        if line.last() == Some(&b'\r') {
            &line[..line.len() - 1]
        } else {
            line
        }
    })
}

fn parse_request_line(line: &[u8]) -> Option<(String, String, String)> {
    let text = std::str::from_utf8(line).ok()?;
    let mut parts = text.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next()?.to_string();
    if !version.starts_with("HTTP/") || method.is_empty() {
        return None;
    }
    Some((method, target, version))
}

fn parse_status_line(line: &[u8]) -> Option<(String, u16, String)> {
    let text = std::str::from_utf8(line).ok()?;
    let mut parts = text.splitn(3, ' ');
    let version = parts.next()?.to_string();
    let status: u16 = parts.next()?.parse().ok()?;
    let reason = parts.next().unwrap_or("").to_string();
    if !version.starts_with("HTTP/") {
        return None;
    }
    Some((version, status, reason))
}

/// Body framing for a request: chunked or a positive Content-Length, else none.
fn request_framing(headers: &[(String, String)]) -> Option<Framing> {
    if is_chunked(headers) {
        return Some(Framing::Chunked(ChunkReader::new()));
    }
    match content_length(headers) {
        Some(n) if n > 0 => Some(Framing::Length(n)),
        _ => None,
    }
}

/// Body framing for a response, honoring the no-body cases (1xx/204/304, HEAD).
fn response_framing(status: u16, method_is_head: bool, headers: &[(String, String)]) -> Option<Framing> {
    if method_is_head || status == 204 || status == 304 || (100..=199).contains(&status) {
        return None;
    }
    if is_chunked(headers) {
        return Some(Framing::Chunked(ChunkReader::new()));
    }
    match content_length(headers) {
        Some(0) => None,
        Some(n) => Some(Framing::Length(n)),
        None => Some(Framing::UntilClose),
    }
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    header(headers, "transfer-encoding").map_or(false, |v| {
        v.split(',').any(|t| t.trim().eq_ignore_ascii_case("chunked"))
    })
}

fn content_length(headers: &[(String, String)]) -> Option<usize> {
    header(headers, "content-length").and_then(|v| v.trim().parse().ok())
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn host_of(request: &HttpRequest) -> Option<String> {
    header(&request.headers, "host").map(|s| s.to_string())
}

fn trim_crlf(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r') {
        end -= 1;
    }
    &line[..end]
}

fn parse_hex(bytes: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    if text.is_empty() {
        return None;
    }
    usize::from_str_radix(text, 16).ok()
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

// --- HAR 1.2 serialization -----------------------------------------------

/// Write the buffered transactions as a HAR 1.2 document to `writer`.
pub fn write_har<W: Write>(mut writer: W, entries: &[HttpTransaction]) -> io::Result<()> {
    let har = Har {
        log: Log {
            version: "1.2",
            creator: Creator { name: "Adwarden", version: env!("CARGO_PKG_VERSION") },
            entries: entries.iter().map(har_entry).collect(),
        },
    };
    serde_json::to_writer(&mut writer, &har).map_err(io::Error::from)?;
    writer.flush()
}

#[derive(Serialize)]
struct Har {
    log: Log,
}

#[derive(Serialize)]
struct Log {
    version: &'static str,
    creator: Creator,
    entries: Vec<Entry>,
}

#[derive(Serialize)]
struct Creator {
    name: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    started_date_time: String,
    time: i64,
    request: ReqJson,
    response: RespJson,
    cache: Empty,
    timings: Timings,
}

#[derive(Serialize)]
struct Empty {}

#[derive(Serialize)]
struct Timings {
    send: i64,
    wait: i64,
    receive: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReqJson {
    method: String,
    url: String,
    http_version: String,
    cookies: Vec<Empty>,
    headers: Vec<NameValue>,
    query_string: Vec<NameValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    post_data: Option<PostData>,
    headers_size: i64,
    body_size: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RespJson {
    status: u16,
    status_text: String,
    http_version: String,
    cookies: Vec<Empty>,
    headers: Vec<NameValue>,
    content: Content,
    #[serde(rename = "redirectURL")]
    redirect_url: String,
    headers_size: i64,
    body_size: i64,
}

#[derive(Serialize)]
struct NameValue {
    name: String,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PostData {
    mime_type: String,
    text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Content {
    size: i64,
    mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<&'static str>,
}

fn har_entry(txn: &HttpTransaction) -> Entry {
    Entry {
        started_date_time: iso8601(txn.started_unix_ms),
        time: txn.duration_ms as i64,
        request: req_json(txn),
        response: resp_json(txn),
        cache: Empty {},
        timings: Timings { send: 0, wait: txn.duration_ms as i64, receive: 0 },
    }
}

fn req_json(txn: &HttpTransaction) -> ReqJson {
    let req = &txn.request;
    let query = query_params(&req.target);
    let authority = txn.host.clone().unwrap_or_else(|| "unknown".to_string());
    let url = format!("https://{authority}{}", req.target);
    let post_data = if req.body_size > 0 || !req.body.is_empty() {
        let (text, encoding) = body_text(&req.body);
        Some(PostData {
            mime_type: content_type(&req.headers),
            text,
            encoding,
            comment: truncated_comment(req.body_truncated),
        })
    } else {
        None
    };
    ReqJson {
        method: req.method.clone(),
        url,
        http_version: req.http_version.clone(),
        cookies: Vec::new(),
        headers: name_values(&req.headers),
        query_string: query,
        post_data,
        headers_size: req.headers_size,
        body_size: req.body_size,
    }
}

fn resp_json(txn: &HttpTransaction) -> RespJson {
    let resp = &txn.response;
    let content = if resp.body.is_empty() && resp.body_size == 0 {
        Content {
            size: 0,
            mime_type: content_type(&resp.headers),
            text: None,
            encoding: None,
            comment: None,
        }
    } else {
        let (text, encoding) = body_text(&resp.body);
        Content {
            size: resp.body_size,
            mime_type: content_type(&resp.headers),
            text: Some(text),
            encoding,
            comment: truncated_comment(resp.body_truncated),
        }
    };
    RespJson {
        status: resp.status,
        status_text: resp.status_text.clone(),
        http_version: resp.http_version.clone(),
        cookies: Vec::new(),
        headers: name_values(&resp.headers),
        content,
        redirect_url: header(&resp.headers, "location").unwrap_or("").to_string(),
        headers_size: resp.headers_size,
        body_size: resp.body_size,
    }
}

fn name_values(headers: &[(String, String)]) -> Vec<NameValue> {
    headers.iter().map(|(k, v)| NameValue { name: k.clone(), value: v.clone() }).collect()
}

/// Extract the query parameters from an origin-form request target.
fn query_params(target: &str) -> Vec<NameValue> {
    let Some((_, q)) = target.split_once('?') else { return Vec::new() };
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((n, v)) => NameValue { name: n.to_string(), value: v.to_string() },
            None => NameValue { name: pair.to_string(), value: String::new() },
        })
        .collect()
}

fn content_type(headers: &[(String, String)]) -> String {
    header(headers, "content-type").unwrap_or("application/octet-stream").to_string()
}

/// Textualize a body: UTF-8 inline, else base64 with an `encoding` marker.
fn body_text(body: &[u8]) -> (String, Option<&'static str>) {
    match std::str::from_utf8(body) {
        Ok(s) => (s.to_string(), None),
        Err(_) => (base64_encode(body), Some("base64")),
    }
}

fn truncated_comment(truncated: bool) -> Option<&'static str> {
    truncated.then_some("body truncated by Adwarden capture cap")
}

/// Standard-alphabet base64 encoder (no line breaks). Mirrors the decoder in
/// `lib.rs`; kept dependency-free.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18 & 63) as usize] as char);
        out.push(ALPHABET[(n >> 12 & 63) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6 & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// Format unix millis as ISO 8601 UTC (`YYYY-MM-DDThh:mm:ss.sssZ`).
fn iso8601(unix_ms: u64) -> String {
    let secs = unix_ms / 1000;
    let millis = unix_ms % 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// Days since the unix epoch → (year, month, day). Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn feed_txn(tap: &mut HttpTap, req: &[u8], resp: &[u8]) {
        tap.feed_request(req);
        tap.feed_response(resp);
    }

    #[test]
    fn parses_simple_get_and_response() {
        let mut tap = HttpTap::new();
        tap.set_host("example.com");
        feed_txn(
            &mut tap,
            b"GET /index.html?a=1&b=2 HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
        );
        let txns = tap.take_transactions();
        assert_eq!(txns.len(), 1);
        let t = &txns[0];
        assert_eq!(t.request.method, "GET");
        assert_eq!(t.request.target, "/index.html?a=1&b=2");
        assert_eq!(t.response.status, 200);
        assert_eq!(t.response.body, b"hello");
        assert_eq!(t.response.body_size, 5);
        assert_eq!(t.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn parses_request_body_and_chunked_response() {
        let mut tap = HttpTap::new();
        feed_txn(
            &mut tap,
            b"POST /submit HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\n\r\nbody",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        );
        let txns = tap.take_transactions();
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].request.body, b"body");
        assert_eq!(txns[0].response.body, b"hello world");
        assert_eq!(txns[0].response.body_size, 11);
    }

    #[test]
    fn pairs_two_keepalive_transactions_in_order() {
        let mut tap = HttpTap::new();
        tap.set_host("h");
        tap.feed_request(b"GET /one HTTP/1.1\r\nHost: h\r\n\r\nGET /two HTTP/1.1\r\nHost: h\r\n\r\n");
        tap.feed_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA\
              HTTP/1.1 404 Not Found\r\nContent-Length: 1\r\n\r\nB",
        );
        let txns = tap.take_transactions();
        assert_eq!(txns.len(), 2);
        assert_eq!(txns[0].request.target, "/one");
        assert_eq!(txns[0].response.status, 200);
        assert_eq!(txns[0].response.body, b"A");
        assert_eq!(txns[1].request.target, "/two");
        assert_eq!(txns[1].response.status, 404);
        assert_eq!(txns[1].response.body, b"B");
    }

    #[test]
    fn head_response_has_no_body_and_next_txn_parses() {
        let mut tap = HttpTap::new();
        // A HEAD advertises Content-Length but sends no body; a following GET on
        // the same connection must still parse (proves we didn't eat its bytes).
        tap.feed_request(b"HEAD /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n");
        tap.feed_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n\
              HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        );
        let txns = tap.take_transactions();
        assert_eq!(txns.len(), 2);
        assert_eq!(txns[0].request.method, "HEAD");
        assert!(txns[0].response.body.is_empty());
        assert_eq!(txns[1].request.target, "/b");
        assert_eq!(txns[1].response.body, b"hi");
    }

    #[test]
    fn response_without_length_completes_on_close() {
        let mut tap = HttpTap::new();
        tap.feed_request(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        tap.feed_response(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nstreamed body");
        assert!(tap.take_transactions().is_empty(), "not complete until EOF");
        tap.finish();
        let txns = tap.take_transactions();
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].response.body, b"streamed body");
    }

    #[test]
    fn informational_100_continue_is_skipped() {
        let mut tap = HttpTap::new();
        tap.feed_request(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 2\r\n\r\nhi");
        tap.feed_response(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok");
        let txns = tap.take_transactions();
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].response.status, 201);
        assert_eq!(txns[0].response.body, b"ok");
    }

    #[test]
    fn non_http_traffic_disables_the_tap() {
        let mut tap = HttpTap::new();
        // An h2 connection preface / raw binary: not HTTP/1.1.
        tap.feed_request(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00");
        tap.feed_response(&[0x17, 0x03, 0x03, 0xde, 0xad, 0xbe, 0xef]);
        assert!(tap.take_transactions().is_empty());
        // Further feeds are inert (no panic, still nothing emitted).
        tap.feed_request(b"GET / HTTP/1.1\r\n\r\n");
        assert!(tap.take_transactions().is_empty());
    }

    #[test]
    fn writes_valid_har_json() {
        let mut tap = HttpTap::new();
        tap.set_host("example.com");
        feed_txn(
            &mut tap,
            b"GET /p?x=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nhi",
        );
        let txns = tap.take_transactions();
        let mut buf = Vec::new();
        write_har(&mut buf, &txns).unwrap();
        let v: Value = serde_json::from_slice(&buf).unwrap();

        assert_eq!(v["log"]["version"], "1.2");
        assert_eq!(v["log"]["creator"]["name"], "Adwarden");
        let entry = &v["log"]["entries"][0];
        assert_eq!(entry["request"]["method"], "GET");
        assert_eq!(entry["request"]["url"], "https://example.com/p?x=1");
        assert_eq!(entry["request"]["queryString"][0]["name"], "x");
        assert_eq!(entry["request"]["queryString"][0]["value"], "1");
        assert_eq!(entry["response"]["status"], 200);
        assert_eq!(entry["response"]["content"]["text"], "hi");
        assert_eq!(entry["response"]["content"]["mimeType"], "text/plain");
        // startedDateTime is ISO-8601 Zulu.
        let started = entry["startedDateTime"].as_str().unwrap();
        assert!(started.ends_with('Z') && started.contains('T'), "got {started}");
    }

    #[test]
    fn iso8601_matches_known_epoch() {
        // 2021-01-01T00:00:00.000Z == 1609459200000 ms.
        assert_eq!(iso8601(1_609_459_200_000), "2021-01-01T00:00:00.000Z");
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn base64_encodes_binary_body() {
        let mut tap = HttpTap::new();
        tap.feed_request(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        tap.feed_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n\xff\xfe\xfd");
        let txns = tap.take_transactions();
        let mut buf = Vec::new();
        write_har(&mut buf, &txns).unwrap();
        let v: Value = serde_json::from_slice(&buf).unwrap();
        let content = &v["log"]["entries"][0]["response"]["content"];
        assert_eq!(content["encoding"], "base64");
        assert_eq!(content["text"], base64_encode(&[0xff, 0xfe, 0xfd]));
    }
}
