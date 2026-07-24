//! Absolute-URI request forwarding for plaintext HTTP (:80) through an HTTP/HTTPS
//! proxy (P5). A standard forward proxy expects HTTP requests in *absolute form*
//! (`GET http://host/path HTTP/1.1`) and refuses `CONNECT` to port 80; this
//! rewrites each request-line on the app->proxy byte stream from origin-form
//! (`GET /path HTTP/1.1`) to absolute-form, streaming request bodies through
//! unchanged. Responses (proxy->app) are relayed verbatim by the caller.
//!
//! Sans-I/O and byte-oriented so it is host-testable and works across arbitrary
//! TCP segmentation. Fail-closed: any parse anomaly (malformed request-line,
//! oversized head, or a chunked request body we don't frame) returns an error so
//! the caller drops the flow rather than forwarding something malformed.

/// Cap on a single request's header block; exceeding it fails the flow closed.
const MAX_HEAD: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum HttpForwardError {
    HeadTooLarge,
    BadRequestLine,
    /// A chunked request body — rare over plaintext HTTP; we don't frame it, so
    /// the flow fails closed rather than risk mis-splitting the stream.
    ChunkedBodyUnsupported,
}

enum State {
    /// Accumulating a request head until CRLFCRLF.
    Head,
    /// Streaming a request body through unchanged; `u64` bytes remain.
    Body(u64),
}

/// Streaming rewriter for one keep-alive HTTP/1.x connection's request direction.
pub struct HttpForward {
    /// Authority used to build the absolute URI when a request omits `Host`
    /// (HTTP/1.0); the origin the app dialed, e.g. `93.184.216.34` or `[::1]:8080`.
    fallback_authority: String,
    state: State,
    head: Vec<u8>,
}

impl HttpForward {
    pub fn new(fallback_authority: String) -> Self {
        HttpForward { fallback_authority, state: State::Head, head: Vec::new() }
    }

    /// Transform a chunk of app->proxy bytes, returning the bytes to send to the
    /// proxy (request-lines rewritten to absolute-form). Stateful across calls;
    /// buffers an incomplete head and emits nothing for it until it completes.
    pub fn push(&mut self, mut input: &[u8]) -> Result<Vec<u8>, HttpForwardError> {
        let mut out = Vec::with_capacity(input.len() + 32);
        while !input.is_empty() {
            match self.state {
                State::Head => {
                    let prev = self.head.len();
                    self.head.extend_from_slice(input);
                    match find_subsequence(&self.head, b"\r\n\r\n") {
                        Some(pos) => {
                            let head_end = pos + 4;
                            let body_len =
                                rewrite_head(&self.head[..head_end], &self.fallback_authority, &mut out)?;
                            // Bytes past the head belong to the body / next request.
                            let consumed = head_end.saturating_sub(prev).min(input.len());
                            input = &input[consumed..];
                            self.head.clear();
                            self.state = if body_len > 0 { State::Body(body_len) } else { State::Head };
                        }
                        None => {
                            if self.head.len() > MAX_HEAD {
                                return Err(HttpForwardError::HeadTooLarge);
                            }
                            input = &[];
                        }
                    }
                }
                State::Body(ref mut remaining) => {
                    let take = (*remaining).min(input.len() as u64) as usize;
                    out.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    *remaining -= take as u64;
                    if *remaining == 0 {
                        self.state = State::Head;
                    }
                }
            }
        }
        Ok(out)
    }
}

/// Rewrite one request head (bytes through the terminating CRLFCRLF): emit the
/// request-line in absolute form followed by the headers verbatim, and return the
/// request body length (0 = none). Errors fail the flow closed.
fn rewrite_head(head: &[u8], fallback: &str, out: &mut Vec<u8>) -> Result<u64, HttpForwardError> {
    // Split the request-line from the rest of the head (headers + blank line).
    let first_crlf = find_subsequence(head, b"\r\n").ok_or(HttpForwardError::BadRequestLine)?;
    let request_line = &head[..first_crlf];
    let rest = &head[first_crlf + 2..]; // headers + terminating CRLFCRLF, verbatim

    let (method, target, version) = parse_request_line(request_line)?;

    // Scan headers we care about (case-insensitive names).
    let mut host: Option<&str> = None;
    let mut content_length: u64 = 0;
    let mut chunked = false;
    for line in split_crlf(rest) {
        if line.is_empty() {
            break; // end of headers
        }
        let Some((name, value)) = split_header(line) else { continue };
        if name.eq_ignore_ascii_case("host") {
            host = Some(value);
        } else if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().unwrap_or(0);
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }
    if chunked {
        return Err(HttpForwardError::ChunkedBodyUnsupported);
    }

    // Rewrite only origin-form targets (`/path`); leave absolute-form / `*` /
    // authority-form (CONNECT) untouched so a proxy-aware client isn't mangled.
    if target.starts_with('/') {
        let authority = host.map(str::trim).filter(|h| !h.is_empty()).unwrap_or(fallback);
        out.extend_from_slice(method.as_bytes());
        out.extend_from_slice(b" http://");
        out.extend_from_slice(authority.as_bytes());
        out.extend_from_slice(target.as_bytes());
        out.push(b' ');
        out.extend_from_slice(version.as_bytes());
        out.extend_from_slice(b"\r\n");
    } else {
        out.extend_from_slice(request_line);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(rest);
    Ok(content_length)
}

fn parse_request_line(line: &[u8]) -> Result<(&str, &str, &str), HttpForwardError> {
    let text = std::str::from_utf8(line).map_err(|_| HttpForwardError::BadRequestLine)?;
    let mut parts = text.splitn(3, ' ');
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let version = parts.next().unwrap_or("");
    if method.is_empty() || target.is_empty() || !version.starts_with("HTTP/") {
        return Err(HttpForwardError::BadRequestLine);
    }
    Ok((method, target, version))
}

fn split_header(line: &[u8]) -> Option<(&str, &str)> {
    let text = std::str::from_utf8(line).ok()?;
    let (name, value) = text.split_once(':')?;
    Some((name.trim_end(), value.trim_start()))
}

/// Iterate CRLF-delimited lines (without the CRLF), stopping at the buffer end.
fn split_crlf(mut data: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        if data.is_empty() {
            return None;
        }
        match find_subsequence(data, b"\r\n") {
            Some(pos) => {
                let line = &data[..pos];
                data = &data[pos + 2..];
                Some(line)
            }
            None => {
                let line = data;
                data = &[];
                Some(line)
            }
        }
    })
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_str(f: &mut HttpForward, s: &[u8]) -> Vec<u8> {
        f.push(s).expect("rewrite ok")
    }

    #[test]
    fn rewrites_simple_get_to_absolute_form() {
        let mut f = HttpForward::new("1.2.3.4".into());
        let out = push_str(&mut f, b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n");
        assert_eq!(
            out,
            b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n".to_vec()
        );
    }

    #[test]
    fn falls_back_to_origin_authority_without_host() {
        let mut f = HttpForward::new("1.2.3.4".into());
        let out = push_str(&mut f, b"GET /a HTTP/1.0\r\n\r\n");
        assert_eq!(out, b"GET http://1.2.3.4/a HTTP/1.0\r\n\r\n".to_vec());
    }

    #[test]
    fn streams_post_body_and_next_request() {
        let mut f = HttpForward::new("h".into());
        // POST with a body, then a pipelined GET.
        let out = push_str(
            &mut f,
            b"POST /submit HTTP/1.1\r\nHost: api.test\r\nContent-Length: 5\r\n\r\nhelloGET /next HTTP/1.1\r\nHost: api.test\r\n\r\n",
        );
        assert_eq!(
            out,
            b"POST http://api.test/submit HTTP/1.1\r\nHost: api.test\r\nContent-Length: 5\r\n\r\nhelloGET http://api.test/next HTTP/1.1\r\nHost: api.test\r\n\r\n".to_vec()
        );
    }

    #[test]
    fn handles_head_split_across_pushes() {
        let mut f = HttpForward::new("h".into());
        let a = push_str(&mut f, b"GET /x HTTP/1.1\r\nHo");
        assert!(a.is_empty()); // head incomplete: nothing emitted yet
        let b = push_str(&mut f, b"st: split.test\r\n\r\n");
        assert_eq!(b, b"GET http://split.test/x HTTP/1.1\r\nHost: split.test\r\n\r\n".to_vec());
    }

    #[test]
    fn body_split_across_pushes() {
        let mut f = HttpForward::new("h".into());
        let a = push_str(&mut f, b"POST /p HTTP/1.1\r\nHost: b.test\r\nContent-Length: 4\r\n\r\nab");
        assert_eq!(a, b"POST http://b.test/p HTTP/1.1\r\nHost: b.test\r\nContent-Length: 4\r\n\r\nab".to_vec());
        let b = push_str(&mut f, b"cd");
        assert_eq!(b, b"cd".to_vec()); // remaining body streamed verbatim
    }

    #[test]
    fn leaves_absolute_form_untouched() {
        let mut f = HttpForward::new("h".into());
        let out = push_str(&mut f, b"GET http://already.abs/x HTTP/1.1\r\nHost: already.abs\r\n\r\n");
        assert_eq!(out, b"GET http://already.abs/x HTTP/1.1\r\nHost: already.abs\r\n\r\n".to_vec());
    }

    #[test]
    fn chunked_request_body_fails_closed() {
        let mut f = HttpForward::new("h".into());
        let err = f.push(b"POST /u HTTP/1.1\r\nHost: c.test\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(err, Err(HttpForwardError::ChunkedBodyUnsupported));
    }

    #[test]
    fn malformed_request_line_fails_closed() {
        let mut f = HttpForward::new("h".into());
        let err = f.push(b"NOT-HTTP garbage here\r\n\r\n");
        assert_eq!(err, Err(HttpForwardError::BadRequestLine));
    }

    #[test]
    fn oversize_head_fails_closed() {
        let mut f = HttpForward::new("h".into());
        let mut giant = b"GET / HTTP/1.1\r\nX: ".to_vec();
        giant.extend(std::iter::repeat(b'a').take(MAX_HEAD + 10));
        assert_eq!(f.push(&giant), Err(HttpForwardError::HeadTooLarge));
    }
}
