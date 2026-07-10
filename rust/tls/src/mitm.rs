// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! The TLS man-in-the-middle splice for a single intercepted flow.
//!
//! A [`TlsMitm`] terminates the app's TLS with a leaf minted for the SNI it
//! offers (rustls *server* side), re-originates a fresh TLS connection to the
//! real upstream (rustls *client* side), and shuttles the decrypted plaintext
//! between the two. The datapath — and pcap/HAR taps downstream — therefore see
//! cleartext for decryptable flows.
//!
//! It is purely a byte pump: the caller owns the sockets. Each service pass the
//! caller feeds whatever TLS bytes arrived from each side ([`recv_from_app`] /
//! [`recv_from_upstream`]), calls [`pump`], and writes the returned TLS bytes
//! back toward each peer. The upstream client session is created lazily, the
//! moment the ClientHello reveals the SNI, so both handshakes then proceed in
//! parallel; app plaintext that arrives before the upstream handshake finishes
//! is buffered by rustls and flushed automatically.
//!
//! [`recv_from_app`]: TlsMitm::recv_from_app
//! [`recv_from_upstream`]: TlsMitm::recv_from_upstream
//! [`pump`]: TlsMitm::pump

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

use crate::dns::{DnsKind, DnsStream};
use crate::har::{HttpTap, HttpTransaction};
use crate::rewriter::HttpRewriter;

/// How a splice's decrypted plaintext is handled.
enum Plaintext {
    /// Normal HTTPS: HAR tap + cosmetic rewriter over the byte stream.
    Http { tap: HttpTap, rewriter: HttpRewriter },
    /// Encrypted DNS (DoT/DoH): filter the DNS messages against the blocklist.
    Dns(DnsStream),
}

/// One pump's worth of output: TLS bytes to write toward each peer, plus a
/// flag telling the caller to tear the flow down.
#[derive(Default)]
pub struct MitmIo {
    /// Encrypted bytes to send to the app (over the smoltcp socket).
    pub to_app: Vec<u8>,
    /// Encrypted bytes to send to the upstream server (over the OS socket).
    pub to_upstream: Vec<u8>,
    /// The splice has finished (both sides closed) or failed; drop the flow.
    pub closed: bool,
}

/// Which side of the splice a failure came from — so we only attribute an
/// aborted *app* handshake to leaf rejection, not an upstream/config problem.
enum FailSide {
    App,
    Upstream,
    Other,
}

/// A live TLS interception splice for one TCP flow.
pub struct TlsMitm {
    /// Toward the app: presents a minted leaf via the config's cert resolver.
    server: ServerConnection,
    /// Toward the upstream: created once the SNI is known.
    client: Option<ClientConnection>,
    client_config: Arc<ClientConfig>,
    host: Option<String>,
    app_closed: bool,
    upstream_closed: bool,
    failed: bool,
    /// Set when the splice failed because the app aborted mid-handshake — i.e. it
    /// refused our minted leaf (cert pinning / user-CA distrust). Drives the
    /// datapath's metadata-only fallback (P2-4).
    cert_rejected: bool,
    /// How the decrypted plaintext is handled: the HTTP tap/rewriter (HAR +
    /// cosmetics, P2/P4) or an encrypted-DNS filter (DoT/DoH).
    plaintext: Plaintext,
}

impl TlsMitm {
    /// Create a splice. `server_config` mints leaves per SNI (see
    /// [`crate::CertAuthority::server_config`]); `client_config` verifies the
    /// real upstream (see [`crate::upstream_client_config`]).
    pub fn new(
        server_config: Arc<ServerConfig>,
        client_config: Arc<ClientConfig>,
    ) -> Result<Self, rustls::Error> {
        Self::with_plaintext(
            server_config,
            client_config,
            Plaintext::Http { tap: HttpTap::new(), rewriter: HttpRewriter::new() },
        )
    }

    /// Create a splice that filters encrypted DNS (DoT/DoH) over the plaintext
    /// instead of running the HTTP tap/rewriter.
    pub fn new_dns(
        server_config: Arc<ServerConfig>,
        client_config: Arc<ClientConfig>,
        kind: DnsKind,
    ) -> Result<Self, rustls::Error> {
        Self::with_plaintext(server_config, client_config, Plaintext::Dns(DnsStream::new(kind)))
    }

    fn with_plaintext(
        server_config: Arc<ServerConfig>,
        client_config: Arc<ClientConfig>,
        plaintext: Plaintext,
    ) -> Result<Self, rustls::Error> {
        Ok(TlsMitm {
            server: ServerConnection::new(server_config)?,
            client: None,
            client_config,
            host: None,
            app_closed: false,
            upstream_closed: false,
            failed: false,
            cert_rejected: false,
            plaintext,
        })
    }

    /// Whether this splice filters encrypted DNS (vs. running the HTTP path).
    pub fn is_dns(&self) -> bool {
        matches!(self.plaintext, Plaintext::Dns(_))
    }

    /// Drain the DNS names sinkholed since the last call (encrypted-DNS mode).
    pub fn take_dns_blocked(&mut self) -> Vec<String> {
        match &mut self.plaintext {
            Plaintext::Dns(dns) => dns.take_blocked(),
            Plaintext::Http { .. } => Vec::new(),
        }
    }

    /// Provision the cosmetic-filtering payload for this flow (P4-2). The datapath
    /// computes it from the filter engine once [`host`](Self::host) is known and
    /// hands it in; empty strings mean "off" (pure identity passthrough).
    pub fn set_cosmetic(&mut self, css: String, js: String) {
        if let Plaintext::Http { rewriter, .. } = &mut self.plaintext {
            rewriter.set_cosmetic(css, js);
        }
    }

    /// The intercepted SNI host, once the ClientHello has been parsed.
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// True once the splice closed because the app rejected our minted leaf
    /// during the handshake (cert pinning / user-CA distrust). Only meaningful
    /// after [`pump`](Self::pump) has reported the flow closed; the datapath then
    /// relays this app's future flows raw and reports them as metadata-only.
    pub fn cert_rejected(&self) -> bool {
        self.cert_rejected
    }

    /// Drain the HTTP transactions decrypted so far (for HAR export, P2-3).
    pub fn take_transactions(&mut self) -> Vec<HttpTransaction> {
        match &mut self.plaintext {
            Plaintext::Http { tap, .. } => tap.take_transactions(),
            Plaintext::Dns(_) => Vec::new(),
        }
    }

    /// Feed TLS bytes just received from the app (smoltcp side).
    pub fn recv_from_app(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            match self.server.read_tls(&mut data) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => {
                    self.mark_failed(FailSide::App);
                    break;
                }
            }
        }
    }

    /// Feed TLS bytes just received from the upstream socket.
    pub fn recv_from_upstream(&mut self, mut data: &[u8]) {
        let Some(client) = self.client.as_mut() else { return };
        while !data.is_empty() {
            match client.read_tls(&mut data) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => {
                    self.mark_failed(FailSide::Upstream);
                    break;
                }
            }
        }
    }

    /// Advance both sessions, cross any ready plaintext, and collect the TLS
    /// bytes to send toward each peer. For the HTTP path (HAR/cosmetics).
    pub fn pump(&mut self) -> MitmIo {
        self.pump_impl(None)
    }

    /// Like [`pump`](Self::pump), but for the encrypted-DNS path: `is_blocked`
    /// decides each query, sinkholed answers go straight back to the app, and
    /// allowed queries are forwarded to the real resolver.
    pub fn pump_dns(&mut self, is_blocked: &mut dyn FnMut(&str) -> bool) -> MitmIo {
        self.pump_impl(Some(is_blocked))
    }

    fn pump_impl(&mut self, dns_filter: Option<&mut dyn FnMut(&str) -> bool>) -> MitmIo {
        let mut io = MitmIo::default();
        if self.failed {
            io.closed = true;
            return io;
        }

        // App side: decrypt, and on the first packets learn the SNI so we can
        // stand up the upstream session.
        match self.server.process_new_packets() {
            Ok(state) => {
                if state.peer_has_closed() {
                    self.app_closed = true;
                }
            }
            Err(_) => return self.fail(FailSide::App),
        }
        if self.client.is_none() {
            if let Some(name) = self.server.server_name() {
                self.host = Some(name.to_string());
                if let Plaintext::Http { tap, .. } = &mut self.plaintext {
                    tap.set_host(name);
                }
                let Ok(sni) = ServerName::try_from(name.to_string()) else {
                    return self.fail(FailSide::Other);
                };
                match ClientConnection::new(self.client_config.clone(), sni) {
                    Ok(c) => self.client = Some(c),
                    Err(_) => return self.fail(FailSide::Other),
                }
            }
        }

        // Upstream side: decrypt.
        if let Some(client) = self.client.as_mut() {
            match client.process_new_packets() {
                Ok(state) => {
                    if state.peer_has_closed() {
                        self.upstream_closed = true;
                    }
                }
                Err(_) => return self.fail(FailSide::Upstream),
            }
        }

        self.cross_plaintext(dns_filter);

        // Propagate clean closes across the splice.
        if self.app_closed {
            if let Some(client) = self.client.as_mut() {
                client.send_close_notify();
            }
        }
        if self.upstream_closed {
            self.server.send_close_notify();
        }

        // Collect outbound TLS for both peers.
        while self.server.wants_write() {
            if self.server.write_tls(&mut io.to_app).is_err() {
                return self.fail(FailSide::Other);
            }
        }
        if let Some(client) = self.client.as_mut() {
            while client.wants_write() {
                if client.write_tls(&mut io.to_upstream).is_err() {
                    return self.fail(FailSide::Other);
                }
            }
        }

        io.closed = self.failed || (self.app_closed && self.upstream_closed);
        if io.closed {
            // Flush a response whose body was delimited by connection close.
            self.finish();
        }
        io
    }

    /// Finalize HTTP capture when the flow is torn down out-of-band (e.g. the app
    /// resets before a clean close). Idempotent; safe to call before draining.
    pub fn finish(&mut self) {
        if let Plaintext::Http { tap, .. } = &mut self.plaintext {
            tap.finish();
        }
    }

    /// Move decrypted bytes app->upstream and upstream->app. rustls buffers on
    /// the far `writer()` until that side's handshake permits sending.
    fn cross_plaintext(&mut self, dns_filter: Option<&mut dyn FnMut(&str) -> bool>) {
        let Some(client) = self.client.as_mut() else { return };
        let mut buf = [0u8; 16 * 1024];
        match &mut self.plaintext {
            Plaintext::Http { tap, rewriter } => {
                // app -> upstream (the HTTP request stream). The tap always sees
                // the raw bytes (HAR reflects true traffic); the rewriter's output
                // is what we forward — identical unless cosmetics are on.
                loop {
                    match self.server.reader().read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            tap.feed_request(&buf[..n]);
                            let out = rewriter.feed_request(&buf[..n]);
                            let _ = client.writer().write_all(&out);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
                // upstream -> app (the HTTP response stream).
                loop {
                    match client.reader().read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            tap.feed_response(&buf[..n]);
                            let out = rewriter.feed_response(&buf[..n]);
                            let _ = self.server.writer().write_all(&out);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }
            Plaintext::Dns(dns) => {
                // Without a block decision (shouldn't happen — the datapath always
                // calls `pump_dns` for DNS flows) fall back to forwarding so the
                // connection can't deadlock.
                let mut allow_all = |_: &str| false;
                let is_blocked: &mut dyn FnMut(&str) -> bool = match dns_filter {
                    Some(f) => f,
                    None => &mut allow_all,
                };
                // app -> resolver: sinkhole blocked queries straight back to the
                // app, forward the rest to the real resolver.
                loop {
                    match self.server.reader().read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let cross = dns.on_app_data(&buf[..n], is_blocked);
                            if !cross.to_upstream.is_empty() {
                                let _ = client.writer().write_all(&cross.to_upstream);
                            }
                            if !cross.to_app.is_empty() {
                                let _ = self.server.writer().write_all(&cross.to_app);
                            }
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
                // resolver -> app: relay responses verbatim.
                loop {
                    match client.reader().read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let out = dns.on_upstream_data(&buf[..n]);
                            let _ = self.server.writer().write_all(&out);
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(_) => break,
                    }
                }
            }
        }
    }

    /// Latch the first failure, attributing it. An app abort while our server
    /// session is still handshaking means the app refused our leaf (pinning).
    fn mark_failed(&mut self, side: FailSide) {
        if !self.failed {
            self.failed = true;
            self.cert_rejected = matches!(side, FailSide::App) && self.server.is_handshaking();
        }
    }

    fn fail(&mut self, side: FailSide) -> MitmIo {
        self.mark_failed(side);
        MitmIo { closed: true, ..Default::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CertAuthority;
    use rustls::pki_types::CertificateDer;
    use rustls::{ClientConnection, RootCertStore, ServerConnection};

    const HOST: &str = "example.com";

    fn client_trusting(ca: &CertAuthority) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(ca.ca_cert_der().to_vec()))
            .unwrap();
        Arc::new(
            ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    /// Drive app <-> mitm <-> upstream one full round: pull pending TLS off each
    /// real endpoint, feed it to the mitm, pump, and deliver the mitm's output.
    fn step(
        app: &mut ClientConnection,
        upstream: &mut ServerConnection,
        mitm: &mut TlsMitm,
    ) -> MitmIo {
        let mut a2m = Vec::new();
        while app.wants_write() {
            app.write_tls(&mut a2m).unwrap();
        }
        mitm.recv_from_app(&a2m);

        let mut u2m = Vec::new();
        while upstream.wants_write() {
            upstream.write_tls(&mut u2m).unwrap();
        }
        mitm.recv_from_upstream(&u2m);

        let io = mitm.pump();

        let mut cur = &io.to_app[..];
        while !cur.is_empty() && app.read_tls(&mut cur).unwrap() > 0 {}
        app.process_new_packets().unwrap();

        let mut cur = &io.to_upstream[..];
        while !cur.is_empty() && upstream.read_tls(&mut cur).unwrap() > 0 {}
        upstream.process_new_packets().unwrap();
        io
    }

    #[test]
    fn splices_and_passes_plaintext_both_ways() {
        // Our interception CA (the app trusts it) and a separate "real upstream"
        // CA (the mitm's client trusts it), each minting a leaf for HOST.
        let our_ca = Arc::new(CertAuthority::generate().unwrap());
        let upstream_ca = Arc::new(CertAuthority::generate().unwrap());

        let mut mitm =
            TlsMitm::new(our_ca.server_config().unwrap(), client_trusting(&upstream_ca)).unwrap();
        let mut app = ClientConnection::new(
            client_trusting(&our_ca),
            ServerName::try_from(HOST).unwrap(),
        )
        .unwrap();
        let mut upstream = ServerConnection::new(upstream_ca.server_config().unwrap()).unwrap();

        // Converge both handshakes.
        let mut done = false;
        for _ in 0..30 {
            step(&mut app, &mut upstream, &mut mitm);
            if !app.is_handshaking() && !upstream.is_handshaking() {
                done = true;
                break;
            }
        }
        assert!(done, "handshakes did not converge");
        assert_eq!(mitm.host(), Some(HOST), "mitm learned the SNI");

        // App -> upstream plaintext.
        app.writer().write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        for _ in 0..5 {
            step(&mut app, &mut upstream, &mut mitm);
        }
        let mut got = Vec::new();
        let _ = upstream.reader().read_to_end(&mut got);
        assert!(
            got.windows(4).any(|w| w == b"GET "),
            "upstream should receive the app's cleartext request, got {got:?}"
        );

        // Upstream -> app plaintext.
        upstream.writer().write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi").unwrap();
        for _ in 0..5 {
            step(&mut app, &mut upstream, &mut mitm);
        }
        let mut resp = Vec::new();
        let _ = app.reader().read_to_end(&mut resp);
        assert!(
            resp.windows(8).any(|w| w == b"HTTP/1.1"),
            "app should receive the upstream's cleartext response, got {resp:?}"
        );

        // The HAR tap should have decrypted and paired the transaction.
        let txns = mitm.take_transactions();
        assert_eq!(txns.len(), 1, "one request/response captured");
        assert_eq!(txns[0].request.method, "GET");
        assert_eq!(txns[0].response.status, 200);
        assert_eq!(txns[0].response.body, b"hi");
        assert_eq!(txns[0].host.as_deref(), Some(HOST));
    }

    #[test]
    fn injects_cosmetics_while_har_sees_the_original() {
        // The app receives the rewritten (injected) HTML, but the HAR tap still
        // captures the original upstream body — the P4-2 coexistence contract.
        let our_ca = Arc::new(CertAuthority::generate().unwrap());
        let upstream_ca = Arc::new(CertAuthority::generate().unwrap());

        let mut mitm =
            TlsMitm::new(our_ca.server_config().unwrap(), client_trusting(&upstream_ca)).unwrap();
        let mut app = ClientConnection::new(
            client_trusting(&our_ca),
            ServerName::try_from(HOST).unwrap(),
        )
        .unwrap();
        let mut upstream = ServerConnection::new(upstream_ca.server_config().unwrap()).unwrap();

        for _ in 0..30 {
            step(&mut app, &mut upstream, &mut mitm);
            if !app.is_handshaking() && !upstream.is_handshaking() {
                break;
            }
        }
        assert_eq!(mitm.host(), Some(HOST));
        // Provision cosmetics once the host is known (as the datapath does).
        mitm.set_cosmetic(".ad{display:none!important;}".to_string(), String::new());

        app.writer().write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        let body = "<html><head></head><body>hi</body></html>";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        for _ in 0..6 {
            step(&mut app, &mut upstream, &mut mitm);
        }
        upstream.writer().write_all(resp.as_bytes()).unwrap();
        for _ in 0..6 {
            step(&mut app, &mut upstream, &mut mitm);
        }

        let mut got = Vec::new();
        let _ = app.reader().read_to_end(&mut got);
        let got = String::from_utf8_lossy(&got);
        assert!(got.contains("<head><!--adw-cosmetic-->"), "app got injected HTML: {got}");
        assert!(got.contains(".ad{display:none!important;}"), "css delivered: {got}");

        let txns = mitm.take_transactions();
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].response.body, body.as_bytes(), "HAR keeps the original body");
    }

    #[test]
    fn detects_cert_rejection_when_app_distrusts_our_leaf() {
        // The app trusts only `other_ca`, not our interception CA, so it aborts
        // the handshake on our minted leaf — exactly what a pinned app does.
        let our_ca = Arc::new(CertAuthority::generate().unwrap());
        let upstream_ca = Arc::new(CertAuthority::generate().unwrap());
        let other_ca = CertAuthority::generate().unwrap();

        let mut mitm =
            TlsMitm::new(our_ca.server_config().unwrap(), client_trusting(&upstream_ca)).unwrap();
        let mut app = ClientConnection::new(
            client_trusting(&other_ca),
            ServerName::try_from(HOST).unwrap(),
        )
        .unwrap();

        let mut closed = false;
        for _ in 0..20 {
            let mut a2m = Vec::new();
            while app.wants_write() {
                app.write_tls(&mut a2m).unwrap();
            }
            mitm.recv_from_app(&a2m);
            let io = mitm.pump();
            let mut cur = &io.to_app[..];
            while !cur.is_empty() && app.read_tls(&mut cur).unwrap() > 0 {}
            // The app rejects our leaf here and queues a fatal alert (flushed to
            // the mitm on the next pass); tolerate the error rather than unwrap.
            let _ = app.process_new_packets();
            if io.closed {
                closed = true;
                break;
            }
        }
        assert!(closed, "the splice should have torn down after the app's rejection");
        assert!(mitm.cert_rejected(), "leaf rejection should be flagged as a cert-pin");
        assert_eq!(mitm.host(), Some(HOST), "SNI learned before the rejection");
    }

    /// Length-prefixed (DoT framing) type-A query for `name`, id 0x1234.
    fn framed_query(name: &str) -> Vec<u8> {
        let mut msg = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&1u16.to_be_bytes()); // A
        msg.extend_from_slice(&1u16.to_be_bytes()); // IN
        let mut framed = (msg.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&msg);
        framed
    }

    /// One DoT round, driving the splice with `pump_dns`.
    fn dns_step(
        app: &mut ClientConnection,
        upstream: &mut ServerConnection,
        mitm: &mut TlsMitm,
        is_blocked: &mut dyn FnMut(&str) -> bool,
    ) -> MitmIo {
        let mut a2m = Vec::new();
        while app.wants_write() {
            app.write_tls(&mut a2m).unwrap();
        }
        mitm.recv_from_app(&a2m);

        let mut u2m = Vec::new();
        while upstream.wants_write() {
            upstream.write_tls(&mut u2m).unwrap();
        }
        mitm.recv_from_upstream(&u2m);

        let io = mitm.pump_dns(is_blocked);

        let mut cur = &io.to_app[..];
        while !cur.is_empty() && app.read_tls(&mut cur).unwrap() > 0 {}
        app.process_new_packets().unwrap();

        let mut cur = &io.to_upstream[..];
        while !cur.is_empty() && upstream.read_tls(&mut cur).unwrap() > 0 {}
        upstream.process_new_packets().unwrap();
        io
    }

    /// Drain whatever plaintext is currently readable from a rustls endpoint.
    fn drain(reader: &mut dyn Read) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(_) => break, // WouldBlock: nothing more decrypted yet
            }
        }
        out
    }

    #[test]
    fn dot_sinkholes_blocked_and_forwards_allowed() {
        // Full DoT splice: our CA (app trusts it) + a separate upstream CA (the
        // mitm's client trusts it), each minting a leaf for the resolver host.
        let our_ca = Arc::new(CertAuthority::generate().unwrap());
        let upstream_ca = Arc::new(CertAuthority::generate().unwrap());
        let mut mitm = TlsMitm::new_dns(
            our_ca.server_config().unwrap(),
            client_trusting(&upstream_ca),
            DnsKind::Dot,
        )
        .unwrap();
        let host = "dns.resolver.example";
        let mut app = ClientConnection::new(
            client_trusting(&our_ca),
            ServerName::try_from(host).unwrap(),
        )
        .unwrap();
        let mut upstream = ServerConnection::new(upstream_ca.server_config().unwrap()).unwrap();
        let mut is_blocked = |name: &str| name == "ads.example.com";

        for _ in 0..30 {
            dns_step(&mut app, &mut upstream, &mut mitm, &mut is_blocked);
            if !app.is_handshaking() && !upstream.is_handshaking() {
                break;
            }
        }
        assert_eq!(mitm.host(), Some(host), "mitm learned the DoT SNI");

        // Blocked query: sinkholed straight back to the app as NXDOMAIN; the
        // resolver never sees it.
        app.writer().write_all(&framed_query("ads.example.com")).unwrap();
        for _ in 0..5 {
            dns_step(&mut app, &mut upstream, &mut mitm, &mut is_blocked);
        }
        assert!(drain(&mut upstream.reader()).is_empty(), "resolver must not see a blocked query");
        let reply = drain(&mut app.reader());
        assert!(reply.len() > 2, "app receives a synthesized answer");
        let len = ((reply[0] as usize) << 8) | reply[1] as usize;
        let ans = &reply[2..2 + len];
        assert_eq!(&ans[0..2], &[0x12, 0x34], "query id echoed");
        assert_eq!(ans[3] & 0x0F, 3, "NXDOMAIN rcode");

        // Allowed query: forwarded to the resolver; its response reaches the app.
        app.writer().write_all(&framed_query("good.example.com")).unwrap();
        for _ in 0..5 {
            dns_step(&mut app, &mut upstream, &mut mitm, &mut is_blocked);
        }
        let forwarded = drain(&mut upstream.reader());
        assert!(!forwarded.is_empty(), "allowed query reaches the resolver");

        upstream.writer().write_all(b"\x00\x04test").unwrap(); // arbitrary framed reply
        for _ in 0..5 {
            dns_step(&mut app, &mut upstream, &mut mitm, &mut is_blocked);
        }
        assert_eq!(drain(&mut app.reader()), b"\x00\x04test", "resolver reply relayed to app");
    }
}
