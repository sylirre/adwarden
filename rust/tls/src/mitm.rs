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
}

impl TlsMitm {
    /// Create a splice. `server_config` mints leaves per SNI (see
    /// [`crate::CertAuthority::server_config`]); `client_config` verifies the
    /// real upstream (see [`crate::upstream_client_config`]).
    pub fn new(
        server_config: Arc<ServerConfig>,
        client_config: Arc<ClientConfig>,
    ) -> Result<Self, rustls::Error> {
        Ok(TlsMitm {
            server: ServerConnection::new(server_config)?,
            client: None,
            client_config,
            host: None,
            app_closed: false,
            upstream_closed: false,
            failed: false,
        })
    }

    /// The intercepted SNI host, once the ClientHello has been parsed.
    pub fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    /// Feed TLS bytes just received from the app (smoltcp side).
    pub fn recv_from_app(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            match self.server.read_tls(&mut data) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => {
                    self.failed = true;
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
                    self.failed = true;
                    break;
                }
            }
        }
    }

    /// Advance both sessions, cross any ready plaintext, and collect the TLS
    /// bytes to send toward each peer.
    pub fn pump(&mut self) -> MitmIo {
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
            Err(_) => return self.fail(),
        }
        if self.client.is_none() {
            if let Some(name) = self.server.server_name() {
                self.host = Some(name.to_string());
                let Ok(sni) = ServerName::try_from(name.to_string()) else {
                    return self.fail();
                };
                match ClientConnection::new(self.client_config.clone(), sni) {
                    Ok(c) => self.client = Some(c),
                    Err(_) => return self.fail(),
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
                Err(_) => return self.fail(),
            }
        }

        self.cross_plaintext();

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
                return self.fail();
            }
        }
        if let Some(client) = self.client.as_mut() {
            while client.wants_write() {
                if client.write_tls(&mut io.to_upstream).is_err() {
                    return self.fail();
                }
            }
        }

        io.closed = self.failed || (self.app_closed && self.upstream_closed);
        io
    }

    /// Move decrypted bytes app->upstream and upstream->app. rustls buffers on
    /// the far `writer()` until that side's handshake permits sending.
    fn cross_plaintext(&mut self) {
        let Some(client) = self.client.as_mut() else { return };
        let mut buf = [0u8; 16 * 1024];
        // app -> upstream
        loop {
            match self.server.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let _ = client.writer().write_all(&buf[..n]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        // upstream -> app
        loop {
            match client.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let _ = self.server.writer().write_all(&buf[..n]);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    fn fail(&mut self) -> MitmIo {
        self.failed = true;
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
    }
}
