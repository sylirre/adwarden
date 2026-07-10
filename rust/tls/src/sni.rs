// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! Passive SNI extraction from a TLS ClientHello.
//!
//! Encrypted-DNS detection (P2) needs to know a 443 flow's SNI *before* deciding
//! whether to terminate it — so it can leave non-DoH traffic untouched. We can't
//! learn the SNI from rustls without first committing to the handshake, so this
//! parses the ClientHello bytes directly off the wire. It only reads; it never
//! validates or decrypts.

/// Result of peeking at a (possibly partial) ClientHello.
#[derive(Debug, PartialEq, Eq)]
pub enum SniPeek {
    /// Not enough bytes yet — call again once more have arrived.
    NeedMore,
    /// The ClientHello carried this SNI host name.
    Found(String),
    /// Parsed far enough to know there is no usable SNI (or it isn't a TLS
    /// ClientHello at all): decide without waiting for more bytes.
    None,
}

fn u16(b: &[u8], o: usize) -> Option<usize> {
    Some(((*b.get(o)? as usize) << 8) | *b.get(o + 1)? as usize)
}

/// Peek the SNI out of the leading TLS ClientHello in `buf`.
///
/// Handles a ClientHello contained in the first TLS record (the common case).
/// Returns [`SniPeek::NeedMore`] while the record is still arriving, or
/// [`SniPeek::None`] the moment we can tell there's nothing to wait for.
pub fn peek_sni(buf: &[u8]) -> SniPeek {
    // TLS record header: type(1) version(2) length(2).
    if buf.len() < 5 {
        return SniPeek::NeedMore;
    }
    if buf[0] != 0x16 {
        return SniPeek::None; // not a handshake record
    }
    let rec_len = match u16(buf, 3) {
        Some(n) => n,
        None => return SniPeek::NeedMore,
    };
    let rec_end = 5 + rec_len;
    if buf.len() < rec_end {
        return SniPeek::NeedMore; // ClientHello record still arriving
    }
    let hs = &buf[5..rec_end];
    parse_client_hello(hs)
}

/// Parse a handshake message body, expecting a ClientHello, and return its SNI.
fn parse_client_hello(hs: &[u8]) -> SniPeek {
    // Handshake header: msg_type(1) length(3).
    if hs.len() < 4 {
        return SniPeek::None;
    }
    if hs[0] != 0x01 {
        return SniPeek::None; // not a ClientHello
    }
    let mut pos = 4;
    // client_version(2) + random(32).
    pos += 2 + 32;
    // session_id: len(1) + bytes.
    let Some(sid_len) = hs.get(pos).copied() else { return SniPeek::None };
    pos += 1 + sid_len as usize;
    // cipher_suites: len(2) + bytes.
    let Some(cs_len) = u16(hs, pos) else { return SniPeek::None };
    pos += 2 + cs_len;
    // compression_methods: len(1) + bytes.
    let Some(cm_len) = hs.get(pos).copied() else { return SniPeek::None };
    pos += 1 + cm_len as usize;
    // extensions: len(2) + bytes.
    let Some(ext_total) = u16(hs, pos) else { return SniPeek::None };
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > hs.len() {
        return SniPeek::None;
    }
    while pos + 4 <= ext_end {
        let ext_type = u16(hs, pos).unwrap_or(usize::MAX);
        let ext_len = u16(hs, pos + 2).unwrap_or(0);
        let body = pos + 4;
        let body_end = body + ext_len;
        if body_end > ext_end {
            return SniPeek::None;
        }
        if ext_type == 0x0000 {
            return parse_server_name(&hs[body..body_end]);
        }
        pos = body_end;
    }
    SniPeek::None
}

/// Parse a `server_name` extension body and return the first host_name entry.
fn parse_server_name(ext: &[u8]) -> SniPeek {
    // server_name_list: len(2), then entries name_type(1) len(2) name.
    let Some(list_len) = u16(ext, 0) else { return SniPeek::None };
    let list_end = (2 + list_len).min(ext.len());
    let mut pos = 2;
    while pos + 3 <= list_end {
        let name_type = ext[pos];
        let name_len = u16(ext, pos + 1).unwrap_or(0);
        let start = pos + 3;
        let end = start + name_len;
        if end > list_end {
            return SniPeek::None;
        }
        if name_type == 0x00 {
            return match std::str::from_utf8(&ext[start..end]) {
                Ok(s) if !s.is_empty() => SniPeek::Found(s.to_ascii_lowercase()),
                _ => SniPeek::None,
            };
        }
        pos = end;
    }
    SniPeek::None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but well-formed TLS ClientHello carrying `sni`.
    fn client_hello(sni: &str) -> Vec<u8> {
        // server_name extension body.
        let mut sni_ext = Vec::new();
        let name = sni.as_bytes();
        let entry_len = 1 + 2 + name.len();
        sni_ext.extend_from_slice(&(entry_len as u16).to_be_bytes()); // list length
        sni_ext.push(0x00); // host_name
        sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(name);

        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0000u16.to_be_bytes()); // type server_name
        ext.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
        ext.extend_from_slice(&sni_ext);

        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]); // client_version
        hs_body.extend_from_slice(&[0u8; 32]); // random
        hs_body.push(0); // session_id len
        hs_body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        hs_body.extend_from_slice(&[0x13, 0x01]); // one cipher suite
        hs_body.push(1); // compression methods len
        hs_body.push(0); // null compression
        hs_body.extend_from_slice(&(ext.len() as u16).to_be_bytes()); // extensions len
        hs_body.extend_from_slice(&ext);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let len = hs_body.len();
        hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        hs.extend_from_slice(&hs_body);

        let mut rec = Vec::new();
        rec.push(0x16); // handshake
        rec.extend_from_slice(&[0x03, 0x01]); // legacy version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn extracts_sni() {
        let ch = client_hello("cloudflare-dns.com");
        assert_eq!(peek_sni(&ch), SniPeek::Found("cloudflare-dns.com".into()));
    }

    #[test]
    fn lowercases_sni() {
        let ch = client_hello("DNS.Google");
        assert_eq!(peek_sni(&ch), SniPeek::Found("dns.google".into()));
    }

    #[test]
    fn need_more_while_record_incomplete() {
        let ch = client_hello("dns.google");
        assert_eq!(peek_sni(&ch[..8]), SniPeek::NeedMore);
        assert_eq!(peek_sni(&[]), SniPeek::NeedMore);
    }

    #[test]
    fn none_for_non_handshake() {
        // A non-0x16 leading byte can be decided immediately.
        assert_eq!(peek_sni(&[0x47, 0x45, 0x54, 0x20, 0x2f]), SniPeek::None);
    }

    #[test]
    fn none_when_no_sni_extension() {
        // A ClientHello with an empty extensions block: decided, not NeedMore.
        let mut hs_body = Vec::new();
        hs_body.extend_from_slice(&[0x03, 0x03]);
        hs_body.extend_from_slice(&[0u8; 32]);
        hs_body.push(0);
        hs_body.extend_from_slice(&0u16.to_be_bytes()); // no cipher suites
        hs_body.push(1);
        hs_body.push(0);
        hs_body.extend_from_slice(&0u16.to_be_bytes()); // no extensions
        let mut hs = vec![0x01];
        let len = hs_body.len();
        hs.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        hs.extend_from_slice(&hs_body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        assert_eq!(peek_sni(&rec), SniPeek::None);
    }
}
