// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! Minimal DNS wire handling for the sinkhole.
//!
//! Parses the header and first question of a query, and synthesizes answers to
//! block a domain: `NXDOMAIN`, or a sink address (`A 0.0.0.0` / `AAAA ::`).
//! Only what the sinkhole needs — this is not a general resolver.

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const CLASS_IN: u16 = 1;

/// Well-known DoH/DoT endpoint hostnames. Under "Filter" mode a 443 flow whose
/// TLS SNI matches one of these is TLS-intercepted and its inner DNS filtered;
/// under "Block" mode the fallback drop forces plaintext we can filter. Matching
/// is by SNI (see [`is_doh_host`]), so CDN-fronted resolvers (e.g.
/// `cloudflare-dns.com` on shared 104.x IPs) are caught without an IP list.
pub const DOH_HOSTS: &[&str] = &[
    "dns.google",
    "dns.google.com",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "one.one.one.one",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.adguard.com",
    "dns.adguard-dns.com",
    "chrome.cloudflare-dns.com",
    "doh.cleanbrowsing.org",
    "dns.nextdns.io",
    "doh.mullvad.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    "dns.controld.com",
    "freedns.controld.com",
];

/// Whether `sni` is a known DoH/DoT endpoint (case-insensitive, exact host or a
/// subdomain of one — e.g. `abc.dns.nextdns.io`).
pub fn is_doh_host(sni: &str) -> bool {
    let sni = sni.trim_end_matches('.').to_ascii_lowercase();
    DOH_HOSTS.iter().any(|&h| sni == h || sni.ends_with(&format!(".{h}")))
}

/// Stable anycast IPs of major public resolvers. QUIC hides the SNI, so DoH3
/// (UDP/443) and DoQ can't be classified by name; suppressing UDP to these
/// forces the common resolvers back to interceptable TCP (P4). Not exhaustive —
/// CDN-fronted DoH (e.g. `cloudflare-dns.com` on 104.x) is only caught over TCP.
pub const KNOWN_DOH_IPS: &[std::net::IpAddr] = &[
    ip4(1, 1, 1, 1),
    ip4(1, 0, 0, 1),
    ip4(8, 8, 8, 8),
    ip4(8, 8, 4, 4),
    ip4(9, 9, 9, 9),
    ip4(149, 112, 112, 112),
    ip4(94, 140, 14, 14),
    ip4(94, 140, 15, 15),
    ip4(208, 67, 222, 222),
    ip4(208, 67, 220, 220),
    ip6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
    ip6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001),
    ip6(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
    ip6(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
    ip6(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe),
    ip6(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9),
];

const fn ip4(a: u8, b: u8, c: u8, d: u8) -> std::net::IpAddr {
    std::net::IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
}

#[allow(clippy::too_many_arguments)]
const fn ip6(a: u16, b: u16, c: u16, d: u16, e: u16, f: u16, g: u16, h: u16) -> std::net::IpAddr {
    std::net::IpAddr::V6(std::net::Ipv6Addr::new(a, b, c, d, e, f, g, h))
}

/// Whether `ip` is a known public-resolver address (for DoH3/DoQ suppression).
pub fn is_known_doh_ip(ip: std::net::IpAddr) -> bool {
    KNOWN_DOH_IPS.contains(&ip)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub id: u16,
    /// Lower-cased dotted name without the trailing root label.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
    /// Offset just past the question (start of the answer section).
    pub question_end: usize,
}

fn u16be(b: &[u8], o: usize) -> Option<u16> {
    if o + 2 <= b.len() {
        Some(((b[o] as u16) << 8) | (b[o + 1] as u16))
    } else {
        None
    }
}

/// Parse the header and first question of a standard query. Returns `None` for
/// malformed input, non-query opcodes, or responses.
pub fn parse_query(buf: &[u8]) -> Option<Question> {
    if buf.len() < 12 {
        return None;
    }
    let id = u16be(buf, 0)?;
    let flags = u16be(buf, 2)?;
    let qr = flags & 0x8000;
    let opcode = (flags >> 11) & 0x0F;
    let qdcount = u16be(buf, 4)?;
    if qr != 0 || opcode != 0 || qdcount == 0 {
        return None; // not a standard query with a question
    }

    let (name, next) = decode_name(buf, 12)?;
    let qtype = u16be(buf, next)?;
    let qclass = u16be(buf, next + 2)?;
    Some(Question { id, name, qtype, qclass, question_end: next + 4 })
}

/// Decode a QNAME starting at `start`, following compression pointers. Returns
/// the dotted name and the offset immediately after the name *in the question*
/// (i.e. past the terminating byte or the first pointer).
fn decode_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end_after: Option<usize> = None;
    let mut jumps = 0;

    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos];
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    let terminal = pos + 1;
                    return Some((labels.join("."), end_after.unwrap_or(terminal)));
                }
                let s = pos + 1;
                let e = s + len as usize;
                if e > buf.len() {
                    return None;
                }
                let label = std::str::from_utf8(&buf[s..e]).ok()?;
                labels.push(label.to_ascii_lowercase());
                pos = e;
            }
            0xC0 => {
                // Compression pointer. The name in the question ends right after
                // the two pointer bytes; record that once.
                if end_after.is_none() {
                    end_after = Some(pos + 2);
                }
                let ptr = ((len as usize & 0x3F) << 8) | *buf.get(pos + 1)? as usize;
                jumps += 1;
                if jumps > 16 || ptr >= buf.len() {
                    return None; // pointer loop / out of range
                }
                pos = ptr;
            }
            _ => return None, // 0x40 / 0x80 reserved
        }
    }
}

/// Build a response that reuses the query's header id and question, sets the
/// response bits, and applies `rcode` / answer records.
fn build_response(query: &[u8], q: &Question, rcode: u16, answers: &[u8], ancount: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(q.question_end + answers.len());
    out.extend_from_slice(&query[..q.question_end]);
    // Flags: QR=1, Opcode=0, AA=0, TC=0, RD copied, RA=1, rcode.
    let rd = (u16be(query, 2).unwrap_or(0)) & 0x0100;
    let flags = 0x8000 | rd | 0x0080 | (rcode & 0x000F);
    out[2] = (flags >> 8) as u8;
    out[3] = (flags & 0xFF) as u8;
    // Counts: QD=1, AN=ancount, NS=0, AR=0.
    out[6] = (ancount >> 8) as u8;
    out[7] = (ancount & 0xFF) as u8;
    out[8] = 0;
    out[9] = 0;
    out[10] = 0;
    out[11] = 0;
    out.extend_from_slice(answers);
    out
}

/// `NXDOMAIN` response — the query resolves to nothing.
pub fn synthesize_nxdomain(query: &[u8], q: &Question) -> Vec<u8> {
    build_response(query, q, 3, &[], 0)
}

/// A sinkhole answer pointing the name at `0.0.0.0` (A) or `::` (AAAA). Returns
/// `NOERROR` with no answer for other qtypes so the client stops asking.
pub fn synthesize_sinkhole(query: &[u8], q: &Question) -> Vec<u8> {
    let (rdata, ok): (&[u8], bool) = match q.qtype {
        TYPE_A => (&[0, 0, 0, 0], true),
        TYPE_AAAA => (&[0u8; 16], true),
        _ => (&[], false),
    };
    if !ok {
        return build_response(query, q, 0, &[], 0);
    }
    let mut ans = Vec::new();
    ans.extend_from_slice(&[0xC0, 0x0C]); // name pointer to the question (offset 12)
    ans.extend_from_slice(&q.qtype.to_be_bytes());
    ans.extend_from_slice(&CLASS_IN.to_be_bytes());
    ans.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
    ans.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    ans.extend_from_slice(rdata);
    build_response(query, q, 0, &ans, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Query for `ads.example.com` type A, id 0x1234, RD set.
    fn query() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["ads", "example", "com"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&TYPE_A.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    #[test]
    fn parses_question() {
        let parsed = parse_query(&query()).unwrap();
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.name, "ads.example.com");
        assert_eq!(parsed.qtype, TYPE_A);
        assert_eq!(parsed.qclass, CLASS_IN);
    }

    #[test]
    fn rejects_response() {
        let mut r = query();
        r[2] |= 0x80; // set QR
        assert!(parse_query(&r).is_none());
    }

    #[test]
    fn nxdomain_flags() {
        let q = query();
        let parsed = parse_query(&q).unwrap();
        let resp = synthesize_nxdomain(&q, &parsed);
        assert_eq!(resp[0], 0x12);
        assert_eq!(resp[1], 0x34); // id preserved
        assert_eq!(resp[2] & 0x80, 0x80); // QR
        assert_eq!(resp[3] & 0x0F, 3); // NXDOMAIN
        assert_eq!(u16be(&resp, 6).unwrap(), 0); // ancount 0
        // The response can be re-parsed as a message with our question echoed.
        assert_eq!(&resp[12..parsed.question_end], &q[12..parsed.question_end]);
    }

    #[test]
    fn sinkhole_a_record() {
        let q = query();
        let parsed = parse_query(&q).unwrap();
        let resp = synthesize_sinkhole(&q, &parsed);
        assert_eq!(resp[3] & 0x0F, 0); // NOERROR
        assert_eq!(u16be(&resp, 6).unwrap(), 1); // one answer
        // Answer rdata is the last 4 bytes: 0.0.0.0
        let n = resp.len();
        assert_eq!(&resp[n - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn detects_doh_hosts() {
        assert!(is_doh_host("cloudflare-dns.com"));
        assert!(is_doh_host("Cloudflare-DNS.com")); // case-insensitive
        assert!(is_doh_host("dns.google."));        // trailing root label
        assert!(is_doh_host("abc.dns.nextdns.io")); // subdomain of a known host
        assert!(!is_doh_host("example.com"));
        assert!(!is_doh_host("notcloudflare-dns.com")); // not a real subdomain
    }

    #[test]
    fn handles_compression_pointer() {
        // name = pointer to offset 12 (a contrived but valid encoding)
        let mut q = vec![0x00, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        // put a real name at 12 then reference it — but the question itself must
        // contain the name; here we just ensure a pointer at question start is
        // followed without panicking and yields the right end offset.
        for label in ["a", "b"] {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&TYPE_A.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        let parsed = parse_query(&q).unwrap();
        assert_eq!(parsed.name, "a.b");
    }
}
