// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! Batched event encoding for the Rust -> Kotlin upcall.
//!
//! Events are accumulated on the datapath thread and flushed as one little-
//! endian blob (see the layout below) roughly every 150 ms, so the FFI boundary
//! is crossed a few times a second rather than per packet. `NativeEventCodec`
//! on the Kotlin side decodes the identical layout.

use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use adwarden_netstack::{Decoded, L4};

pub const KIND_FLOW: u8 = 0;
pub const KIND_DNS_BLOCK: u8 = 1;
/// An intercepted HTTPS flow whose app rejected our leaf (cert pinning): it now
/// relays raw, so it's reported as metadata-only (P2-4). `domain` carries the SNI.
pub const KIND_TLS_PINNED: u8 = 2;
/// A window's worth of coalesced allowed-flow telemetry (P3-4). Emitted instead
/// of per-flow [`KIND_FLOW`] events when the live log is closed and the flow's
/// app isn't engaged, so an idle background tunnel makes far fewer FFI upcalls.
/// It carries no endpoint — only aggregate counters, packed into the otherwise
/// unused `src`/`dst` fields (see [`Event::coarse`]).
pub const KIND_COARSE: u8 = 3;

pub const PROTO_TCP: u8 = 0;
pub const PROTO_UDP: u8 = 1;
pub const PROTO_ICMP: u8 = 2;
pub const PROTO_OTHER: u8 = 3;

pub const VERDICT_ALLOW: u8 = 0;
pub const VERDICT_BLOCK: u8 = 1;

/// One event to surface in the live log / stats.
///
/// Wire layout (little-endian), repeated `count` times after a leading u32
/// count:
///   kind:u8, ip_version:u8, proto:u8, verdict:u8,
///   uid:i32, src_port:u16, dst_port:u16, length:u32, timestamp_ms:u64,
///   src:[u8;16], dst:[u8;16], domain_len:u16, domain:[u8; domain_len]
pub struct Event {
    pub kind: u8,
    pub ip_version: u8,
    pub proto: u8,
    pub verdict: u8,
    pub uid: i32,
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u32,
    pub timestamp_ms: u64,
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub domain: Option<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn ip_bytes(ip: IpAddr) -> [u8; 16] {
    let mut out = [0u8; 16];
    match ip {
        IpAddr::V4(v4) => out[..4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.copy_from_slice(&v6.octets()),
    }
    out
}

fn proto_code(l4: L4) -> u8 {
    match l4 {
        L4::Tcp => PROTO_TCP,
        L4::Udp => PROTO_UDP,
        L4::Icmp => PROTO_ICMP,
        L4::Other => PROTO_OTHER,
    }
}

impl Event {
    fn from_decoded(decoded: &Decoded, kind: u8, verdict: u8, domain: Option<String>) -> Event {
        Event {
            kind,
            ip_version: decoded.ip_version,
            proto: proto_code(decoded.proto),
            verdict,
            uid: -1,
            src_port: decoded.src_port,
            dst_port: decoded.dst_port,
            length: decoded.length,
            timestamp_ms: now_ms(),
            src: ip_bytes(decoded.src),
            dst: ip_bytes(decoded.dst),
            domain,
        }
    }

    /// A plain forwarded flow event (allow verdict, UID unknown).
    pub fn flow(decoded: &Decoded) -> Event {
        Event::from_decoded(decoded, KIND_FLOW, VERDICT_ALLOW, None)
    }

    /// A blocked flow with no domain context (e.g. an encrypted-DNS drop).
    pub fn blocked(decoded: &Decoded) -> Event {
        Event::from_decoded(decoded, KIND_FLOW, VERDICT_BLOCK, None)
    }

    /// A DNS query blocked by the filter engine, carrying the sinkholed domain.
    pub fn blocked_domain(decoded: &Decoded, domain: String) -> Event {
        Event::from_decoded(decoded, KIND_DNS_BLOCK, VERDICT_BLOCK, Some(domain))
    }

    /// An HTTPS flow we couldn't decrypt because the app pinned/refused our leaf.
    /// The flow still forwards (allow), but only its metadata is visible. `host`
    /// is the SNI, if it was learned before the rejection. We lack the app's
    /// local endpoint here, so `src` is left zeroed.
    pub fn tls_pinned(uid: i32, dst: SocketAddr, host: Option<String>) -> Event {
        Event {
            kind: KIND_TLS_PINNED,
            ip_version: if dst.is_ipv4() { 4 } else { 6 },
            proto: PROTO_TCP,
            verdict: VERDICT_ALLOW,
            uid,
            src_port: 0,
            dst_port: dst.port(),
            length: 0,
            timestamp_ms: now_ms(),
            src: [0u8; 16],
            dst: ip_bytes(dst.ip()),
            domain: host,
        }
    }

    /// A coalesced aggregate of allowed flows that were not surfaced
    /// individually (P3-4). The record keeps the fixed wire shape; the counters
    /// ride in the unused address fields, little-endian:
    ///   src[0..4] = packets, src[4..8] = tcp, src[8..12] = udp,
    ///   src[12..16] = dns, dst[0..8] = bytes.
    /// `NativeEventCodec` unpacks the identical layout for `kind == KIND_COARSE`.
    pub fn coarse(packets: u32, bytes: u64, tcp: u32, udp: u32, dns: u32) -> Event {
        let mut src = [0u8; 16];
        src[0..4].copy_from_slice(&packets.to_le_bytes());
        src[4..8].copy_from_slice(&tcp.to_le_bytes());
        src[8..12].copy_from_slice(&udp.to_le_bytes());
        src[12..16].copy_from_slice(&dns.to_le_bytes());
        let mut dst = [0u8; 16];
        dst[0..8].copy_from_slice(&bytes.to_le_bytes());
        Event {
            kind: KIND_COARSE,
            ip_version: 0,
            proto: PROTO_OTHER,
            verdict: VERDICT_ALLOW,
            uid: -1,
            src_port: 0,
            dst_port: 0,
            length: 0,
            timestamp_ms: now_ms(),
            src,
            dst,
            domain: None,
        }
    }

    /// Attach the owning app UID (from the firewall lookup).
    pub fn with_uid(mut self, uid: i32) -> Event {
        self.uid = uid;
        self
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.kind);
        out.push(self.ip_version);
        out.push(self.proto);
        out.push(self.verdict);
        out.extend_from_slice(&self.uid.to_le_bytes());
        out.extend_from_slice(&self.src_port.to_le_bytes());
        out.extend_from_slice(&self.dst_port.to_le_bytes());
        out.extend_from_slice(&self.length.to_le_bytes());
        out.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.dst);
        match &self.domain {
            Some(d) => {
                let bytes = d.as_bytes();
                let len = bytes.len().min(u16::MAX as usize);
                out.extend_from_slice(&(len as u16).to_le_bytes());
                out.extend_from_slice(&bytes[..len]);
            }
            None => out.extend_from_slice(&0u16.to_le_bytes()),
        }
    }
}

/// Accumulates events and encodes them into a single batch blob.
pub struct Batcher {
    events: Vec<Event>,
}

impl Batcher {
    pub fn new() -> Self {
        Batcher { events: Vec::new() }
    }

    pub fn push(&mut self, event: Event) {
        self.events.push(event);
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Encode and clear. Returns `None` when empty.
    pub fn drain_encoded(&mut self) -> Option<Vec<u8>> {
        if self.events.is_empty() {
            return None;
        }
        let mut out = Vec::with_capacity(64 * self.events.len());
        out.extend_from_slice(&(self.events.len() as u32).to_le_bytes());
        for event in &self.events {
            event.encode_into(&mut out);
        }
        self.events.clear();
        Some(out)
    }
}

impl Default for Batcher {
    fn default() -> Self {
        Batcher::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_count_prefix_and_domain() {
        let mut b = Batcher::new();
        b.push(Event {
            kind: KIND_DNS_BLOCK,
            ip_version: 4,
            proto: PROTO_UDP,
            verdict: VERDICT_BLOCK,
            uid: 10123,
            src_port: 40000,
            dst_port: 53,
            length: 60,
            timestamp_ms: 1,
            src: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst: [1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            domain: Some("ads.example.com".into()),
        });
        let blob = b.drain_encoded().unwrap();
        assert_eq!(u32::from_le_bytes(blob[..4].try_into().unwrap()), 1);
        // kind, ipver, proto, verdict at offset 4..8
        assert_eq!(&blob[4..8], &[KIND_DNS_BLOCK, 4, PROTO_UDP, VERDICT_BLOCK]);
        // domain length lives at the tail: total fixed = 4(count)+4+4+2+2+4+8+16+16 = 60, then u16 len
        let domain_len_off = 4 + 4 + 4 + 2 + 2 + 4 + 8 + 16 + 16;
        let dlen = u16::from_le_bytes(blob[domain_len_off..domain_len_off + 2].try_into().unwrap());
        assert_eq!(dlen as usize, "ads.example.com".len());
        assert!(b.is_empty());
    }

    #[test]
    fn empty_batch_is_none() {
        assert!(Batcher::new().drain_encoded().is_none());
    }

    #[test]
    fn coarse_packs_counters_into_address_fields() {
        let e = Event::coarse(7, 4096, 5, 2, 3);
        assert_eq!(e.kind, KIND_COARSE);
        // src holds packets/tcp/udp/dns as u32 LE at 0/4/8/12.
        assert_eq!(u32::from_le_bytes(e.src[0..4].try_into().unwrap()), 7);
        assert_eq!(u32::from_le_bytes(e.src[4..8].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(e.src[8..12].try_into().unwrap()), 2);
        assert_eq!(u32::from_le_bytes(e.src[12..16].try_into().unwrap()), 3);
        // dst holds bytes as u64 LE.
        assert_eq!(u64::from_le_bytes(e.dst[0..8].try_into().unwrap()), 4096);
    }
}
