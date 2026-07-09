// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! UDP datagram parsing and reply-packet construction.
//!
//! UDP is not run through smoltcp; the core keeps a small NAT table of
//! `protect()`ed `UdpSocket`s and shuttles datagrams directly. These helpers
//! parse an inbound datagram off the TUN and build the IP+UDP reply to inject
//! back toward the app (with correct checksums via smoltcp's wire builders).

use std::net::{IpAddr, SocketAddr};

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, UdpPacket, UdpRepr,
};

pub struct UdpDatagram {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

/// Parse an inbound IPv4/IPv6 UDP datagram. Returns `None` if it isn't UDP.
pub fn parse(packet: &[u8]) -> Option<UdpDatagram> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp = UdpPacket::new_checked(ip.payload()).ok()?;
            Some(UdpDatagram {
                src: SocketAddr::new(IpAddr::V4(ip.src_addr()), udp.src_port()),
                dst: SocketAddr::new(IpAddr::V4(ip.dst_addr()), udp.dst_port()),
                payload: udp.payload().to_vec(),
            })
        }
        Some(6) => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp = UdpPacket::new_checked(ip.payload()).ok()?;
            Some(UdpDatagram {
                src: SocketAddr::new(IpAddr::V6(ip.src_addr()), udp.src_port()),
                dst: SocketAddr::new(IpAddr::V6(ip.dst_addr()), udp.dst_port()),
                payload: udp.payload().to_vec(),
            })
        }
        _ => None,
    }
}

/// Build an IP+UDP packet from `src` to `dst` carrying `payload`. Used to inject
/// an upstream reply (src = server) or a synthesized DNS answer back to the app.
pub fn build_reply(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_repr = UdpRepr { src_port: src.port(), dst_port: dst.port() };
    let udp_len = udp_repr.header_len() + payload.len();

    match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let ip_repr = Ipv4Repr {
                src_addr: s,
                dst_addr: d,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: 64,
            };
            let mut buf = vec![0u8; ip_repr.buffer_len() + udp_len];
            let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf);
            ip_repr.emit(&mut ip_pkt, &ChecksumCapabilities::default());
            let mut udp_pkt = UdpPacket::new_unchecked(ip_pkt.payload_mut());
            udp_repr.emit(
                &mut udp_pkt,
                &IpAddress::Ipv4(s),
                &IpAddress::Ipv4(d),
                payload.len(),
                |b| b.copy_from_slice(payload),
                &ChecksumCapabilities::default(),
            );
            Some(buf)
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let ip_repr = Ipv6Repr {
                src_addr: s,
                dst_addr: d,
                next_header: IpProtocol::Udp,
                payload_len: udp_len,
                hop_limit: 64,
            };
            let mut buf = vec![0u8; ip_repr.buffer_len() + udp_len];
            let mut ip_pkt = Ipv6Packet::new_unchecked(&mut buf);
            ip_repr.emit(&mut ip_pkt);
            let mut udp_pkt = UdpPacket::new_unchecked(ip_pkt.payload_mut());
            udp_repr.emit(
                &mut udp_pkt,
                &IpAddress::Ipv6(s),
                &IpAddress::Ipv6(d),
                payload.len(),
                |b| b.copy_from_slice(payload),
                &ChecksumCapabilities::default(),
            );
            Some(buf)
        }
        _ => None, // mixed address families never happen for a single flow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_then_build_round_trips() {
        let app: SocketAddr = "10.215.173.2:40000".parse().unwrap();
        let server: SocketAddr = "8.8.8.8:53".parse().unwrap();

        // App -> server query.
        let query = build_reply(app, server, b"hello-dns").unwrap();
        let parsed = parse(&query).unwrap();
        assert_eq!(parsed.src, app);
        assert_eq!(parsed.dst, server);
        assert_eq!(parsed.payload, b"hello-dns");

        // Server -> app reply.
        let reply = build_reply(server, app, b"answer").unwrap();
        let parsed = parse(&reply).unwrap();
        assert_eq!(parsed.src, server);
        assert_eq!(parsed.dst, app);
        assert_eq!(parsed.payload, b"answer");
    }

    #[test]
    fn ignores_non_udp() {
        // A TCP-ish v4 header (protocol 6) must not parse as UDP.
        let mut p = vec![0u8; 28];
        p[0] = 0x45;
        p[9] = 6;
        assert!(parse(&p).is_none());
    }
}
