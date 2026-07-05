//! Best-effort IPv4/IPv6 header decoding, mirroring the P0 Kotlin
//! `PacketDecoder`. Extension-header walking and fragment reassembly are the
//! job of the smoltcp stack (P1-A); this only reads the leading headers to
//! classify a packet into a 5-tuple for the live log and flow table.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4 {
    Tcp,
    Udp,
    Icmp,
    Other,
}

impl L4 {
    fn of(proto: u8) -> L4 {
        match proto {
            PROTO_TCP => L4::Tcp,
            PROTO_UDP => L4::Udp,
            PROTO_ICMP | PROTO_ICMPV6 => L4::Icmp,
            _ => L4::Other,
        }
    }
}

/// A decoded packet's addressing, enough for logging and flow keying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decoded {
    pub ip_version: u8,
    pub proto: L4,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// Total on-wire length as reported by the IP header (clamped to the buffer).
    pub length: u32,
}

fn u16be(b: &[u8], o: usize) -> u16 {
    ((b[o] as u16) << 8) | (b[o + 1] as u16)
}

/// Decode the leading IP + L4 header. Returns `None` for a runt or unknown
/// version.
pub fn decode(buf: &[u8]) -> Option<Decoded> {
    if buf.len() < 20 {
        return None;
    }
    match buf[0] >> 4 {
        4 => decode_v4(buf),
        6 => decode_v6(buf),
        _ => None,
    }
}

fn decode_v4(buf: &[u8]) -> Option<Decoded> {
    let ihl = ((buf[0] & 0x0F) as usize) * 4;
    if ihl < 20 || ihl > buf.len() {
        return None;
    }
    let total_len = u16be(buf, 2) as u32;
    let proto = L4::of(buf[9]);
    let src = IpAddr::V4(Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]));
    let (sp, dp) = ports(buf, ihl, proto);
    let length = clamp_len(total_len, buf.len());
    Some(Decoded { ip_version: 4, proto, src, dst, src_port: sp, dst_port: dp, length })
}

fn decode_v6(buf: &[u8]) -> Option<Decoded> {
    if buf.len() < 40 {
        return None;
    }
    let payload_len = u16be(buf, 4) as u32;
    let proto = L4::of(buf[6]);
    let src = IpAddr::V6(v6(buf, 8));
    let dst = IpAddr::V6(v6(buf, 24));
    let (sp, dp) = ports(buf, 40, proto);
    let length = clamp_len(40 + payload_len, buf.len());
    Some(Decoded { ip_version: 6, proto, src, dst, src_port: sp, dst_port: dp, length })
}

fn ports(buf: &[u8], l4_off: usize, proto: L4) -> (u16, u16) {
    if matches!(proto, L4::Tcp | L4::Udp) && buf.len() >= l4_off + 4 {
        (u16be(buf, l4_off), u16be(buf, l4_off + 2))
    } else {
        (0, 0)
    }
}

fn clamp_len(reported: u32, actual: usize) -> u32 {
    if reported >= 1 && reported as usize <= actual {
        reported
    } else {
        actual as u32
    }
}

fn v6(buf: &[u8], o: usize) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&buf[o..o + 16]);
    Ipv6Addr::from(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal IPv4 + UDP packet to 8.8.8.8:53.
    fn v4_udp() -> Vec<u8> {
        let mut p = vec![0u8; 28];
        p[0] = 0x45; // version 4, IHL 5
        let total = (28u16).to_be_bytes();
        p[2] = total[0];
        p[3] = total[1];
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[16..20].copy_from_slice(&[8, 8, 8, 8]);
        p[20..22].copy_from_slice(&(40000u16).to_be_bytes()); // src port
        p[22..24].copy_from_slice(&(53u16).to_be_bytes()); // dst port
        p
    }

    #[test]
    fn decodes_v4_udp() {
        let d = decode(&v4_udp()).unwrap();
        assert_eq!(d.ip_version, 4);
        assert_eq!(d.proto, L4::Udp);
        assert_eq!(d.src, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(d.dst, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(d.src_port, 40000);
        assert_eq!(d.dst_port, 53);
        assert_eq!(d.length, 28);
    }

    #[test]
    fn rejects_runt() {
        assert!(decode(&[0x45, 0, 0]).is_none());
    }

    #[test]
    fn decodes_v6_tcp() {
        let mut p = vec![0u8; 60];
        p[0] = 0x60; // version 6
        p[4..6].copy_from_slice(&(20u16).to_be_bytes()); // payload len
        p[6] = PROTO_TCP;
        p[8] = 0xfd; // src ::/fd..
        p[24] = 0x20; // dst 2000::
        p[40..42].copy_from_slice(&(1234u16).to_be_bytes());
        p[42..44].copy_from_slice(&(443u16).to_be_bytes());
        let d = decode(&p).unwrap();
        assert_eq!(d.ip_version, 6);
        assert_eq!(d.proto, L4::Tcp);
        assert_eq!(d.dst_port, 443);
        assert_eq!(d.length, 60);
    }
}
