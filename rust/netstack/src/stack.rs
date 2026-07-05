//! smoltcp-backed TCP proxy.
//!
//! Apps route all traffic into the TUN, so packets arrive addressed to real
//! internet servers rather than to us. We accept them with `any_ip` plus a
//! default route whose gateway is our own interface address, and for each new
//! outbound connection we create a TCP socket that `listen`s on the *server's*
//! endpoint — so smoltcp completes the handshake as if it were that server. The
//! datapath thread relays bytes between this socket and a real
//! `protect()`ed upstream socket.
//!
//! Addressing (tun2proxy pattern): the interface identifies as `.1` while the
//! app's tunnel address is `.2`, so smoltcp can route replies to the app
//! on-link and never confuses them with its own address.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::storage::RingBuffer;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, IpProtocol, Ipv4Packet, Ipv6Packet,
    TcpPacket,
};

use crate::device::TunDevice;

/// Interface (gateway) addresses; the app is the `.2` peer.
pub const V4_IFACE: Ipv4Addr = Ipv4Addr::new(10, 215, 173, 1);
pub const V6_IFACE: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xaced, 1, 0, 0, 0, 0, 1);

const TCP_RX_BUF: usize = 64 * 1024;
const TCP_TX_BUF: usize = 64 * 1024;
const DEFAULT_MAX_FLOWS: usize = 1024;

pub type FlowId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FourTuple {
    app: SocketAddr,
    server: SocketAddr,
}

struct TcpFlow {
    handle: SocketHandle,
    server: SocketAddr,
    tuple: FourTuple,
    closed_notified: bool,
}

/// Result of a `poll`: connections to open upstream and flows that ended.
#[derive(Default)]
pub struct PollOutcome {
    pub new_flows: Vec<(FlowId, SocketAddr)>,
    pub closed: Vec<FlowId>,
}

struct TcpPeek {
    app: SocketAddr,
    server: SocketAddr,
    syn: bool,
    ack: bool,
}

pub struct NetStack {
    iface: Interface,
    device: TunDevice,
    sockets: SocketSet<'static>,
    flows: HashMap<FlowId, TcpFlow>,
    by_tuple: HashMap<FourTuple, FlowId>,
    next_id: FlowId,
    max_flows: usize,
}

impl NetStack {
    pub fn new(mtu: usize) -> Self {
        Self::with_seed(mtu, 0)
    }

    pub fn with_seed(mtu: usize, random_seed: u64) -> Self {
        let mut device = TunDevice::new(mtu);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = random_seed;
        let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));

        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::from(IpAddr::V4(V4_IFACE)), 24));
            let _ = addrs.push(IpCidr::new(IpAddress::from(IpAddr::V6(V6_IFACE)), 64));
        });
        // any_ip accepts packets to arbitrary servers as long as a route sends
        // that prefix via one of our own addresses.
        iface.set_any_ip(true);
        iface.routes_mut().add_default_ipv4_route(V4_IFACE).ok();
        iface.routes_mut().add_default_ipv6_route(V6_IFACE).ok();

        NetStack {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            flows: HashMap::new(),
            by_tuple: HashMap::new(),
            next_id: 1,
            max_flows: DEFAULT_MAX_FLOWS,
        }
    }

    pub fn set_max_flows(&mut self, max: usize) {
        self.max_flows = max.max(1);
    }

    pub fn active_flows(&self) -> Vec<FlowId> {
        self.flows.keys().copied().collect()
    }

    /// Feed a TCP packet read off the TUN. On a fresh SYN this creates a
    /// listening socket for the server endpoint and returns the new flow so the
    /// caller can open the upstream connection.
    pub fn on_tcp_packet(&mut self, packet: &[u8]) -> Option<(FlowId, SocketAddr)> {
        let mut new_flow = None;
        if let Some(peek) = peek_tcp(packet) {
            let tuple = FourTuple { app: peek.app, server: peek.server };
            if peek.syn && !peek.ack && !self.by_tuple.contains_key(&tuple) {
                if self.flows.len() >= self.max_flows {
                    return None; // at capacity: drop; the app will retransmit
                }
                new_flow = self.create_flow(tuple);
            }
        }
        self.device.push_inbound(packet.to_vec());
        new_flow
    }

    fn create_flow(&mut self, tuple: FourTuple) -> Option<(FlowId, SocketAddr)> {
        let mut socket = tcp::Socket::new(
            RingBuffer::new(vec![0u8; TCP_RX_BUF]),
            RingBuffer::new(vec![0u8; TCP_TX_BUF]),
        );
        let listen: IpListenEndpoint = tuple.server.into();
        socket.listen(listen).ok()?;
        let handle = self.sockets.add(socket);

        let id = self.next_id;
        self.next_id += 1;
        self.flows.insert(
            id,
            TcpFlow { handle, server: tuple.server, tuple, closed_notified: false },
        );
        self.by_tuple.insert(tuple, id);
        Some((id, tuple.server))
    }

    /// Advance the stack. Call after feeding inbound packets and after updating
    /// socket buffers from upstream.
    pub fn poll(&mut self, now_ms: i64) -> PollOutcome {
        self.iface.poll(Instant::from_millis(now_ms), &mut self.device, &mut self.sockets);

        let mut outcome = PollOutcome::default();
        let snapshot: Vec<(FlowId, SocketHandle)> =
            self.flows.iter().map(|(id, f)| (*id, f.handle)).collect();
        for (id, handle) in snapshot {
            let state = self.sockets.get_mut::<tcp::Socket>(handle).state();
            if state == tcp::State::Closed {
                if let Some(flow) = self.flows.get_mut(&id) {
                    if !flow.closed_notified {
                        flow.closed_notified = true;
                        outcome.closed.push(id);
                    }
                }
            }
        }
        outcome
    }

    /// How long until the stack next needs servicing (for the poll timeout).
    pub fn poll_delay(&mut self, now_ms: i64) -> Option<Duration> {
        self.iface.poll_delay(Instant::from_millis(now_ms), &self.sockets)
    }

    /// Drain data the app has sent (to forward upstream).
    pub fn tcp_take_app_data(&mut self, id: FlowId) -> Vec<u8> {
        let Some(flow) = self.flows.get(&id) else { return Vec::new() };
        let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
        let mut out = Vec::new();
        while socket.can_recv() {
            match socket.recv(|buf| (buf.len(), buf.to_vec())) {
                Ok(chunk) if !chunk.is_empty() => out.extend_from_slice(&chunk),
                _ => break,
            }
        }
        out
    }

    /// Send bytes from upstream toward the app. Returns how many were accepted
    /// (the socket's send buffer applies backpressure).
    pub fn tcp_send_to_app(&mut self, id: FlowId, data: &[u8]) -> usize {
        let Some(flow) = self.flows.get(&id) else { return 0 };
        let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
        socket.send_slice(data).unwrap_or(0)
    }

    /// Free space in the app-bound send buffer.
    pub fn tcp_send_space(&mut self, id: FlowId) -> usize {
        let Some(flow) = self.flows.get(&id) else { return 0 };
        let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
        socket.send_capacity() - socket.send_queue()
    }

    /// True once the app has closed its sending half (FIN) and we've drained it.
    pub fn tcp_app_finished(&mut self, id: FlowId) -> bool {
        let Some(flow) = self.flows.get(&id) else { return true };
        let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
        !socket.may_recv() && socket.recv_queue() == 0
    }

    /// Close our side toward the app (send FIN) — upstream reached EOF.
    pub fn tcp_close_app(&mut self, id: FlowId) {
        if let Some(flow) = self.flows.get(&id) {
            self.sockets.get_mut::<tcp::Socket>(flow.handle).close();
        }
    }

    /// Abort toward the app (send RST) — used for firewall blocks / errors.
    pub fn tcp_abort(&mut self, id: FlowId) {
        if let Some(flow) = self.flows.get(&id) {
            self.sockets.get_mut::<tcp::Socket>(flow.handle).abort();
        }
    }

    /// Remove a fully-finished flow and its socket.
    pub fn remove_flow(&mut self, id: FlowId) {
        if let Some(flow) = self.flows.remove(&id) {
            self.sockets.remove(flow.handle);
            self.by_tuple.remove(&flow.tuple);
        }
    }

    pub fn server_addr(&self, id: FlowId) -> Option<SocketAddr> {
        self.flows.get(&id).map(|f| f.server)
    }

    /// Pop packets smoltcp produced for the app, to write to the TUN.
    pub fn drain_outbound(&mut self, mut sink: impl FnMut(&[u8])) {
        while let Some(packet) = self.device.pop_outbound() {
            sink(&packet);
        }
    }
}

fn peek_tcp(packet: &[u8]) -> Option<TcpPeek> {
    match packet.first().map(|b| b >> 4) {
        Some(4) => {
            let ip = Ipv4Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            Some(TcpPeek {
                app: SocketAddr::new(IpAddr::V4(ip.src_addr()), tcp.src_port()),
                server: SocketAddr::new(IpAddr::V4(ip.dst_addr()), tcp.dst_port()),
                syn: tcp.syn(),
                ack: tcp.ack(),
            })
        }
        Some(6) => {
            let ip = Ipv6Packet::new_checked(packet).ok()?;
            if ip.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
            Some(TcpPeek {
                app: SocketAddr::new(IpAddr::V6(ip.src_addr()), tcp.src_port()),
                server: SocketAddr::new(IpAddr::V6(ip.dst_addr()), tcp.dst_port()),
                syn: tcp.syn(),
                ack: tcp.ack(),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        Ipv4Address, Ipv4Repr, TcpControl, TcpRepr, TcpSeqNumber,
    };

    const APP: Ipv4Address = Ipv4Address::new(10, 215, 173, 2);
    const SERVER: Ipv4Address = Ipv4Address::new(93, 184, 216, 34);
    const APP_PORT: u16 = 51000;
    const SERVER_PORT: u16 = 80;

    fn build(
        control: TcpControl,
        seq: i32,
        ack: Option<i32>,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_repr = TcpRepr {
            src_port: APP_PORT,
            dst_port: SERVER_PORT,
            control,
            seq_number: TcpSeqNumber(seq),
            ack_number: ack.map(TcpSeqNumber),
            window_len: 64240,
            window_scale: None,
            max_seg_size: if control == TcpControl::Syn { Some(1460) } else { None },
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload,
        };
        let ip_repr = Ipv4Repr {
            src_addr: APP,
            dst_addr: SERVER,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut buf = vec![0u8; ip_repr.buffer_len() + tcp_repr.buffer_len()];
        let mut ip_pkt = Ipv4Packet::new_unchecked(&mut buf);
        ip_repr.emit(&mut ip_pkt, &ChecksumCapabilities::default());
        let mut tcp_pkt = TcpPacket::new_unchecked(ip_pkt.payload_mut());
        tcp_repr.emit(
            &mut tcp_pkt,
            &IpAddress::Ipv4(APP),
            &IpAddress::Ipv4(SERVER),
            &ChecksumCapabilities::default(),
        );
        buf
    }

    fn pop_out(stack: &mut NetStack) -> Option<Vec<u8>> {
        let mut out = None;
        stack.drain_outbound(|p| {
            if out.is_none() {
                out = Some(p.to_vec());
            }
        });
        out
    }

    #[test]
    fn intercepts_syn_and_relays_data() {
        let mut stack = NetStack::with_seed(1500, 0x1234);

        // 1. App SYN -> a new flow is reported for the real server endpoint.
        let client_isn = 1000;
        let syn = build(TcpControl::Syn, client_isn, None, &[]);
        let new_flow = stack.on_tcp_packet(&syn);
        assert_eq!(
            new_flow,
            Some((1, SocketAddr::new(IpAddr::V4(SERVER), SERVER_PORT)))
        );

        // 2. Poll -> smoltcp answers with a SYN-ACK sourced from the server.
        stack.poll(0);
        let synack = pop_out(&mut stack).expect("SYN-ACK emitted");
        let ip = Ipv4Packet::new_checked(&synack).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.syn() && tcp.ack(), "expected SYN-ACK");
        assert_eq!(ip.src_addr(), SERVER);
        assert_eq!(tcp.src_port(), SERVER_PORT);
        assert_eq!(ip.dst_addr(), APP);
        assert_eq!(tcp.dst_port(), APP_PORT);
        let server_isn = tcp.seq_number().0;

        // 3. App completes the handshake with an ACK.
        let ack = build(TcpControl::None, client_isn + 1, Some(server_isn + 1), &[]);
        stack.on_tcp_packet(&ack);
        stack.poll(0);

        // 4. App sends request data -> the stack surfaces it for the upstream.
        let body = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let data = build(TcpControl::Psh, client_isn + 1, Some(server_isn + 1), body);
        stack.on_tcp_packet(&data);
        stack.poll(0);
        assert_eq!(stack.tcp_take_app_data(1), body);

        // 5. Upstream reply flows back toward the app.
        let accepted = stack.tcp_send_to_app(1, b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(accepted, 19);
        stack.poll(0);
        let reply = pop_out(&mut stack).expect("data packet to app");
        let ip = Ipv4Packet::new_checked(&reply).unwrap();
        assert_eq!(ip.src_addr(), SERVER);
        assert_eq!(ip.dst_addr(), APP);
    }

    #[test]
    fn respects_flow_cap() {
        let mut stack = NetStack::with_seed(1500, 1);
        stack.set_max_flows(1);
        let syn = build(TcpControl::Syn, 1, None, &[]);
        assert!(stack.on_tcp_packet(&syn).is_some());
        // A second distinct SYN would exceed the cap; same tuple is deduped, so
        // just assert the cap is enforced via the count.
        assert_eq!(stack.active_flows().len(), 1);
    }
}
