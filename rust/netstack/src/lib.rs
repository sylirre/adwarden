//! Userspace TCP/IP datapath: smoltcp-backed TCP proxying and a hand-rolled
//! UDP NAT, relayed through `VpnService.protect()`ed upstream sockets.
//!
//! Phase 0 skeleton — the stack lands with P1-A.
