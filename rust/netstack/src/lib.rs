// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! Userspace TCP/IP datapath: a smoltcp-backed TCP proxy plus packet decoding
//! and the per-flow table. UDP is handled directly by the core (hand-rolled
//! NAT), so this crate focuses on TCP interception and the shared primitives.

pub mod device;
pub mod flow_table;
pub mod packet;
pub mod stack;
pub mod udp;

pub use device::TunDevice;
pub use flow_table::{FlowKey, FlowTable};
pub use packet::{decode, Decoded, L4};
pub use stack::{reset_for_syn, FlowId, NetStack, PollOutcome};
pub use udp::UdpDatagram;
