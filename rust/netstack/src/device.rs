// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! An in-memory smoltcp `phy::Device` for the tunnel.
//!
//! The datapath thread feeds inbound IP packets (read off the TUN fd) into
//! `inbound`, and drains packets smoltcp wants to send toward the app from
//! `outbound` to write back to the TUN fd. This keeps the stack itself free of
//! any I/O, so it is fully host-testable.

use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

pub struct TunDevice {
    inbound: VecDeque<Vec<u8>>,
    outbound: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl TunDevice {
    pub fn new(mtu: usize) -> Self {
        TunDevice { inbound: VecDeque::new(), outbound: VecDeque::new(), mtu }
    }

    /// Queue a packet read from the TUN for smoltcp to process.
    pub fn push_inbound(&mut self, packet: Vec<u8>) {
        self.inbound.push_back(packet);
    }

    /// Pop the next packet smoltcp produced for the app, to write to the TUN.
    pub fn pop_outbound(&mut self) -> Option<Vec<u8>> {
        self.outbound.pop_front()
    }

    pub fn has_inbound(&self) -> bool {
        !self.inbound.is_empty()
    }
}

pub struct RxToken(Vec<u8>);
pub struct TxToken<'a> {
    outbound: &'a mut VecDeque<Vec<u8>>,
}

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl<'a> smoltcp::phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf);
        self.outbound.push_back(buf);
        result
    }
}

impl Device for TunDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.inbound.pop_front()?;
        Some((RxToken(packet), TxToken { outbound: &mut self.outbound }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken { outbound: &mut self.outbound })
    }
}
