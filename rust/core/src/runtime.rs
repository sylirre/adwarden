// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

//! The datapath thread and its lifecycle.
//!
//! A single thread owns an mio poll loop over the TUN fd, a control waker, and
//! every upstream socket (registered by the [`Forwarder`]). It reads packets off
//! the TUN, forwards allowed flows through the smoltcp proxy / UDP NAT, writes
//! resulting packets back to the TUN, and batches events to Kotlin.

use std::collections::VecDeque;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};

use std::collections::HashMap;

use crate::bridge::Bridge;
use crate::config::{Config, EncryptedDnsMode};
use crate::event::Batcher;
use crate::forward::{AppPolicy, Forwarder};

const TUN: Token = Token(0);
const WAKE: Token = Token(1);
const FLUSH_INTERVAL: Duration = Duration::from_millis(150);
const MAX_BATCH: usize = 256;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);
/// Relaxed cadence used when telemetry is "cold" — the live log is closed and no
/// app is engaged (P3-4). The poll then blocks up to a full second instead of
/// waking ~7×/s just to check the flush timer, and the heartbeat log quiets down.
/// A control command (e.g. the log opening) wakes the poll immediately, so the
/// ramp back to full cadence is not delayed by these intervals.
const FLUSH_INTERVAL_IDLE: Duration = Duration::from_millis(1000);
const HEARTBEAT_INTERVAL_IDLE: Duration = Duration::from_secs(15);

/// A runtime control message applied on the datapath thread between polls.
pub enum Command {
    /// Load a serialized filter-engine cache from disk, optionally applying a
    /// scriptlet resource pack (P4-3) so `injected_script` is populated. Resources
    /// aren't serialized into the cache, so the pack is re-applied on every load.
    LoadEngine { engine: String, resources: Option<String> },
    /// Set how encrypted DNS (DoT/DoH) is handled: off, block, or filter.
    SetEncryptedDnsMode(EncryptedDnsMode),
    /// Replace the per-app firewall rules (uid -> policy).
    UpdateFirewall(HashMap<i32, AppPolicy>),
    /// Set the current network transport (0 other / 1 wifi / 2 cellular).
    SetTransport(u8),
    /// Start a pcapng capture to an owned fd (ring_bytes 0 = unbounded).
    StartPcap { fd: RawFd, ring_bytes: u64 },
    /// Stop and close the active capture.
    StopPcap,
    /// Write the decrypted HTTP transactions as HAR 1.2 to an owned fd (P2-3).
    ExportHar { fd: RawFd },
    /// Set whether the live traffic log / a capture is open (P3-4). Drives the
    /// coalescing fast-path and the datapath's wakeup cadence.
    SetLogOpen(bool),
    /// Set the cosmetic-filtering mode (P4): element hiding and/or scriptlet
    /// injection into `text/html` on inspected flows.
    SetCosmetic { element_hiding: bool, scriptlets: bool },
}

pub struct Session {
    stop: Arc<AtomicBool>,
    waker: Arc<Waker>,
    commands: Arc<Mutex<VecDeque<Command>>>,
    thread: Option<JoinHandle<()>>,
}

impl Session {
    pub fn start(bridge: Bridge, tun_fd: RawFd, config: Config) -> std::io::Result<Session> {
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKE)?);
        let stop = Arc::new(AtomicBool::new(false));
        let commands = Arc::new(Mutex::new(VecDeque::new()));

        let thread_stop = stop.clone();
        let thread_commands = commands.clone();
        let thread = std::thread::Builder::new()
            .name("adw-core".into())
            .spawn(move || {
                // A panic must not silently kill the datapath thread (that would
                // look like a total hang). Catch it and log instead.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_loop(poll, bridge, tun_fd, config, thread_stop, thread_commands)
                }));
                if outcome.is_err() {
                    crate::alog!("adw-core datapath thread panicked");
                }
            })?;

        Ok(Session { stop, waker, commands, thread: Some(thread) })
    }

    /// Queue a control command and wake the datapath thread to apply it.
    pub fn send(&self, command: Command) {
        if let Ok(mut queue) = self.commands.lock() {
            queue.push_back(command);
        }
        let _ = self.waker.wake();
    }

    /// Signal the loop to exit, wake it, and join. The TUN fd is closed by the
    /// loop as it returns.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.waker.wake();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn set_nonblocking(fd: RawFd) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
}

fn run_loop(
    mut poll: Poll,
    bridge: Bridge,
    tun_fd: RawFd,
    config: Config,
    stop: Arc<AtomicBool>,
    commands: Arc<Mutex<VecDeque<Command>>>,
) {
    // Take ownership so the fd is closed exactly once, when this returns.
    let fd = unsafe { OwnedFd::from_raw_fd(tun_fd) };
    set_nonblocking(fd.as_raw_fd());
    crate::alog!("run_loop: starting (tun_fd={}, mtu={})", tun_fd, config.mtu);

    // Attach this thread to the JVM permanently (daemon) and reuse the env.
    let mut env = match bridge.vm().attach_current_thread_as_daemon() {
        Ok(env) => env,
        Err(e) => {
            crate::alog!("run_loop: attach_current_thread_as_daemon failed: {:?}", e);
            return;
        }
    };

    let registry = match poll.registry().try_clone() {
        Ok(r) => r,
        Err(e) => {
            crate::alog!("run_loop: registry.try_clone failed: {:?}", e);
            return;
        }
    };
    if let Err(e) = poll
        .registry()
        .register(&mut SourceFd(&fd.as_raw_fd()), TUN, Interest::READABLE)
    {
        crate::alog!("run_loop: TUN register failed: {:?}", e);
        return;
    }

    let mut forwarder = Forwarder::new(&config, registry);
    let mut events = Events::with_capacity(256);
    let mut batcher = Batcher::new();
    let mut buf = vec![0u8; 65536];
    let mut last_flush = Instant::now();
    let mut last_heartbeat = Instant::now();
    crate::alog!("run_loop: entering poll loop");

    while !stop.load(Ordering::Relaxed) {
        // Full cadence while the log is open or an app is engaged; relaxed while
        // idle-background so the thread wakes ~1×/s instead of ~7×/s (P3-4).
        let hot = forwarder.telemetry_hot();
        let flush_interval = if hot { FLUSH_INTERVAL } else { FLUSH_INTERVAL_IDLE };
        let heartbeat_interval = if hot { HEARTBEAT_INTERVAL } else { HEARTBEAT_INTERVAL_IDLE };

        let timeout = forwarder.poll_timeout_ms().min(flush_interval.as_millis() as u64);
        if let Err(e) = poll.poll(&mut events, Some(Duration::from_millis(timeout))) {
            crate::alog!("run_loop: poll failed: {:?}", e);
            break;
        }

        apply_commands(&commands, &mut forwarder);

        for event in events.iter() {
            match event.token() {
                WAKE => {}
                TUN => drain_tun(&fd, &mut buf, &mut forwarder, &mut env, &bridge, &mut batcher),
                token => forwarder.on_ready(token, event, &mut batcher),
            }
        }

        forwarder.service(&mut env, &bridge, &mut batcher);
        write_outbox(&fd, &mut forwarder);

        if batcher.len() >= MAX_BATCH || last_flush.elapsed() >= flush_interval {
            // Fold the coalesced allowed-flow aggregate into this batch (P3-4).
            if let Some(coarse) = forwarder.take_coarse() {
                batcher.push(coarse);
            }
            if let Some(blob) = batcher.drain_encoded() {
                bridge.on_events(&mut env, &blob);
            }
            last_flush = Instant::now();
        }

        if last_heartbeat.elapsed() >= heartbeat_interval {
            let s = forwarder.take_stats();
            let (tcp_flows, udp_flows) = forwarder.flow_counts();
            crate::alog!(
                "hb tun_in={} tcp_new={} udp_new={} protect_ok={} protect_fail={} connect_fail={} \
                 reply={} out={} uid_lookups={} blocked={} mitm={} pinned={} har={} flows(tcp={},udp={})",
                s.tun_in, s.tcp_new, s.udp_new, s.protect_ok, s.protect_fail, s.connect_fail,
                s.upstream_reply, s.out_written, s.uid_lookups, s.blocked, s.mitm_new,
                s.pinned, forwarder.har_len(), tcp_flows, udp_flows,
            );
            last_heartbeat = Instant::now();
        }
    }

    if let Some(coarse) = forwarder.take_coarse() {
        batcher.push(coarse);
    }
    if let Some(blob) = batcher.drain_encoded() {
        bridge.on_events(&mut env, &blob);
    }
    crate::alog!("run_loop: exiting (stop={})", stop.load(Ordering::Relaxed));
}

/// Drain queued control commands and apply them to the forwarder.
fn apply_commands(commands: &Arc<Mutex<VecDeque<Command>>>, forwarder: &mut Forwarder) {
    let drained: Vec<Command> = match commands.lock() {
        Ok(mut queue) => queue.drain(..).collect(),
        Err(_) => return,
    };
    for command in drained {
        match command {
            Command::LoadEngine { engine, resources } => {
                forwarder.load_engine(&engine, resources.as_deref())
            }
            Command::SetEncryptedDnsMode(mode) => forwarder.set_encrypted_dns_mode(mode),
            Command::UpdateFirewall(rules) => forwarder.set_firewall(rules),
            Command::SetTransport(transport) => forwarder.set_transport(transport),
            Command::StartPcap { fd, ring_bytes } => forwarder.start_pcap(fd, ring_bytes),
            Command::StopPcap => forwarder.stop_pcap(),
            Command::ExportHar { fd } => forwarder.export_har(fd),
            Command::SetLogOpen(open) => forwarder.set_log_open(open),
            Command::SetCosmetic { element_hiding, scriptlets } => {
                forwarder.set_cosmetic(element_hiding, scriptlets)
            }
        }
    }
}

/// Drain all currently-readable packets from the TUN and route each one.
fn drain_tun(
    fd: &OwnedFd,
    buf: &mut [u8],
    forwarder: &mut Forwarder,
    env: &mut jni::JNIEnv,
    bridge: &Bridge,
    batcher: &mut Batcher,
) {
    loop {
        let n = unsafe {
            libc::read(fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if n > 0 {
            forwarder.on_tun_packet(&buf[..n as usize], env, bridge, batcher);
        } else {
            break;
        }
    }
}

/// Write every packet the forwarder produced back to the TUN.
fn write_outbox(fd: &OwnedFd, forwarder: &mut Forwarder) {
    for packet in forwarder.take_outbox() {
        let mut off = 0;
        while off < packet.len() {
            let n = unsafe {
                libc::write(
                    fd.as_raw_fd(),
                    packet[off..].as_ptr() as *const libc::c_void,
                    packet.len() - off,
                )
            };
            if n > 0 {
                off += n as usize;
            } else {
                break; // EWOULDBLOCK or error: drop the rest of this packet
            }
        }
    }
}
