//! The datapath thread and its lifecycle.
//!
//! A single thread owns an mio poll loop over the TUN fd plus a control waker.
//! In this milestone it runs in **monitor parity**: it reads packets off the
//! TUN, decodes them into events, and drops them (matching P0). P1-A replaces
//! the drop with smoltcp forwarding at the marked seam.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};

use crate::bridge::Bridge;
use crate::config::Config;
use crate::event::{Batcher, Event};

const TUN: Token = Token(0);
const WAKE: Token = Token(1);
const FLUSH_INTERVAL: Duration = Duration::from_millis(150);
const MAX_BATCH: usize = 256;

/// A running datapath. Dropping it does not stop the thread — call [`stop`].
pub struct Session {
    stop: Arc<AtomicBool>,
    waker: Arc<Waker>,
    thread: Option<JoinHandle<()>>,
}

impl Session {
    pub fn start(bridge: Bridge, tun_fd: RawFd, config: Config) -> std::io::Result<Session> {
        let poll = Poll::new()?;
        let waker = Arc::new(Waker::new(poll.registry(), WAKE)?);
        let stop = Arc::new(AtomicBool::new(false));

        let thread_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("adw-core".into())
            .spawn(move || run_loop(poll, bridge, tun_fd, config, thread_stop))?;

        Ok(Session { stop, waker, thread: Some(thread) })
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

fn run_loop(mut poll: Poll, bridge: Bridge, tun_fd: RawFd, _config: Config, stop: Arc<AtomicBool>) {
    // Take ownership so the fd is closed exactly once, when this returns.
    let fd = unsafe { OwnedFd::from_raw_fd(tun_fd) };
    set_nonblocking(fd.as_raw_fd());

    // Attach this thread to the JVM permanently (daemon) and reuse the env.
    let mut env = match bridge.vm().attach_current_thread_as_daemon() {
        Ok(env) => env,
        Err(_) => return,
    };

    if poll
        .registry()
        .register(&mut SourceFd(&fd.as_raw_fd()), TUN, Interest::READABLE)
        .is_err()
    {
        return;
    }

    let mut events = Events::with_capacity(64);
    let mut batcher = Batcher::new();
    let mut buf = vec![0u8; 65536];
    let mut last_flush = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        if poll.poll(&mut events, Some(FLUSH_INTERVAL)).is_err() {
            break;
        }
        for event in events.iter() {
            if event.token() == TUN {
                drain_tun(&fd, &mut buf, &mut batcher);
            }
        }

        if batcher.len() >= MAX_BATCH || last_flush.elapsed() >= FLUSH_INTERVAL {
            if let Some(blob) = batcher.drain_encoded() {
                bridge.on_events(&mut env, &blob);
            }
            last_flush = Instant::now();
        }
    }

    if let Some(blob) = batcher.drain_encoded() {
        bridge.on_events(&mut env, &blob);
    }
}

/// Drain all currently-readable packets from the TUN. Edge-triggered readiness
/// means we must read until EWOULDBLOCK.
fn drain_tun(fd: &OwnedFd, buf: &mut [u8], batcher: &mut Batcher) {
    loop {
        let n = unsafe {
            libc::read(fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if n > 0 {
            if let Some(decoded) = adwarden_netstack::decode(&buf[..n as usize]) {
                batcher.push(Event::flow(&decoded));
            }
            // P1-A forwarding seam: reinject upstream via smoltcp + a
            // protect()ed socket. Monitor mode drops the packet here.
        } else {
            break;
        }
    }
}
