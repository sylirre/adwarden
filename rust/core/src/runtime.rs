//! The datapath thread and its lifecycle.
//!
//! A single thread owns an mio poll loop over the TUN fd, a control waker, and
//! every upstream socket (registered by the [`Forwarder`]). It reads packets off
//! the TUN, forwards allowed flows through the smoltcp proxy / UDP NAT, writes
//! resulting packets back to the TUN, and batches events to Kotlin.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token, Waker};

use crate::bridge::Bridge;
use crate::config::Config;
use crate::event::Batcher;
use crate::forward::Forwarder;

const TUN: Token = Token(0);
const WAKE: Token = Token(1);
const FLUSH_INTERVAL: Duration = Duration::from_millis(150);
const MAX_BATCH: usize = 256;

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

fn run_loop(mut poll: Poll, bridge: Bridge, tun_fd: RawFd, config: Config, stop: Arc<AtomicBool>) {
    // Take ownership so the fd is closed exactly once, when this returns.
    let fd = unsafe { OwnedFd::from_raw_fd(tun_fd) };
    set_nonblocking(fd.as_raw_fd());

    // Attach this thread to the JVM permanently (daemon) and reuse the env.
    let mut env = match bridge.vm().attach_current_thread_as_daemon() {
        Ok(env) => env,
        Err(_) => return,
    };

    let registry = match poll.registry().try_clone() {
        Ok(r) => r,
        Err(_) => return,
    };
    if poll
        .registry()
        .register(&mut SourceFd(&fd.as_raw_fd()), TUN, Interest::READABLE)
        .is_err()
    {
        return;
    }

    let mut forwarder = Forwarder::new(config.mtu, registry);
    let mut events = Events::with_capacity(256);
    let mut batcher = Batcher::new();
    let mut buf = vec![0u8; 65536];
    let mut last_flush = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        let timeout = forwarder.poll_timeout_ms().min(FLUSH_INTERVAL.as_millis() as u64);
        if poll.poll(&mut events, Some(Duration::from_millis(timeout))).is_err() {
            break;
        }

        for event in events.iter() {
            match event.token() {
                WAKE => {}
                TUN => drain_tun(&fd, &mut buf, &mut forwarder, &mut env, &bridge, &mut batcher),
                token => forwarder.on_ready(token, event, &mut batcher),
            }
        }

        forwarder.service(&mut env, &bridge, &mut batcher);
        write_outbox(&fd, &mut forwarder);

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
