//! Adwarden native core — the JNI surface loaded by the Android app as
//! `libadwarden_core.so`.
//!
//! In this milestone the core runs in monitor parity: it takes ownership of the
//! TUN fd, decodes packets on a dedicated thread, and batches events back to
//! Kotlin over the `NativeBridge` upcall. Forwarding (smoltcp), the DNS
//! sinkhole, the filter engine, the per-app firewall, and the pcap tap build on
//! this scaffold in P1-A..E.

mod bridge;
mod config;
mod event;
mod ffi;
mod runtime;

pub use ffi::ABI_VERSION;

/// Initialize Android logcat logging. Called once from `nativeAbiVersion` guard
/// paths in later commits; kept here so both `cfg` branches compile.
#[cfg(target_os = "android")]
pub fn init_logging() {
    use android_logger::Config;
    use log::LevelFilter;
    android_logger::init_once(
        Config::default()
            .with_max_level(LevelFilter::Info)
            .with_tag("AdwardenCore"),
    );
}

#[cfg(not(target_os = "android"))]
pub fn init_logging() {}
