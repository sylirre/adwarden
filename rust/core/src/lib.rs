// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

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
mod forward;
mod runtime;

pub use ffi::ABI_VERSION;

/// Initialize Android logcat logging via the `log` facade (best-effort — the
/// datapath diagnostics use [`alog`] directly, which cannot silently no-op).
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

/// Write a line straight to Android's logcat (tag `AdwardenCore`, INFO) via
/// liblog. This bypasses the `log`/android_logger stack entirely so diagnostics
/// are guaranteed to appear regardless of logger init or level filtering.
#[cfg(target_os = "android")]
pub fn alog(msg: &str) {
    use std::ffi::CString;
    use std::os::raw::c_char;
    extern "C" {
        fn __android_log_write(prio: i32, tag: *const c_char, text: *const c_char) -> i32;
    }
    const ANDROID_LOG_INFO: i32 = 4;
    if let (Ok(tag), Ok(text)) = (CString::new("AdwardenCore"), CString::new(msg)) {
        unsafe {
            __android_log_write(ANDROID_LOG_INFO, tag.as_ptr(), text.as_ptr());
        }
    }
}

#[cfg(not(target_os = "android"))]
pub fn alog(_msg: &str) {}

/// `alog` with `format!`-style arguments.
#[macro_export]
macro_rules! alog {
    ($($arg:tt)*) => { $crate::alog(&format!($($arg)*)) };
}
