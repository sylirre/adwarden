//! JNI entry points (`Java_com_adwarden_core_NativeCore_*`).
//!
//! Every function wraps its body in `catch_unwind`: a Rust panic unwinding
//! across the FFI boundary is undefined behavior, so panics are converted to a
//! null/zero result instead.

use std::panic::{catch_unwind, AssertUnwindSafe};

use jni::objects::{JClass, JObject, JString};
use jni::sys::{jint, jlong};
use jni::JNIEnv;

use crate::bridge::Bridge;
use crate::config::Config;
use crate::runtime::Session;

/// Bumped whenever the Kotlin<->Rust FFI contract changes shape.
pub const ABI_VERSION: i32 = 1;

#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeAbiVersion(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    ABI_VERSION
}

#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeStart<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    tun_fd: jint,
    config: JString<'local>,
    bridge: JObject<'local>,
) -> jlong {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let config_json: String = env
            .get_string(&config)
            .map(|s| s.into())
            .unwrap_or_default();
        let config = Config::from_json(&config_json);
        let bridge = Bridge::new(&mut env, &bridge).ok()?;
        Session::start(bridge, tun_fd as std::os::fd::RawFd, config).ok()
    }));

    match result {
        Ok(Some(session)) => Box::into_raw(Box::new(session)) as jlong,
        _ => 0,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeStop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let session = unsafe { Box::from_raw(handle as *mut Session) };
        session.stop();
    }));
}
