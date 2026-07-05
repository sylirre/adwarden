//! The upcall surface into Kotlin (`NativeBridge`).
//!
//! Holds a `JavaVM` plus a global reference to the Kotlin `NativeBridge`
//! instance. The datapath thread attaches to the JVM once (as a daemon) and
//! reuses its `JNIEnv`. For now only `onEvents` is wired; `protect` and
//! `lookupUid` (hot-path, so their method IDs will be cached) arrive with P1-A
//! and P1-D.

use std::net::IpAddr;
use std::os::fd::RawFd;

use jni::objects::{GlobalRef, JObject, JValue};
use jni::{JNIEnv, JavaVM};

pub struct Bridge {
    vm: JavaVM,
    global: GlobalRef,
}

impl Bridge {
    pub fn new(env: &mut JNIEnv, obj: &JObject) -> jni::errors::Result<Self> {
        let vm = env.get_java_vm()?;
        let global = env.new_global_ref(obj)?;
        Ok(Bridge { vm, global })
    }

    pub fn vm(&self) -> &JavaVM {
        &self.vm
    }

    /// Deliver an encoded event batch to `NativeBridge.onEvents([B)`. Any Java
    /// exception is cleared so it does not poison the next call.
    pub fn on_events(&self, env: &mut JNIEnv, batch: &[u8]) {
        let Ok(array) = env.byte_array_from_slice(batch) else { return };
        let _ = env.call_method(&self.global, "onEvents", "([B)V", &[JValue::Object(&array)]);
        self.clear_exception(env);
    }

    /// Ask the VpnService to `protect` a socket fd so its traffic bypasses the
    /// tunnel. Called on the datapath thread before connecting an upstream
    /// socket; returns false on any error (caller should abandon the socket).
    pub fn protect(&self, env: &mut JNIEnv, fd: RawFd) -> bool {
        let result = env.call_method(&self.global, "protect", "(I)Z", &[JValue::Int(fd)]);
        self.clear_exception(env);
        result.and_then(|v| v.z()).unwrap_or(false)
    }

    /// Resolve the owning app UID of a connection via
    /// `ConnectivityManager.getConnectionOwnerUid`. Returns -1 (INVALID_UID) on
    /// error or when the connection isn't attributable.
    pub fn lookup_uid(
        &self,
        env: &mut JNIEnv,
        proto: i32,
        src: std::net::SocketAddr,
        dst: std::net::SocketAddr,
    ) -> i32 {
        let src_bytes = ip_octets(src.ip());
        let dst_bytes = ip_octets(dst.ip());
        let (Ok(src_arr), Ok(dst_arr)) =
            (env.byte_array_from_slice(&src_bytes), env.byte_array_from_slice(&dst_bytes))
        else {
            return -1;
        };
        let result = env.call_method(
            &self.global,
            "lookupUid",
            "(I[BI[BI)I",
            &[
                JValue::Int(proto),
                JValue::Object(&src_arr),
                JValue::Int(src.port() as i32),
                JValue::Object(&dst_arr),
                JValue::Int(dst.port() as i32),
            ],
        );
        self.clear_exception(env);
        result.and_then(|v| v.i()).unwrap_or(-1)
    }

    fn clear_exception(&self, env: &mut JNIEnv) {
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
    }
}

fn ip_octets(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}
