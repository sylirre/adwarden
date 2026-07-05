//! Adwarden native core — the JNI surface loaded by the Android app as
//! `libadwarden_core.so`.
//!
//! Phase 0 skeleton: exposes only an ABI tag so the Gradle/cargo wiring can be
//! validated end to end. The datapath (TUN forwarding, DNS sinkhole, filter
//! engine, pcap tap) lands with P1-A..E.

use jni::objects::JClass;
use jni::sys::jint;
use jni::JNIEnv;

/// Bumped whenever the Kotlin<->Rust FFI contract changes shape.
pub const ABI_VERSION: i32 = 1;

#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeAbiVersion(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    ABI_VERSION
}
