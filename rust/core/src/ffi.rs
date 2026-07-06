//! JNI entry points (`Java_com_adwarden_core_NativeCore_*`).
//!
//! Every function wraps its body in `catch_unwind`: a Rust panic unwinding
//! across the FFI boundary is undefined behavior, so panics are converted to a
//! null/zero result instead.

use std::panic::{catch_unwind, AssertUnwindSafe};

use std::collections::HashMap;

use jni::objects::{JByteArray, JClass, JIntArray, JObject, JObjectArray, JString};
use jni::sys::{jboolean, jint, jlong, jobjectArray, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

use adwarden_filter::{FilterEngine, ListFormat};

use crate::bridge::Bridge;
use crate::config::Config;
use crate::forward::AppPolicy;
use crate::runtime::{Command, Session};

/// Borrow the session behind a handle without taking ownership.
unsafe fn session<'a>(handle: jlong) -> Option<&'a Session> {
    if handle == 0 {
        None
    } else {
        Some(&*(handle as *const Session))
    }
}

/// Bumped whenever the Kotlin<->Rust FFI contract changes shape.
/// v2: added `nativeGenerateCa` for TLS interception (P2).
/// v3: added `nativeExportHar` for HAR 1.2 export of decrypted flows (P2-3).
pub const ABI_VERSION: i32 = 3;

#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeAbiVersion(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    ABI_VERSION
}

/// Generate a fresh TLS-interception root CA. Returns a `String[2]` of
/// `[certPem, keyPem]`, or null on failure. Called once on first run (P2); Kotlin
/// persists the key app-privately and exports the cert for the install wizard.
#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeGenerateCa<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jobjectArray {
    let result = catch_unwind(AssertUnwindSafe(|| generate_ca(&mut env)));
    match result {
        Ok(Some(arr)) => arr,
        _ => std::ptr::null_mut(),
    }
}

fn generate_ca(env: &mut JNIEnv) -> Option<jobjectArray> {
    let ca = adwarden_tls::CertAuthority::generate().ok()?;
    let cert = env.new_string(ca.ca_cert_pem()).ok()?;
    let key = env.new_string(ca.ca_key_pem()).ok()?;
    let class = env.find_class("java/lang/String").ok()?;
    let arr = env.new_object_array(2, &class, JObject::null()).ok()?;
    env.set_object_array_element(&arr, 0, &cert).ok()?;
    env.set_object_array_element(&arr, 1, &key).ok()?;
    Some(arr.into_raw())
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
        crate::init_logging();
        let config_json: String = env
            .get_string(&config)
            .map(|s| s.into())
            .unwrap_or_default();
        crate::alog!("nativeStart: config={}", config_json);
        let config = Config::from_json(&config_json);
        let bridge = match Bridge::new(&mut env, &bridge) {
            Ok(b) => b,
            Err(e) => {
                crate::alog!("nativeStart: Bridge::new failed: {:?}", e);
                return None;
            }
        };
        match Session::start(bridge, tun_fd as std::os::fd::RawFd, config) {
            Ok(session) => Some(session),
            Err(e) => {
                crate::alog!("nativeStart: Session::start failed: {:?}", e);
                None
            }
        }
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

#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeUpdateFilter<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    engine_path: JString<'local>,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let path: String = env.get_string(&engine_path).map(|s| s.into()).unwrap_or_default();
        if let Some(session) = unsafe { session(handle) } {
            session.send(Command::LoadEngine(path));
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeUpdateConfig<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    config: JString<'local>,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let config_json: String = env.get_string(&config).map(|s| s.into()).unwrap_or_default();
        let parsed = Config::from_json(&config_json);
        if let Some(session) = unsafe { session(handle) } {
            session.send(Command::BlockEncryptedDns(parsed.block_encrypted_dns));
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeUpdateFirewall<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    rules: JByteArray<'local>,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let blob = env.convert_byte_array(&rules).unwrap_or_default();
        let parsed = parse_firewall(&blob);
        if let Some(session) = unsafe { session(handle) } {
            session.send(Command::UpdateFirewall(parsed));
        }
    }));
}

#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeUpdateNetwork(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    transport: jint,
    _metered: jboolean,
    _roaming: jboolean,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(session) = unsafe { session(handle) } {
            session.send(Command::SetTransport(transport as u8));
        }
    }));
}

/// Parse the firewall blob: u32 count, then per rule i32 uid + u8 wifi + u8 cell
/// + u8 inspect_tls (7 bytes/rule). Must match `AppRuleRepository.encodeBlob`.
fn parse_firewall(blob: &[u8]) -> HashMap<i32, AppPolicy> {
    let mut map = HashMap::new();
    if blob.len() < 4 {
        return map;
    }
    let count = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    let mut off = 4;
    for _ in 0..count {
        if off + 7 > blob.len() {
            break;
        }
        let uid = i32::from_le_bytes([blob[off], blob[off + 1], blob[off + 2], blob[off + 3]]);
        let allow_wifi = blob[off + 4] != 0;
        let allow_cellular = blob[off + 5] != 0;
        let inspect_tls = blob[off + 6] != 0;
        map.insert(uid, AppPolicy { allow_wifi, allow_cellular, inspect_tls });
        off += 7;
    }
    map
}

#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeStartPcap(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    fd: jint,
    ring_bytes: jlong,
) -> jboolean {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if let Some(session) = unsafe { session(handle) } {
            session.send(Command::StartPcap {
                fd: fd as std::os::fd::RawFd,
                ring_bytes: ring_bytes.max(0) as u64,
            });
            true
        } else {
            false
        }
    }));
    match result {
        Ok(true) => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeStopPcap(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(session) = unsafe { session(handle) } {
            session.send(Command::StopPcap);
        }
    }));
}

/// Export the decrypted HTTP transactions captured so far as a HAR 1.2 file to
/// an owned fd (P2-3). Returns true if the session accepted the request; the
/// write happens asynchronously on the datapath thread, which closes the fd.
#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeExportHar(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    fd: jint,
) -> jboolean {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if let Some(session) = unsafe { session(handle) } {
            session.send(Command::ExportHar { fd: fd as std::os::fd::RawFd });
            true
        } else {
            false
        }
    }));
    match result {
        Ok(true) => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

/// Compile a filter engine from downloaded list files + custom rules and write
/// the serialized cache to `out_path`. Runs off the datapath (called from the
/// WorkManager sync worker). Returns true on success.
#[no_mangle]
pub extern "system" fn Java_com_adwarden_core_NativeCore_nativeCompileEngine<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    list_paths: JObjectArray<'local>,
    formats: JIntArray<'local>,
    custom_rules: JObjectArray<'local>,
    out_path: JString<'local>,
) -> jboolean {
    let result = catch_unwind(AssertUnwindSafe(|| compile_engine(&mut env, list_paths, formats, custom_rules, out_path)));
    match result {
        Ok(true) => JNI_TRUE,
        _ => JNI_FALSE,
    }
}

fn compile_engine(
    env: &mut JNIEnv,
    list_paths: JObjectArray,
    formats: JIntArray,
    custom_rules: JObjectArray,
    out_path: JString,
) -> bool {
    let out: String = match env.get_string(&out_path) {
        Ok(s) => s.into(),
        Err(_) => return false,
    };

    let path_count = env.get_array_length(&list_paths).unwrap_or(0);
    let format_count = env.get_array_length(&formats).unwrap_or(0);
    if path_count != format_count {
        return false;
    }
    let mut format_codes = vec![0i32; path_count as usize];
    if path_count > 0 && env.get_int_array_region(&formats, 0, &mut format_codes).is_err() {
        return false;
    }

    // Read each list file into an owned String, then borrow for the engine.
    let mut sources: Vec<(ListFormat, String)> = Vec::with_capacity(path_count as usize);
    for i in 0..path_count {
        let Ok(elem) = env.get_object_array_element(&list_paths, i) else { continue };
        let path: String = match env.get_string(&JString::from(elem)) {
            Ok(s) => s.into(),
            Err(_) => continue,
        };
        if let Ok(text) = std::fs::read_to_string(&path) {
            let format = if format_codes[i as usize] == 1 { ListFormat::Hosts } else { ListFormat::Adblock };
            sources.push((format, text));
        }
    }

    let custom_count = env.get_array_length(&custom_rules).unwrap_or(0);
    let mut custom: Vec<String> = Vec::with_capacity(custom_count as usize);
    for i in 0..custom_count {
        let Ok(elem) = env.get_object_array_element(&custom_rules, i) else { continue };
        if let Ok(s) = env.get_string(&JString::from(elem)) {
            custom.push(s.into());
        }
    }

    let borrowed: Vec<(ListFormat, &str)> =
        sources.iter().map(|(fmt, text)| (*fmt, text.as_str())).collect();
    let engine = FilterEngine::from_lists(&borrowed, &custom);
    std::fs::write(&out, engine.serialize()).is_ok()
}
