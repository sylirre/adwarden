//! The upcall surface into Kotlin (`NativeBridge`).
//!
//! Holds a `JavaVM` plus a global reference to the Kotlin `NativeBridge`
//! instance. The datapath thread attaches to the JVM once (as a daemon) and
//! reuses its `JNIEnv`. For now only `onEvents` is wired; `protect` and
//! `lookupUid` (hot-path, so their method IDs will be cached) arrive with P1-A
//! and P1-D.

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
        if env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
    }
}
