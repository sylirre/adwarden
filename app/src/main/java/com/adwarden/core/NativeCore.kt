package com.adwarden.core

/**
 * JNI facade for the Rust native core (`libadwarden_core.so`).
 *
 * The library owns the TUN fd once [nativeStart] is called with a detached
 * descriptor, and closes it in [nativeStop]. The returned handle is an opaque
 * pointer to the native session; treat 0 as failure.
 */
object NativeCore {

    @Volatile private var loaded = false

    /** Load the native library. Safe to call repeatedly. */
    fun ensureLoaded(): Boolean {
        if (loaded) return true
        return try {
            System.loadLibrary("adwarden_core")
            loaded = true
            true
        } catch (_: UnsatisfiedLinkError) {
            false
        }
    }

    external fun nativeAbiVersion(): Int

    /** Hand the TUN fd + config JSON to the core. Returns an opaque handle (0 = failure). */
    external fun nativeStart(tunFd: Int, configJson: String, bridge: NativeBridge): Long

    /** Stop the session; the core closes the TUN fd it owns. */
    external fun nativeStop(handle: Long)

    /** Point the core at a freshly compiled, serialized filter-engine cache file. */
    external fun nativeUpdateFilter(handle: Long, engineCachePath: String)

    /** Push updated runtime config (e.g. the block-encrypted-DNS toggle) as JSON. */
    external fun nativeUpdateConfig(handle: Long, configJson: String)
}
