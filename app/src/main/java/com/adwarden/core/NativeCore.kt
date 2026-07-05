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

    /**
     * Compile a filter engine from downloaded list files (with per-list format
     * codes: 0 = adblock, 1 = hosts) plus custom rules, writing the serialized
     * cache to [outPath]. Returns true on success. Safe to call off the datapath.
     */
    external fun nativeCompileEngine(
        listPaths: Array<String>,
        formats: IntArray,
        customRules: Array<String>,
        outPath: String,
    ): Boolean

    /** Push per-app firewall rules: u32 count, then [i32 uid, u8 wifi, u8 cell] each (LE). */
    external fun nativeUpdateFirewall(handle: Long, rulesBlob: ByteArray)

    /** Report the current network transport (0 other / 1 wifi / 2 cellular). */
    external fun nativeUpdateNetwork(handle: Long, transport: Int, metered: Boolean, roaming: Boolean)

    /** Start a pcapng capture to an owned fd (ringBytes 0 = unbounded). Returns true if accepted. */
    external fun nativeStartPcap(handle: Long, fd: Int, ringBytes: Long): Boolean

    /** Stop the active capture and close its file. */
    external fun nativeStopPcap(handle: Long)
}
