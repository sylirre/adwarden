package com.adwarden.core

import androidx.annotation.Keep
import com.adwarden.data.CaptureRepository

/**
 * Upcall target the native core holds a global reference to. Methods are called
 * from the core's datapath thread, so they must be cheap and thread-safe.
 *
 * `@Keep` and the explicit signatures are load-bearing: the Rust side resolves
 * these by name/descriptor via JNI.
 *
 * @param protector wraps `VpnService.protect(fd)` so upstream sockets bypass the
 *   tunnel; supplied by the service so this class stays unit-testable.
 */
class NativeBridge(
    private val capture: CaptureRepository,
    private val protector: (Int) -> Boolean,
) {
    /** Receive an encoded event batch and fan it into the capture repository. */
    @Keep
    fun onEvents(batch: ByteArray) {
        capture.onEvents(NativeEventCodec.decode(batch))
    }

    /** Protect an upstream socket fd so its traffic bypasses the VPN. */
    @Keep
    fun protect(fd: Int): Boolean = protector(fd)
}
