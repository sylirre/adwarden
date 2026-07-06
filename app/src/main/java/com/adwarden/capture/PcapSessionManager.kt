package com.adwarden.capture

import android.content.Context
import android.net.Uri
import com.adwarden.core.LiveLogState
import com.adwarden.core.NativeCore
import com.adwarden.core.NativeSessionHolder
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Drives a pcapng capture session. The user picks a destination via SAF; we hand
 * the (detached) fd to the native core, which owns and closes it on stop.
 */
@Singleton
class PcapSessionManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val sessionHolder: NativeSessionHolder,
    private val liveLog: LiveLogState,
) {
    private val _capturing = MutableStateFlow(false)
    val capturing: StateFlow<Boolean> = _capturing.asStateFlow()

    /** Suggested filename for the SAF create-document intent. */
    fun defaultFileName(): String = "adwarden-${System.currentTimeMillis()}.pcapng"

    /**
     * Begin capturing to [target]. Returns false if the core isn't running or
     * the document can't be opened.
     */
    fun start(target: Uri, ringBytes: Long = 0L): Boolean {
        val handle = sessionHolder.handle
        if (handle == 0L) return false
        val pfd = runCatching { context.contentResolver.openFileDescriptor(target, "w") }
            .getOrNull() ?: return false
        // Ownership of the fd transfers to native; do not close pfd afterwards.
        val fd = pfd.detachFd()
        val ok = NativeCore.nativeStartPcap(handle, fd, ringBytes)
        _capturing.value = ok
        // A running capture needs full-fidelity events even if the Traffic screen
        // is backgrounded, so it holds the live-log signal open (P3-4).
        liveLog.setCapturing(ok)
        return ok
    }

    fun stop() {
        val handle = sessionHolder.handle
        if (handle != 0L) NativeCore.nativeStopPcap(handle)
        _capturing.value = false
        liveLog.setCapturing(false)
    }

    /** Called when protection stops so the UI reflects that capture ended. */
    fun onSessionEnded() {
        _capturing.value = false
        liveLog.setCapturing(false)
    }
}
