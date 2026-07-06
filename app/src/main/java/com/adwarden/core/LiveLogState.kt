package com.adwarden.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Tracks whether anything is actively consuming live per-flow telemetry, so the
 * native datapath can drop into its coalescing battery fast-path when nothing is
 * (P3-4). [open] is true while the Traffic screen is on-screen **or** a pcap
 * capture is running — the two producers of a demand for full-fidelity events.
 *
 * The VPN service observes [open] and pushes it to the core via
 * `NativeCore.nativeSetLogOpen`. Screen presence is ref-counted (guarded against
 * underflow) so overlapping enter/exit callbacks can't wedge it; the capture flag
 * is a simple latch. This is a same-process singleton, mirroring
 * [NativeSessionHolder].
 */
@Singleton
class LiveLogState @Inject constructor() {

    private val lock = Any()
    private var screenRefs = 0
    private var capturing = false

    private val _open = MutableStateFlow(false)
    val open: StateFlow<Boolean> = _open.asStateFlow()

    /** The Traffic screen became visible. */
    fun acquireScreen() = synchronized(lock) {
        screenRefs++
        recompute()
    }

    /** The Traffic screen left the screen. Idempotent below zero. */
    fun releaseScreen() = synchronized(lock) {
        if (screenRefs > 0) screenRefs--
        recompute()
    }

    /** A pcap capture started (true) or ended (false). */
    fun setCapturing(on: Boolean) = synchronized(lock) {
        capturing = on
        recompute()
    }

    private fun recompute() {
        _open.value = screenRefs > 0 || capturing
    }
}
