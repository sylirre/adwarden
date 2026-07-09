// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package io.github.sylirre.adwarden.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Shares the running core's opaque session handle so UI-driven actions (e.g. a
 * pcap capture started from the Traffic screen) can reach the datapath without a
 * bound-service dance. The VPN service is the sole writer.
 */
@Singleton
class NativeSessionHolder @Inject constructor() {

    private val _handle = MutableStateFlow(0L)
    val handleFlow: StateFlow<Long> = _handle.asStateFlow()

    val handle: Long get() = _handle.value
    val isRunning: Boolean get() = _handle.value != 0L

    fun set(handle: Long) {
        _handle.value = handle
    }

    fun clear() {
        _handle.value = 0L
    }
}
