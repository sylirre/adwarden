// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package io.github.sylirre.adwarden.ui.screens

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.sylirre.adwarden.capture.HarExportManager
import io.github.sylirre.adwarden.capture.PcapSessionManager
import io.github.sylirre.adwarden.core.LiveLogState
import io.github.sylirre.adwarden.core.NativeSessionHolder
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import javax.inject.Inject

@HiltViewModel
class TrafficViewModel @Inject constructor(
    private val pcap: PcapSessionManager,
    private val har: HarExportManager,
    private val liveLog: LiveLogState,
    sessionHolder: NativeSessionHolder,
) : ViewModel() {

    val capturing: StateFlow<Boolean> = pcap.capturing

    // Holds at most one live-log screen-ref for this VM, so ON_START/ON_STOP and
    // the disposal fallback can each fire without double-counting (P3-4).
    private var held = false

    /** The Traffic screen became visible — demand full-fidelity telemetry. */
    fun onScreenActive() {
        if (!held) {
            held = true
            liveLog.acquireScreen()
        }
    }

    /** The Traffic screen is no longer visible (backgrounded or navigated away). */
    fun onScreenInactive() {
        if (held) {
            held = false
            liveLog.releaseScreen()
        }
    }

    override fun onCleared() {
        onScreenInactive()
        super.onCleared()
    }

    val running: StateFlow<Boolean> = sessionHolder.handleFlow
        .map { it != 0L }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), sessionHolder.isRunning)

    fun defaultFileName(): String = pcap.defaultFileName()

    fun startCapture(target: Uri) {
        pcap.start(target)
    }

    fun stopCapture() {
        pcap.stop()
    }

    fun defaultHarFileName(): String = har.defaultFileName()

    fun exportHar(target: Uri) {
        har.export(target)
    }
}
