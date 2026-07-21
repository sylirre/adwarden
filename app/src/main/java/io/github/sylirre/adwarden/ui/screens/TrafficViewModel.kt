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
import io.github.sylirre.adwarden.data.FilterRepository
import io.github.sylirre.adwarden.data.settings.SettingsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class TrafficViewModel @Inject constructor(
    private val pcap: PcapSessionManager,
    private val har: HarExportManager,
    private val liveLog: LiveLogState,
    private val settings: SettingsRepository,
    private val filter: FilterRepository,
    sessionHolder: NativeSessionHolder,
) : ViewModel() {

    val capturing: StateFlow<Boolean> = pcap.capturing

    /** Whether live traffic monitoring is enabled (persisted, default off). Drives
     *  both what the screen renders and whether we demand full-fidelity telemetry.
     *  It is purely a display/telemetry preference — filtering is never gated on it. */
    val liveTrafficEnabled: StateFlow<Boolean> = settings.settings
        .map { it.liveTrafficMonitoring }
        .stateIn(viewModelScope, SharingStarted.Eagerly, false)

    // The live-log screen ref is held iff the screen is visible AND monitoring is
    // enabled, so turning the switch off (or leaving the screen) lets the core drop
    // into its coalescing battery fast-path (P3-4). Both inputs are updated on the
    // main thread; `held` guards against a double acquire/release.
    private var screenVisible = false
    private var held = false

    init {
        liveTrafficEnabled.onEach { syncLiveLog() }.launchIn(viewModelScope)
    }

    /** The Traffic screen became visible. */
    fun onScreenActive() {
        screenVisible = true
        syncLiveLog()
    }

    /** The Traffic screen is no longer visible (backgrounded or navigated away). */
    fun onScreenInactive() {
        screenVisible = false
        syncLiveLog()
    }

    private fun syncLiveLog() {
        val want = screenVisible && liveTrafficEnabled.value
        if (want && !held) {
            held = true
            liveLog.acquireScreen()
        } else if (!want && held) {
            held = false
            liveLog.releaseScreen()
        }
    }

    fun setLiveTrafficEnabled(value: Boolean) {
        viewModelScope.launch { settings.setLiveTrafficMonitoring(value) }
    }

    /**
     * Add a user filter rule blocking [host] (and its subdomains) and trigger the
     * engine recompile + hot-reload. Mirrors the Filters screen's custom-rule add
     * ([FilterRepository.addCustomRule]); the rule goes live within a moment.
     */
    fun blockHost(host: String) {
        val normalized = normalizeHost(host)
        if (normalized.isEmpty()) return
        viewModelScope.launch { filter.addCustomRule("||$normalized^") }
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

    private fun normalizeHost(raw: String): String =
        raw.trim().lowercase().substringBefore('/').substringBefore(':').trimEnd('.')
}
