// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package io.github.sylirre.adwarden

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import io.github.sylirre.adwarden.data.CaRepository
import io.github.sylirre.adwarden.data.CaptureRepository
import io.github.sylirre.adwarden.data.StatsRepository
import io.github.sylirre.adwarden.data.settings.EncryptedDnsMode
import io.github.sylirre.adwarden.data.settings.SettingsRepository
import io.github.sylirre.adwarden.data.settings.ThemeMode
import io.github.sylirre.adwarden.firewall.AppInventory
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.time.LocalDate
import javax.inject.Inject

/** A ranked dashboard row: a display [label] and its [count]. */
data class RankedItem(val label: String, val count: Long)

@HiltViewModel
class MainViewModel @Inject constructor(
    private val settings: SettingsRepository,
    private val ca: CaRepository,
    captureRepository: CaptureRepository,
    statsRepository: StatsRepository,
    inventory: AppInventory,
) : ViewModel() {

    // Read the gate values once, synchronously, at construction. This mirrors the
    // P0 SharedPreferences.getBoolean call it replaces and avoids a flash of the
    // onboarding screen (or the wrong theme) before the DataStore flow emits.
    private val initial = runBlocking { settings.settings.first() }

    val onboarded: StateFlow<Boolean> = settings.settings
        .map { it.onboarded }
        .stateIn(viewModelScope, SharingStarted.Eagerly, initial.onboarded)

    val dynamicColor: StateFlow<Boolean> = settings.settings
        .map { it.dynamicColor }
        .stateIn(viewModelScope, SharingStarted.Eagerly, initial.dynamicColor)

    val themeMode: StateFlow<ThemeMode> = settings.settings
        .map { it.themeMode }
        .stateIn(viewModelScope, SharingStarted.Eagerly, initial.themeMode)

    val encryptedDnsMode: StateFlow<EncryptedDnsMode> = settings.settings
        .map { it.encryptedDnsMode }
        .stateIn(viewModelScope, SharingStarted.Eagerly, initial.encryptedDnsMode)

    val interceptTls: StateFlow<Boolean> = settings.settings
        .map { it.interceptTls }
        .stateIn(viewModelScope, SharingStarted.Eagerly, initial.interceptTls)

    val cosmeticElementHiding: StateFlow<Boolean> = settings.settings
        .map { it.cosmeticElementHiding }
        .stateIn(viewModelScope, SharingStarted.Eagerly, initial.cosmeticElementHiding)

    val cosmeticScriptlets: StateFlow<Boolean> = settings.settings
        .map { it.cosmeticScriptlets }
        .stateIn(viewModelScope, SharingStarted.Eagerly, initial.cosmeticScriptlets)

    // The interception CA cert (PEM), loaded lazily when the install wizard opens.
    // Null until generated/loaded.
    private val _caCertPem = MutableStateFlow<String?>(null)
    val caCertPem: StateFlow<String?> = _caCertPem.asStateFlow()

    val stats = captureRepository.stats
    val events = captureRepository.events
    val running = captureRepository.running

    // --- Persistent history (P3-3) ------------------------------------------
    // Window is resolved once at construction; a day-boundary crossing while the
    // screen stays open is corrected on the next open (acceptable staleness).
    private val weekStartDay = LocalDate.now().toEpochDay() - (HISTORY_DAYS - 1)

    private val history: StateFlow<List<io.github.sylirre.adwarden.data.db.DailyStat>> =
        statsRepository.dailyStatsSince(weekStartDay)
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    /** Blocked-per-day over the last [HISTORY_DAYS] days, oldest→newest, zero-filled. */
    val weekBlockedPerDay: StateFlow<List<Long>> = history
        .map { rows ->
            val byDay = rows.associateBy { it.dateEpochDay }
            (0 until HISTORY_DAYS).map { i -> byDay[weekStartDay + i]?.blocked ?: 0L }
        }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), List(HISTORY_DAYS) { 0L })

    val blockedToday: StateFlow<Long> = history
        .map { rows -> rows.find { it.dateEpochDay == weekStartDay + (HISTORY_DAYS - 1) }?.blocked ?: 0L }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0L)

    val blockedThisWeek: StateFlow<Long> = history
        .map { rows -> rows.sumOf { it.blocked } }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0L)

    val topBlockedDomains: StateFlow<List<RankedItem>> =
        statsRepository.topDomains(weekStartDay, TOP_LIMIT)
            .map { list -> list.map { RankedItem(it.key, it.count) } }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    // uid→label, resolved once (installed apps rarely change within a session).
    private val uidLabels: StateFlow<Map<Int, String>> =
        flow { emit(inventory.load().associate { it.uid to it.label }) }
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyMap())

    val topBlockedApps: StateFlow<List<RankedItem>> =
        combine(statsRepository.topApps(weekStartDay, TOP_LIMIT), uidLabels) { tallies, labels ->
            tallies.map { RankedItem(labels[it.key.toIntOrNull()] ?: "App ${it.key}", it.count) }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    fun completeOnboarding() {
        viewModelScope.launch { settings.setOnboarded(true) }
    }

    fun setDynamicColor(value: Boolean) {
        viewModelScope.launch { settings.setDynamicColor(value) }
    }

    fun setThemeMode(value: ThemeMode) {
        viewModelScope.launch { settings.setThemeMode(value) }
    }

    fun setEncryptedDnsMode(value: EncryptedDnsMode) {
        viewModelScope.launch { settings.setEncryptedDnsMode(value) }
    }

    fun setInterceptTls(value: Boolean) {
        viewModelScope.launch {
            settings.setInterceptTls(value)
            if (value) _caCertPem.value = ca.ensureCa()?.certPem
        }
    }

    fun setCosmeticElementHiding(value: Boolean) {
        viewModelScope.launch {
            settings.setCosmeticElementHiding(value)
            // Scriptlets are meaningless without element hiding — keep them
            // consistent so the native side never gets scriptlets-without-hiding.
            if (!value) settings.setCosmeticScriptlets(false)
        }
    }

    fun setCosmeticScriptlets(value: Boolean) {
        // The built-in scriptlet pack ships in the APK, so no download is needed;
        // the datapath already loads it. Injection is gated by this switch (P4-4).
        viewModelScope.launch { settings.setCosmeticScriptlets(value) }
    }

    /** Ensure the CA exists and publish its cert PEM for the install wizard. */
    fun prepareCaForInstall() {
        viewModelScope.launch { _caCertPem.value = ca.caCertPem() }
    }

    private companion object {
        const val HISTORY_DAYS = 7
        const val TOP_LIMIT = 5
    }
}
