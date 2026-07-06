package com.adwarden

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adwarden.data.CaRepository
import com.adwarden.data.CaptureRepository
import com.adwarden.data.settings.SettingsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    private val settings: SettingsRepository,
    private val ca: CaRepository,
    captureRepository: CaptureRepository,
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

    val blockEncryptedDns: StateFlow<Boolean> = settings.settings
        .map { it.blockEncryptedDns }
        .stateIn(viewModelScope, SharingStarted.Eagerly, initial.blockEncryptedDns)

    val interceptTls: StateFlow<Boolean> = settings.settings
        .map { it.interceptTls }
        .stateIn(viewModelScope, SharingStarted.Eagerly, initial.interceptTls)

    // The interception CA cert (PEM), loaded lazily when the install wizard opens.
    // Null until generated/loaded.
    private val _caCertPem = MutableStateFlow<String?>(null)
    val caCertPem: StateFlow<String?> = _caCertPem.asStateFlow()

    val stats = captureRepository.stats
    val events = captureRepository.events
    val running = captureRepository.running

    fun completeOnboarding() {
        viewModelScope.launch { settings.setOnboarded(true) }
    }

    fun setDynamicColor(value: Boolean) {
        viewModelScope.launch { settings.setDynamicColor(value) }
    }

    fun setBlockEncryptedDns(value: Boolean) {
        viewModelScope.launch { settings.setBlockEncryptedDns(value) }
    }

    fun setInterceptTls(value: Boolean) {
        viewModelScope.launch {
            settings.setInterceptTls(value)
            if (value) _caCertPem.value = ca.ensureCa()?.certPem
        }
    }

    /** Ensure the CA exists and publish its cert PEM for the install wizard. */
    fun prepareCaForInstall() {
        viewModelScope.launch { _caCertPem.value = ca.caCertPem() }
    }
}
