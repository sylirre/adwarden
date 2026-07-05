package com.adwarden

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adwarden.data.CaptureRepository
import com.adwarden.data.settings.SettingsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    private val settings: SettingsRepository,
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
}
