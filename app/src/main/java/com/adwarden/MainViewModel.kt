package com.adwarden

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import com.adwarden.core.CaptureState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

class MainViewModel(app: Application) : AndroidViewModel(app) {

    private val prefs = app.getSharedPreferences("adwarden", 0)

    private val _onboarded = MutableStateFlow(prefs.getBoolean(KEY_ONBOARDED, false))
    val onboarded: StateFlow<Boolean> = _onboarded

    val stats = CaptureState.stats
    val events = CaptureState.events
    val running = CaptureState.running

    /** Appearance preference; in-memory for P0, moves to DataStore later. */
    var dynamicColor by mutableStateOf(false)

    fun completeOnboarding() {
        prefs.edit().putBoolean(KEY_ONBOARDED, true).apply()
        _onboarded.value = true
    }

    private companion object {
        const val KEY_ONBOARDED = "onboarded"
    }
}
