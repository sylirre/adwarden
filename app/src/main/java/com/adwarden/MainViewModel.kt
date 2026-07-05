package com.adwarden

import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import com.adwarden.data.CaptureRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    @ApplicationContext context: Context,
    captureRepository: CaptureRepository,
) : ViewModel() {

    private val prefs = context.getSharedPreferences("adwarden", 0)

    private val _onboarded = MutableStateFlow(prefs.getBoolean(KEY_ONBOARDED, false))
    val onboarded: StateFlow<Boolean> = _onboarded

    val stats = captureRepository.stats
    val events = captureRepository.events
    val running = captureRepository.running

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
