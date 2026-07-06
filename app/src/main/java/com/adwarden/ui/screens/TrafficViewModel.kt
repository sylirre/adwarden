package com.adwarden.ui.screens

import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adwarden.capture.HarExportManager
import com.adwarden.capture.PcapSessionManager
import com.adwarden.core.NativeSessionHolder
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
    sessionHolder: NativeSessionHolder,
) : ViewModel() {

    val capturing: StateFlow<Boolean> = pcap.capturing

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
