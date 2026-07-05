package com.adwarden

import android.Manifest
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.core.content.ContextCompat
import com.adwarden.core.CaptureState
import com.adwarden.ui.AdwardenRoot
import com.adwarden.ui.theme.AdwardenTheme
import com.adwarden.vpn.AdwardenVpnService

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    private val vpnConsent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == RESULT_OK) startVpn()
    }

    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* best-effort; capture works regardless */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        maybeRequestNotifications()

        setContent {
            AdwardenTheme(dynamicColor = viewModel.dynamicColor) {
                AdwardenRoot(
                    viewModel = viewModel,
                    onToggleProtection = ::toggleProtection,
                )
            }
        }
    }

    private fun toggleProtection() {
        if (CaptureState.running.value) {
            stopVpn()
        } else {
            val prepare = VpnService.prepare(this)
            if (prepare != null) vpnConsent.launch(prepare) else startVpn()
        }
    }

    private fun startVpn() {
        val intent = Intent(this, AdwardenVpnService::class.java)
            .setAction(AdwardenVpnService.ACTION_START)
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopVpn() {
        val intent = Intent(this, AdwardenVpnService::class.java)
            .setAction(AdwardenVpnService.ACTION_STOP)
        startService(intent)
    }

    private fun maybeRequestNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
}
