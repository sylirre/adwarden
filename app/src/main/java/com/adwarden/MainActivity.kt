package com.adwarden

import android.Manifest
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.windowsizeclass.ExperimentalMaterial3WindowSizeClassApi
import androidx.compose.material3.windowsizeclass.calculateWindowSizeClass
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adwarden.data.settings.ThemeMode
import com.adwarden.ui.AdwardenRoot
import com.adwarden.ui.theme.AdwardenTheme
import com.adwarden.vpn.AdwardenVpnService
import dagger.hilt.android.AndroidEntryPoint

// Scrims applied behind the 3-button navigation bar so its icons stay legible on
// content of any color (gesture nav is fully transparent). Values from the AOSP
// edge-to-edge guidance.
private val LIGHT_SCRIM = android.graphics.Color.argb(0xe6, 0xff, 0xff, 0xff)
private val DARK_SCRIM = android.graphics.Color.argb(0x80, 0x1b, 0x1b, 0x1b)

@AndroidEntryPoint
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

    @OptIn(ExperimentalMaterial3WindowSizeClassApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // Permission priming now lives in the onboarding wizard (P3-6); the
        // notification request survives here only as a fallback on the toggle path.
        // A fresh launch from the QS tile (consent needed) carries this action.
        if (savedInstanceState == null) handleTileAction(intent)

        setContent {
            val dynamicColor by viewModel.dynamicColor.collectAsStateWithLifecycle()
            val themeMode by viewModel.themeMode.collectAsStateWithLifecycle()
            val darkTheme = when (themeMode) {
                ThemeMode.SYSTEM -> isSystemInDarkTheme()
                ThemeMode.LIGHT -> false
                ThemeMode.DARK -> true
            }
            val windowSizeClass = calculateWindowSizeClass(this)

            // Re-apply edge-to-edge whenever the resolved theme flips so the
            // system-bar icons stay legible even when the user forces Light/Dark
            // against the system setting (a static values-night theme can't).
            DisposableEffect(darkTheme) {
                enableEdgeToEdge(
                    statusBarStyle = SystemBarStyle.auto(
                        android.graphics.Color.TRANSPARENT,
                        android.graphics.Color.TRANSPARENT,
                    ) { darkTheme },
                    navigationBarStyle = SystemBarStyle.auto(LIGHT_SCRIM, DARK_SCRIM) { darkTheme },
                )
                onDispose {}
            }

            AdwardenTheme(darkTheme = darkTheme, dynamicColor = dynamicColor) {
                AdwardenRoot(
                    viewModel = viewModel,
                    onToggleProtection = ::toggleProtection,
                    widthSizeClass = windowSizeClass.widthSizeClass,
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleTileAction(intent)
    }

    /**
     * The QS tile bounces here when protection can't start without the
     * `VpnService.prepare()` consent dialog it can't show itself (P3-5). Run the
     * normal toggle, which drives the consent launcher, then consume the action so
     * a later recreate can't re-fire it.
     */
    private fun handleTileAction(intent: Intent?) {
        if (intent?.action != ACTION_TOGGLE_PROTECTION) return
        intent.action = null
        toggleProtection()
    }

    private fun toggleProtection() {
        if (viewModel.running.value) {
            stopVpn()
        } else {
            val prepare = VpnService.prepare(this)
            if (prepare != null) vpnConsent.launch(prepare) else startVpn()
        }
    }

    private fun startVpn() {
        // Fallback priming for users who skipped the onboarding notification step:
        // ask in-context as protection starts. A no-op once already granted.
        maybeRequestNotifications()
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

    companion object {
        /** Sent by the QS tile when starting protection needs the consent dialog. */
        const val ACTION_TOGGLE_PROTECTION = "com.adwarden.action.TOGGLE_PROTECTION"
    }
}
