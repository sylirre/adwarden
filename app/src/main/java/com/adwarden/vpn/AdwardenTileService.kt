package com.adwarden.vpn

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.core.content.ContextCompat
import com.adwarden.MainActivity
import com.adwarden.R
import com.adwarden.core.NativeSessionHolder
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import javax.inject.Inject

/**
 * Quick Settings tile that mirrors and toggles protection (P3-5).
 *
 * The tile reflects the *actual* running state via [NativeSessionHolder] (a
 * same-process @Singleton the VPN service writes) rather than the persisted
 * intent, so it can never claim "on" while the tunnel is down. Toggling reuses
 * the service's [AdwardenVpnService.ACTION_START]/[AdwardenVpnService.ACTION_STOP]
 * intents. A tile can't host the `VpnService.prepare()` consent dialog, so when
 * consent is missing it bounces into [MainActivity], which owns the launcher.
 */
@AndroidEntryPoint
class AdwardenTileService : TileService() {

    @Inject lateinit var sessionHolder: NativeSessionHolder

    private var scope: CoroutineScope? = null

    override fun onStartListening() {
        super.onStartListening()
        // Keep the tile live while the shade is open.
        val s = CoroutineScope(Dispatchers.Main.immediate + SupervisorJob())
        scope = s
        s.launch {
            sessionHolder.handleFlow.collect { handle -> render(handle != 0L) }
        }
    }

    override fun onStopListening() {
        scope?.cancel()
        scope = null
        super.onStopListening()
    }

    override fun onClick() {
        super.onClick()
        if (sessionHolder.isRunning) {
            // Stopping is safe from a locked device.
            stopVpn()
            render(false)
        } else {
            // Starting may need the consent activity and an FGS start, so make
            // sure the device is unlocked first.
            val begin = Runnable { beginStart() }
            if (isLocked) unlockAndRun(begin) else begin.run()
        }
    }

    private fun beginStart() {
        val prepare = VpnService.prepare(this)
        if (prepare == null) {
            startVpn()
            render(true)
        } else {
            bounceForConsent()
        }
    }

    private fun render(active: Boolean) {
        val tile = qsTile ?: return
        tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.icon = Icon.createWithResource(this, R.drawable.ic_tile_shield)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = getString(
                if (active) R.string.tile_subtitle_on else R.string.tile_subtitle_off,
            )
        }
        tile.updateTile()
    }

    private fun startVpn() {
        val intent = Intent(this, AdwardenVpnService::class.java)
            .setAction(AdwardenVpnService.ACTION_START)
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopVpn() {
        startService(
            Intent(this, AdwardenVpnService::class.java)
                .setAction(AdwardenVpnService.ACTION_STOP),
        )
    }

    /** Collapse the shade and open the app to gather first-run VPN consent. */
    private fun bounceForConsent() {
        val intent = Intent(this, MainActivity::class.java)
            .setAction(MainActivity.ACTION_TOGGLE_PROTECTION)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            val pi = PendingIntent.getActivity(
                this,
                0,
                intent,
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            startActivityAndCollapse(pi)
        } else {
            @Suppress("DEPRECATION")
            startActivityAndCollapse(intent)
        }
    }

    companion object {
        /**
         * Ask the system to rebind and refresh the tile after protection changes
         * from elsewhere (the app UI, always-on). No-op if the tile isn't added.
         */
        fun requestUpdate(context: Context) {
            runCatching {
                requestListeningState(
                    context,
                    ComponentName(context, AdwardenTileService::class.java),
                )
            }
        }
    }
}
