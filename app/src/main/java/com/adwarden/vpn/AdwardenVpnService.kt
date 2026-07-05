package com.adwarden.vpn

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.adwarden.AdwardenApp
import com.adwarden.MainActivity
import com.adwarden.R
import com.adwarden.core.NativeBridge
import com.adwarden.core.NativeCore
import com.adwarden.data.AppRuleRepository
import com.adwarden.data.CaptureRepository
import com.adwarden.data.FilterRepository
import com.adwarden.data.settings.SettingsRepository
import com.adwarden.firewall.NetworkStateMonitor
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import javax.inject.Inject

/**
 * Loopback VPN. Establishes a TUN device and hands its file descriptor to the
 * Rust native core, which decodes, filters and forwards traffic on its own
 * thread.
 *
 * In this milestone the core runs in monitor parity — it decodes packets into
 * the live log but still drops them (no forwarding yet). Transparent forwarding
 * arrives with P1-A at the seam inside the native runtime.
 */
@AndroidEntryPoint
class AdwardenVpnService : VpnService() {

    @Inject lateinit var capture: CaptureRepository
    @Inject lateinit var settings: SettingsRepository
    @Inject lateinit var filters: FilterRepository
    @Inject lateinit var appRules: AppRuleRepository
    @Inject lateinit var networkMonitor: NetworkStateMonitor

    @Volatile private var running = false
    private var nativeHandle: Long = 0L
    private var serviceScope: CoroutineScope? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                stopEverything()
                stopSelf()
                START_NOT_STICKY
            }
            else -> {
                startCapture()
                START_STICKY
            }
        }
    }

    private fun startCapture() {
        if (running) return
        // Keep the foreground promise first: the caller used startForegroundService().
        startForegroundCompat()

        if (!NativeCore.ensureLoaded()) {
            Log.e("Adwarden", "Native core failed to load")
            stopEverything()
            stopSelf()
            return
        }

        val fd = establishTunnel()
        if (fd == null) {
            stopEverything()
            stopSelf()
            return
        }

        // Ownership of the descriptor transfers to the native core, which closes
        // it on nativeStop. We must not touch it after detachFd().
        val rawFd = fd.detachFd()
        val connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val bridge = NativeBridge(
            capture = capture,
            connectivity = connectivity,
            protector = { socketFd -> protect(socketFd) },
        )
        val handle = NativeCore.nativeStart(rawFd, buildConfigJson(), bridge)
        if (handle == 0L) {
            Log.e("Adwarden", "Native core failed to start")
            stopEverything()
            stopSelf()
            return
        }

        nativeHandle = handle
        running = true
        capture.onStarted()
        startObservers()
    }

    private fun startObservers() {
        val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
        serviceScope = scope

        // Push the block-encrypted-DNS toggle to the core on change.
        scope.launch {
            settings.settings
                .map { it.blockEncryptedDns }
                .distinctUntilChanged()
                .collect { block ->
                    val handle = nativeHandle
                    if (handle != 0L) {
                        NativeCore.nativeUpdateConfig(
                            handle,
                            JSONObject().put("block_encrypted_dns", block).toString(),
                        )
                    }
                }
        }

        // Load any existing engine cache immediately, reload on recompile, and
        // kick off a sync (download-if-missing) so blocking is available.
        if (filters.hasCompiledEngine()) {
            NativeCore.nativeUpdateFilter(nativeHandle, filters.engineCacheFile.absolutePath)
        }
        filters.scheduleSync(expedited = !filters.hasCompiledEngine())
        scope.launch {
            filters.engineVersion
                .drop(1)
                .collect {
                    val handle = nativeHandle
                    if (handle != 0L && filters.hasCompiledEngine()) {
                        NativeCore.nativeUpdateFilter(handle, filters.engineCacheFile.absolutePath)
                    }
                }
        }

        // Push per-app firewall rules whenever they change.
        scope.launch {
            appRules.rules.collect { rules ->
                val handle = nativeHandle
                if (handle != 0L) {
                    NativeCore.nativeUpdateFirewall(handle, appRules.encodeBlob(rules))
                }
            }
        }

        // Track the active transport so per-network rules apply correctly.
        scope.launch {
            networkMonitor.state.collect { networkState ->
                val handle = nativeHandle
                if (handle != 0L) {
                    NativeCore.nativeUpdateNetwork(
                        handle,
                        networkState.transport,
                        networkState.metered,
                        networkState.roaming,
                    )
                }
            }
        }
    }

    private fun establishTunnel(): ParcelFileDescriptor? {
        return try {
            val builder = Builder()
                .setSession("Adwarden")
                .setMtu(MTU)
                .addAddress("10.215.173.2", 32)
                .addRoute("0.0.0.0", 0)
                .addAddress("fd00:aced:1::2", 128)
                .addRoute("::", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("2606:4700:4700::1111")
            // Never tunnel ourselves — avoids a capture feedback loop.
            runCatching { builder.addDisallowedApplication(packageName) }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
            builder.establish()
        } catch (e: Exception) {
            Log.e("Adwarden", "Failed to establish tunnel", e)
            null
        }
    }

    private fun buildConfigJson(): String {
        // One-time synchronous read of the current toggle at startup; live
        // changes are pushed by observeSettings().
        val blockEncryptedDns = runBlocking { settings.settings.first().blockEncryptedDns }
        return JSONObject().apply {
            put("mtu", MTU)
            put("block_encrypted_dns", blockEncryptedDns)
            put("dns_servers", JSONArray(listOf("1.1.1.1", "2606:4700:4700::1111")))
        }.toString()
    }

    private fun startForegroundCompat() {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val notification = NotificationCompat.Builder(this, AdwardenApp.CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.vpn_notification_title))
            .setContentText(getString(R.string.vpn_notification_text))
            .setContentIntent(open)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIF_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }

    private fun stopEverything() {
        running = false
        serviceScope?.cancel()
        serviceScope = null
        if (nativeHandle != 0L) {
            NativeCore.nativeStop(nativeHandle)
            nativeHandle = 0L
        }
        capture.onStopped()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    override fun onRevoke() {
        stopEverything()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopEverything()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "com.adwarden.vpn.action.START"
        const val ACTION_STOP = "com.adwarden.vpn.action.STOP"
        private const val NOTIF_ID = 1001
        private const val MTU = 1500
    }
}
