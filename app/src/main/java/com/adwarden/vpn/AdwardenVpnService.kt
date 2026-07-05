package com.adwarden.vpn

import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
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
import com.adwarden.data.CaptureRepository
import dagger.hilt.android.AndroidEntryPoint
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

    @Volatile private var running = false
    private var nativeHandle: Long = 0L

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
        val bridge = NativeBridge(capture)
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

    private fun buildConfigJson(): String = JSONObject().apply {
        put("mtu", MTU)
        put("block_encrypted_dns", false)
        put("dns_servers", JSONArray(listOf("1.1.1.1", "2606:4700:4700::1111")))
    }.toString()

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
