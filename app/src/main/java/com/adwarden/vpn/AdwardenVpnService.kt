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
import com.adwarden.core.PacketDecoder
import com.adwarden.data.CaptureRepository
import dagger.hilt.android.AndroidEntryPoint
import java.io.FileInputStream
import java.io.IOException
import javax.inject.Inject

/**
 * P0 loopback VPN. It establishes a TUN device, captures every IP packet the
 * system routes into it and decodes headers for the live log / dashboard.
 *
 * P0 runs in **monitor mode**: packets are inspected but not yet forwarded, so
 * while it is active the tunnelled traffic is dropped. Transparent forwarding
 * (userspace TCP/IP + protected upstream sockets) arrives with the native core
 * in P1/P2. The service is structured so that seam is a single call site in the
 * capture loop.
 */
@AndroidEntryPoint
class AdwardenVpnService : VpnService() {

    @Inject lateinit var capture: CaptureRepository

    @Volatile private var running = false
    private var tunnel: ParcelFileDescriptor? = null
    private var worker: Thread? = null

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

        val fd = establishTunnel()
        if (fd == null) {
            stopEverything()
            stopSelf()
            return
        }
        tunnel = fd
        running = true
        capture.onStarted()
        worker = Thread({ captureLoop(fd) }, "adw-capture").apply {
            isDaemon = true
            start()
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

    private fun captureLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val packet = ByteArray(MTU + 64)
        try {
            while (running) {
                val n = input.read(packet)
                if (n < 0) break
                if (n == 0) continue
                val decoded = PacketDecoder.decode(packet, n)
                capture.onPacket(decoded, n)
                // P1/P2 forwarding seam: here the native core reinjects the packet
                // upstream via a protect()ed socket. In P0 monitor mode it is dropped.
            }
        } catch (_: IOException) {
            // Expected when the descriptor is closed on stop.
        } finally {
            runCatching { input.close() }
        }
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
        runCatching { tunnel?.close() }
        tunnel = null
        worker?.interrupt()
        worker = null
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
