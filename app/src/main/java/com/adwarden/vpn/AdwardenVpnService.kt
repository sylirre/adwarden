package com.adwarden.vpn

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.adwarden.AdwardenApp
import com.adwarden.MainActivity
import com.adwarden.R
import com.adwarden.core.NativeBridge
import com.adwarden.core.NativeCore
import com.adwarden.core.NativeSessionHolder
import com.adwarden.data.AppRuleRepository
import com.adwarden.data.CaMaterial
import com.adwarden.data.CaptureRepository
import com.adwarden.data.CaRepository
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
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.net.Inet6Address
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
    @Inject lateinit var ca: CaRepository
    @Inject lateinit var networkMonitor: NetworkStateMonitor
    @Inject lateinit var sessionHolder: NativeSessionHolder

    @Volatile private var running = false
    private var nativeHandle: Long = 0L
    private var serviceScope: CoroutineScope? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private var underlyingCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var currentUnderlying: Network? = null

    // Whether the live tunnel currently advertises IPv6. Toggled by re-establish
    // when the underlay's working-v6 status changes. Serialized by [v6Mutex].
    @Volatile private var tunnelHasV6 = false
    private val v6Mutex = Mutex()

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
            Log.e(TAG, "Native core .so failed to load")
            stopEverything()
            stopSelf()
            return
        }
        Log.i(TAG, "Native core loaded (abi=${runCatching { NativeCore.nativeAbiVersion() }.getOrDefault(-1)})")

        // Advertise IPv6 from the start only if the current underlay carries
        // working global v6; otherwise the callback reconciles it later.
        val initialV6 = runCatching { activeUnderlayHasGlobalV6() }.getOrDefault(false)
        val fd = establishTunnel(includeIpv6 = initialV6)
        if (fd == null) {
            Log.e(TAG, "establishTunnel returned null")
            stopEverything()
            stopSelf()
            return
        }
        Log.i(TAG, "TUN established (v6=$initialV6)")

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
        Log.i(TAG, "nativeStart returned handle=$handle")
        if (handle == 0L) {
            Log.e(TAG, "Native core failed to start; closing leaked TUN fd $rawFd")
            // The core did not take ownership — close the detached fd so the
            // tunnel tears down instead of black-holing.
            runCatching { ParcelFileDescriptor.adoptFd(rawFd).close() }
            stopEverything()
            stopSelf()
            return
        }

        nativeHandle = handle
        sessionHolder.set(handle)
        running = true
        tunnelHasV6 = initialV6
        capture.onStarted()
        // Observers create serviceScope, which reconcileV6 launches onto — start
        // them before registering the callback that can trigger a reconcile.
        startObservers()
        registerUnderlyingNetworkTracking()
        Log.i(TAG, "Capture started")
    }

    /**
     * Tell the system which physical network carries the tunnel, so metering,
     * bandwidth attribution, and capability propagation track the real underlay —
     * and keep it current as the device roams between Wi-Fi and cellular.
     *
     * We track the single best non-VPN internet network via
     * [ConnectivityManager.registerBestMatchingNetworkCallback] (API 30+). The
     * NOT_VPN capability keeps us from ever selecting our own tunnel as its own
     * underlay. `onAvailable` fires immediately with the current best network, so
     * this also covers the initial application at start.
     */
    private fun registerUnderlyingNetworkTracking() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                currentUnderlying = network
                applyUnderlying(arrayOf(network))
                scheduleV6Reconcile()
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                // A global v6 address often arrives shortly AFTER onAvailable
                // (SLAAC), and can also disappear — re-evaluate the tunnel's v6.
                if (network == currentUnderlying) scheduleV6Reconcile()
            }

            override fun onLost(network: Network) {
                // Only clear if the network we're actually using went away — a
                // stale onLost for the previous network can arrive after
                // onAvailable for the new best one during a transport switch.
                if (network == currentUnderlying) {
                    currentUnderlying = null
                    applyUnderlying(null)
                }
            }
        }
        underlyingCallback = callback
        try {
            cm.registerBestMatchingNetworkCallback(request, callback, mainHandler)
        } catch (e: Exception) {
            Log.e(TAG, "registerBestMatchingNetworkCallback failed", e)
            underlyingCallback = null
        }
    }

    private fun applyUnderlying(networks: Array<Network>?) {
        try {
            setUnderlyingNetworks(networks)
            Log.i(TAG, "setUnderlyingNetworks -> ${networks?.joinToString()}")
        } catch (e: Exception) {
            Log.e(TAG, "setUnderlyingNetworks failed", e)
        }
    }

    private fun unregisterUnderlyingNetworkTracking() {
        val callback = underlyingCallback ?: return
        underlyingCallback = null
        currentUnderlying = null
        runCatching {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.unregisterNetworkCallback(callback)
        }
    }

    /**
     * IPv6 egress is gated on the underlay actually carrying working global v6.
     * When that changes (roaming, SLAAC completing, v6 dropping), re-establish the
     * tunnel to add or remove the v6 address/route. Serialized via [v6Mutex] so
     * overlapping network events collapse to the final desired state.
     */
    private fun scheduleV6Reconcile() {
        val scope = serviceScope ?: return
        scope.launch { v6Mutex.withLock { reconcileV6() } }
    }

    private suspend fun reconcileV6() {
        if (!running) return
        val underlay = currentUnderlying
        val desired = underlay != null && networkHasGlobalV6(underlay)
        if (desired == tunnelHasV6) return
        Log.i(TAG, "Underlay IPv6 availability changed -> re-establishing (v6=$desired)")
        reestablishTunnel(desired)
    }

    /**
     * Stop the native session, rebuild the TUN with/without v6, restart the core,
     * and re-push the filter/firewall/network state the running observers won't
     * re-emit. A network switch breaks every in-flight upstream socket anyway, so
     * dropping and rebuilding the session here is the clean, safe path.
     */
    private suspend fun reestablishTunnel(withV6: Boolean) {
        val old = nativeHandle
        if (old != 0L) NativeCore.nativeStop(old)
        nativeHandle = 0L
        sessionHolder.clear()

        val fd = establishTunnel(includeIpv6 = withV6)
        if (fd == null) {
            Log.e(TAG, "Re-establish failed to build tunnel; stopping")
            stopEverything(); stopSelf(); return
        }
        val rawFd = fd.detachFd()
        val connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val bridge = NativeBridge(
            capture = capture,
            connectivity = connectivity,
            protector = { socketFd -> protect(socketFd) },
        )
        val handle = NativeCore.nativeStart(rawFd, buildConfigJson(), bridge)
        if (handle == 0L) {
            Log.e(TAG, "Re-establish nativeStart failed; closing fd and stopping")
            runCatching { ParcelFileDescriptor.adoptFd(rawFd).close() }
            stopEverything(); stopSelf(); return
        }
        nativeHandle = handle
        sessionHolder.set(handle)
        tunnelHasV6 = withV6
        applyUnderlying(currentUnderlying?.let { arrayOf(it) })
        reapplyNativeState(handle)
        Log.i(TAG, "Tunnel re-established (v6=$withV6, handle=$handle)")
    }

    /** Re-push state a fresh native session doesn't carry from its start config. */
    private suspend fun reapplyNativeState(handle: Long) {
        if (filters.hasCompiledEngine()) {
            NativeCore.nativeUpdateFilter(handle, filters.engineCacheFile.absolutePath)
        }
        NativeCore.nativeUpdateFirewall(handle, appRules.encodeBlob(appRules.rules.first()))
        val net = networkMonitor.state.first()
        NativeCore.nativeUpdateNetwork(handle, net.transport, net.metered, net.roaming)
    }

    private fun activeUnderlayHasGlobalV6(): Boolean {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val net = cm.activeNetwork ?: return false
        return networkHasGlobalV6(net)
    }

    /**
     * True when [network] carries working global IPv6: it has a global-unicast
     * (2000::/3) source address AND a default v6 route. Requiring both avoids the
     * "addressed but unrouted" false positive that would resurrect the SYN-retry
     * storm the IPv4-only tunnel was built to dodge.
     */
    private fun networkHasGlobalV6(network: Network): Boolean {
        val lp = runCatching {
            (getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager)
                .getLinkProperties(network)
        }.getOrNull() ?: return false
        val hasGlobalAddr = lp.linkAddresses.any { la ->
            val a = la.address
            a is Inet6Address && !a.isLoopbackAddress && !a.isLinkLocalAddress &&
                !a.isMulticastAddress && (a.address[0].toInt() and 0xE0) == 0x20
        }
        val hasDefaultV6Route = lp.routes.any { r ->
            r.isDefaultRoute && r.destination.address is Inet6Address
        }
        return hasGlobalAddr && hasDefaultV6Route
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

    /**
     * Build the TUN. IPv4 is always advertised; IPv6 is added only when
     * [includeIpv6] is true — i.e. only when the underlay has working global v6
     * ([networkHasGlobalV6]).
     *
     * Why gate v6: advertising a v6 address/route makes apps do AAAA lookups and
     * prefer IPv6 (Happy Eyeballs), pushing v6 flows into the tunnel. When the
     * underlay has no working v6 (common on mobile data and many Wi-Fi nets), our
     * protect()ed upstream v6 sockets can't connect (ENETUNREACH) and every
     * v6-preferred connection stalls into a SYN-retry storm. So we advertise v6
     * only when the underlay carries it and re-establish the moment that flips
     * ([reconcileV6]). With v6 off, apps use IPv4, which egresses fine.
     */
    private fun establishTunnel(includeIpv6: Boolean): ParcelFileDescriptor? {
        return try {
            val builder = Builder()
                .setSession("Adwarden")
                .setMtu(MTU)
                .addAddress("10.215.173.2", 32)
                // Advertise a tunnel-local placeholder resolver (the gateway), NOT
                // a real public DoH provider like 1.1.1.1 — otherwise Chrome's
                // "Automatic" secure DNS recognizes the provider and upgrades to
                // DoH, bypassing our filtering. The core intercepts these
                // plaintext queries and forwards them to the real upstream
                // (config "dns_servers"). A v4 resolver serves AAAA records fine,
                // so no v6 resolver is needed even when v6 egress is on.
                .addDnsServer(DNS_PLACEHOLDER_V4)
                // Let VPN-aware apps explicitly bind to other networks; an
                // ad-blocker shouldn't be a captive tunnel.
                .allowBypass()
            // Route all IPv4 into the tunnel EXCEPT the private LAN ranges, so
            // LAN traffic (router UI, printers, NAS, casting) keeps flowing
            // direct — the same default NetGuard and RethinkDNS ship.
            addRoutesExceptLan(builder)
            if (includeIpv6) {
                // App-side v6 address, peer of the core gateway fd00:aced:1::1 in
                // the same /64. Route only global-unicast v6 (2000::/3) into the
                // tunnel; link-local/ULA/multicast stay direct (the v6 analog of
                // the RFC1918 carve-out).
                builder.addAddress(V6_TUN_ADDR, 128)
                builder.addRoute("2000::", 3)
            }
            // Never tunnel ourselves — avoids a capture feedback loop.
            runCatching { builder.addDisallowedApplication(packageName) }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
            builder.establish()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish tunnel", e)
            null
        }
    }

    /**
     * Add IPv4 routes covering 0.0.0.0/0 minus all three RFC1918 private ranges
     * (10/8, 172.16/12, 192.168/16) and multicast/reserved (224/3), so LAN and
     * multicast traffic stays off the tunnel (matching NetGuard/RethinkDNS).
     *
     * The tunnel-local DNS placeholder [DNS_PLACEHOLDER_V4] sits inside the
     * excluded 10/8, so it is carved back IN with a /32 route: longest-prefix
     * routing then sends only that one address through the tunnel, leaving DNS
     * sinkholing intact while the rest of 10/8 flows direct.
     */
    private fun addRoutesExceptLan(builder: Builder) {
        TunRoutes.complementRoutes(EXCLUDED_ROUTES).forEach { route ->
            builder.addRoute(route.address, route.prefixLength)
        }
        builder.addRoute(DNS_PLACEHOLDER_V4, 32)
    }

    private fun buildConfigJson(): String {
        // One-time synchronous read of current settings at startup. block-DNS
        // changes are pushed live by observeSettings(); TLS interception is a
        // start-time setting (the native factory is built at session start), so
        // toggling it takes effect on the next VPN start / re-establish.
        data class Cfg(val block: Boolean, val material: CaMaterial?, val requested: Boolean)
        val cfg = runBlocking {
            val s = settings.settings.first()
            Cfg(s.blockEncryptedDns, if (s.interceptTls) ca.ensureCa() else null, s.interceptTls)
        }
        if (cfg.requested && cfg.material == null) {
            Log.w(TAG, "TLS interception enabled but CA unavailable; starting without it")
        }
        return JSONObject().apply {
            put("mtu", MTU)
            put("block_encrypted_dns", cfg.block)
            put("dns_servers", JSONArray(UPSTREAM_DNS))
            cfg.material?.let {
                put("intercept_tls", true)
                put("ca_cert_pem", it.certPem)
                put("ca_key_pem", it.keyPem)
            }
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
        tunnelHasV6 = false
        unregisterUnderlyingNetworkTracking()
        serviceScope?.cancel()
        serviceScope = null
        sessionHolder.clear()
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
        private const val TAG = "Adwarden"
        private const val NOTIF_ID = 1001
        private const val MTU = 1500

        // Tunnel-local placeholder resolver advertised to apps (the gateway).
        private const val DNS_PLACEHOLDER_V4 = "10.215.173.1"

        // App-side IPv6 tunnel address; peer of the core's gateway fd00:aced:1::1
        // (same /64), advertised only when v6 egress is enabled.
        private const val V6_TUN_ADDR = "fd00:aced:1::2"

        // Blocks kept OFF the tunnel: the RFC1918 private LAN ranges plus
        // multicast/reserved (224/3). DNS_PLACEHOLDER_V4 lives inside 10/8 and is
        // carved back in as a /32 by addRoutesExceptLan().
        private val EXCLUDED_ROUTES = listOf(
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "224.0.0.0/3",
        )

        // Real upstream resolver the core forwards allowed DNS queries to
        // (IPv4-only, matching the IPv4-only tunnel).
        private val UPSTREAM_DNS = listOf("1.1.1.1")
    }
}
