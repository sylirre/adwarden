package com.adwarden.data

import com.adwarden.core.CaptureStats
import com.adwarden.core.ConnectionEvent
import com.adwarden.core.L4Proto
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Bridge between the capture producer (the VPN worker / native core) and the
 * Compose UI. Publishes are throttled so a busy tunnel cannot flood
 * recomposition.
 *
 * This is the injectable successor to the former `CaptureState` global object;
 * the public StateFlow surface (`stats` / `events` / `running`) is preserved
 * verbatim so screens bind to it unchanged.
 */
@Singleton
class CaptureRepository @Inject constructor() {

    private val lock = Any()
    private var seq = 0L
    private var packets = 0L
    private var bytes = 0L
    private var tcp = 0L
    private var udp = 0L
    private var dns = 0L
    private var startedAt = 0L
    private var isRunning = false
    private var lastPublish = 0L
    private val dests = HashSet<String>()
    private val recent = ArrayDeque<ConnectionEvent>()

    private val _stats = MutableStateFlow(CaptureStats())
    val stats: StateFlow<CaptureStats> = _stats.asStateFlow()

    private val _events = MutableStateFlow<List<ConnectionEvent>>(emptyList())
    val events: StateFlow<List<ConnectionEvent>> = _events.asStateFlow()

    private val _running = MutableStateFlow(false)
    val running: StateFlow<Boolean> = _running.asStateFlow()

    fun onStarted() {
        synchronized(lock) {
            packets = 0; bytes = 0; tcp = 0; udp = 0; dns = 0; seq = 0
            dests.clear(); recent.clear()
            startedAt = System.currentTimeMillis()
            isRunning = true
        }
        _running.value = true
        publish(force = true)
    }

    fun onStopped() {
        synchronized(lock) { isRunning = false }
        _running.value = false
        publish(force = true)
    }

    fun onPacket(parsed: ConnectionEvent?, size: Int) {
        synchronized(lock) {
            packets++
            bytes += size
            if (parsed != null) {
                when (parsed.proto) {
                    L4Proto.TCP -> tcp++
                    L4Proto.UDP -> udp++
                    else -> {}
                }
                if (parsed.isDns) dns++
                if (dests.size < 8000) dests.add(parsed.dstIp)
                recent.addFirst(parsed.copy(id = ++seq, timestampMs = System.currentTimeMillis()))
                while (recent.size > MAX_EVENTS) recent.removeLast()
            }
        }
        publish(force = false)
    }

    private fun publish(force: Boolean) {
        val now = System.currentTimeMillis()
        synchronized(lock) {
            if (!force && now - lastPublish < PUBLISH_INTERVAL_MS) return
            lastPublish = now
            _stats.value = CaptureStats(
                running = isRunning,
                startedAtMs = startedAt,
                packets = packets,
                bytes = bytes,
                tcpPackets = tcp,
                udpPackets = udp,
                dnsQueries = dns,
                distinctDestinations = dests.size,
            )
            _events.value = recent.toList()
        }
    }

    private companion object {
        const val MAX_EVENTS = 400
        const val PUBLISH_INTERVAL_MS = 150L
    }
}
