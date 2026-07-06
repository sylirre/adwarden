package com.adwarden.data

import com.adwarden.core.CaptureStats
import com.adwarden.core.ConnectionEvent
import com.adwarden.core.L4Proto
import com.adwarden.core.Verdict
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Per-batch increments handed to [StatsRepository] for persistence. Emitted once
 * per native upcall (see [CaptureRepository.onEvents]) so daily aggregates can be
 * rolled up without re-deriving them from the throttled, session-resetting
 * [CaptureStats] StateFlow. [blockedDomains]/[blockedApps] map a blocked domain /
 * owning uid to its occurrence count within the batch.
 */
data class StatsDelta(
    val packets: Long,
    val bytes: Long,
    val tcpPackets: Long,
    val dnsQueries: Long,
    val blocked: Long,
    val blockedDomains: Map<String, Int>,
    val blockedApps: Map<Int, Int>,
)

/**
 * Bridge between the capture producer (the native core, via NativeBridge) and
 * the Compose UI. Publishes are throttled so a busy tunnel cannot flood
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
    private var blocked = 0L
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

    // Fire-and-forget increments for persistent daily aggregates. Buffered +
    // DROP_OLDEST so tryEmit() from the datapath thread never blocks; the
    // in-memory consumer keeps up in practice, so drops only happen under
    // pathological bursts (a few uncounted stat increments, never a crash).
    private val _deltas = MutableSharedFlow<StatsDelta>(
        extraBufferCapacity = 128,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    val deltas: SharedFlow<StatsDelta> = _deltas.asSharedFlow()

    fun onStarted() {
        synchronized(lock) {
            packets = 0; bytes = 0; tcp = 0; udp = 0; dns = 0; blocked = 0; seq = 0
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

    /**
     * Ingest a batch of events decoded from a native upcall. Native-assigned
     * timestamps are kept; only the display id is (re)assigned here.
     */
    fun onEvents(batch: List<ConnectionEvent>) {
        if (batch.isEmpty()) return
        // Accumulate this batch's contribution to the persistent daily aggregates
        // in the same pass we already make over the events.
        var dPackets = 0L
        var dBytes = 0L
        var dTcp = 0L
        var dDns = 0L
        var dBlocked = 0L
        val dDomains = HashMap<String, Int>()
        val dApps = HashMap<Int, Int>()
        synchronized(lock) {
            for (event in batch) {
                packets++; dPackets++
                bytes += event.length; dBytes += event.length
                when (event.proto) {
                    L4Proto.TCP -> { tcp++; dTcp++ }
                    L4Proto.UDP -> udp++
                    else -> {}
                }
                if (event.isDns) { dns++; dDns++ }
                if (event.verdict == Verdict.BLOCK) {
                    blocked++; dBlocked++
                    event.blockedDomain?.let { dDomains.merge(it, 1, Int::plus) }
                    event.uid?.let { if (it > 0) dApps.merge(it, 1, Int::plus) }
                }
                if (dests.size < 8000) dests.add(event.dstIp)
                recent.addFirst(event.copy(id = ++seq))
                while (recent.size > MAX_EVENTS) recent.removeLast()
            }
        }
        _deltas.tryEmit(
            StatsDelta(dPackets, dBytes, dTcp, dDns, dBlocked, dDomains, dApps),
        )
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
                blockedQueries = blocked,
            )
            _events.value = recent.toList()
        }
    }

    private companion object {
        const val MAX_EVENTS = 400
        const val PUBLISH_INTERVAL_MS = 150L
    }
}
