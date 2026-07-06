package com.adwarden.data

import com.adwarden.data.db.DailyStat
import com.adwarden.data.db.StatsDao
import com.adwarden.data.db.TallyKind
import com.adwarden.data.db.TallyRank
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.time.LocalDate
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Rolls the live [CaptureRepository.deltas] stream into persistent per-day
 * aggregates (Room). This is the durable counterpart to the session-only
 * [com.adwarden.core.CaptureStats]: it survives protection restarts and process
 * death, backing the dashboard's "blocked today / this week", the daily bar chart,
 * and the top-blocked domain/app lists.
 *
 * Deltas are coalesced in memory and flushed on a coarse cadence (not once per
 * batch) to keep DB writes off the hot path; the accumulator is also drained
 * whenever protection stops so the last window isn't lost. Reads are plain Room
 * Flows, invalidated automatically as rows change.
 *
 * Instantiation is anchored by [com.adwarden.vpn.AdwardenVpnService] (field
 * injection), so recording is active whenever capture runs — independent of
 * whether any UI is bound.
 */
@Singleton
class StatsRepository @Inject constructor(
    private val dao: StatsDao,
    capture: CaptureRepository,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutex = Mutex()
    private val pending = Accumulator()

    init {
        // Coalesce every batch's delta into the in-memory accumulator.
        scope.launch {
            capture.deltas.collect { delta ->
                mutex.withLock { pending.add(delta) }
            }
        }
        // Periodic drain → DB. flush() is a no-op when nothing is pending, so an
        // idle tunnel costs only a bare coroutine timer (no wakelock, no writes).
        scope.launch {
            while (true) {
                delay(FLUSH_INTERVAL_MS)
                flush()
            }
        }
        // Don't strand the final window when protection stops.
        scope.launch {
            var wasRunning = false
            capture.running.collect { running ->
                if (wasRunning && !running) flush()
                wasRunning = running
            }
        }
    }

    private suspend fun flush() {
        val snapshot = mutex.withLock { pending.drain() } ?: return
        val day = LocalDate.now().toEpochDay()
        dao.addDaily(
            day = day,
            packets = snapshot.packets,
            bytes = snapshot.bytes,
            tcpPackets = snapshot.tcpPackets,
            dnsQueries = snapshot.dnsQueries,
            blocked = snapshot.blocked,
        )
        snapshot.domains.forEach { (domain, count) ->
            dao.addTally(day, TallyKind.DOMAIN, domain, count.toLong())
        }
        snapshot.apps.forEach { (uid, count) ->
            dao.addTally(day, TallyKind.APP, uid.toString(), count.toLong())
        }
    }

    /** Daily rows from [sinceDay] (inclusive), oldest first. */
    fun dailyStatsSince(sinceDay: Long): Flow<List<DailyStat>> = dao.dailyStatsSince(sinceDay)

    /** Top blocked domains by summed count over the window from [sinceDay]. */
    fun topDomains(sinceDay: Long, limit: Int): Flow<List<TallyRank>> =
        dao.topTallies(TallyKind.DOMAIN, sinceDay, limit)

    /** Top blocked apps (keyed by owning uid) over the window from [sinceDay]. */
    fun topApps(sinceDay: Long, limit: Int): Flow<List<TallyRank>> =
        dao.topTallies(TallyKind.APP, sinceDay, limit)

    /**
     * Mutable running totals for one flush window. Kept as a plain class (not a
     * data class) because it is drained-and-reset in place under [mutex].
     * `internal` so the coalescing logic can be unit-tested directly.
     */
    internal class Accumulator {
        private var packets = 0L
        private var bytes = 0L
        private var tcpPackets = 0L
        private var dnsQueries = 0L
        private var blocked = 0L
        private val domains = HashMap<String, Int>()
        private val apps = HashMap<Int, Int>()
        private var dirty = false

        fun add(delta: StatsDelta) {
            packets += delta.packets
            bytes += delta.bytes
            tcpPackets += delta.tcpPackets
            dnsQueries += delta.dnsQueries
            blocked += delta.blocked
            delta.blockedDomains.forEach { (k, v) -> domains.merge(k, v, Int::plus) }
            delta.blockedApps.forEach { (k, v) -> apps.merge(k, v, Int::plus) }
            dirty = true
        }

        /** Returns the accumulated window and resets, or null if nothing pending. */
        fun drain(): Snapshot? {
            if (!dirty) return null
            val snapshot = Snapshot(
                packets, bytes, tcpPackets, dnsQueries, blocked,
                HashMap(domains), HashMap(apps),
            )
            packets = 0; bytes = 0; tcpPackets = 0; dnsQueries = 0; blocked = 0
            domains.clear(); apps.clear(); dirty = false
            return snapshot
        }
    }

    internal class Snapshot(
        val packets: Long,
        val bytes: Long,
        val tcpPackets: Long,
        val dnsQueries: Long,
        val blocked: Long,
        val domains: Map<String, Int>,
        val apps: Map<Int, Int>,
    )

    private companion object {
        const val FLUSH_INTERVAL_MS = 3_000L
    }
}
