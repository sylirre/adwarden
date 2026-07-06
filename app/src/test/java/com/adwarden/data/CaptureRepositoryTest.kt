package com.adwarden.data

import com.adwarden.core.ConnectionEvent
import com.adwarden.core.L4Proto
import com.adwarden.core.Verdict
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

class CaptureRepositoryTest {

    // A little past CaptureRepository's 150 ms publish throttle.
    private val PUBLISH_WAIT_MS = 200L

    private fun event(
        proto: L4Proto,
        dstPort: Int,
        length: Int,
        verdict: Verdict = Verdict.ALLOW,
        dstIp: String = "1.1.1.1",
        uid: Int? = null,
        blockedDomain: String? = if (verdict == Verdict.BLOCK) "ads.test" else null,
    ) = ConnectionEvent(
        id = 0,
        timestampMs = 1,
        ipVersion = 4,
        proto = proto,
        srcIp = "10.0.0.2",
        srcPort = 40000,
        dstIp = dstIp,
        dstPort = dstPort,
        length = length,
        uid = uid,
        verdict = verdict,
        blockedDomain = blockedDomain,
    )

    @Test
    fun aggregatesCountersFromBatch() {
        val repo = CaptureRepository()
        repo.onStarted()
        Thread.sleep(PUBLISH_WAIT_MS) // let the publish throttle window elapse
        repo.onEvents(
            listOf(
                event(L4Proto.TCP, 443, 100),
                event(L4Proto.UDP, 53, 60, verdict = Verdict.BLOCK),
                event(L4Proto.UDP, 53, 60, dstIp = "8.8.8.8"),
            ),
        )

        val stats = repo.stats.value
        assertEquals(3, stats.packets)
        assertEquals(220, stats.bytes)
        assertEquals(1, stats.tcpPackets)
        assertEquals(2, stats.udpPackets)
        assertEquals(2, stats.dnsQueries) // both UDP:53 events count as DNS
        assertEquals(1, stats.blockedQueries)
        assertEquals(2, stats.distinctDestinations) // 1.1.1.1 and 8.8.8.8
    }

    @Test
    fun assignsMonotonicIds() {
        val repo = CaptureRepository()
        repo.onStarted()
        Thread.sleep(PUBLISH_WAIT_MS)
        repo.onEvents(listOf(event(L4Proto.TCP, 443, 10), event(L4Proto.TCP, 443, 10)))
        val ids = repo.events.value.map { it.id }.toSet()
        assertEquals(2, ids.size) // distinct ids assigned
    }

    @Test
    fun emitsStatsDeltaWithBlockedAttribution() = runTest {
        val repo = CaptureRepository()
        repo.onStarted()
        // UNDISPATCHED runs the collector synchronously until it subscribes to the
        // (replay-less) SharedFlow and suspends, so the emit below isn't missed.
        val deferred = async(start = CoroutineStart.UNDISPATCHED) {
            repo.deltas.first()
        }
        repo.onEvents(
            listOf(
                event(L4Proto.TCP, 443, 100),
                event(L4Proto.UDP, 53, 60, verdict = Verdict.BLOCK, uid = 10005, blockedDomain = "ads.test"),
                event(L4Proto.UDP, 53, 60, verdict = Verdict.BLOCK, uid = 10005, blockedDomain = "trk.test"),
            ),
        )

        val delta = deferred.await()
        assertEquals(3, delta.packets)
        assertEquals(220, delta.bytes)
        assertEquals(1, delta.tcpPackets)
        assertEquals(2, delta.dnsQueries)
        assertEquals(2, delta.blocked)
        assertEquals(mapOf("ads.test" to 1, "trk.test" to 1), delta.blockedDomains)
        assertEquals(mapOf(10005 to 2), delta.blockedApps)
    }

    @Test
    fun resetsCountersOnRestart() {
        val repo = CaptureRepository()
        repo.onStarted()
        repo.onEvents(listOf(event(L4Proto.TCP, 443, 100)))
        repo.onStarted() // restart clears counters
        assertEquals(0, repo.stats.value.packets)
        assertEquals(0, repo.stats.value.bytes)
    }
}
