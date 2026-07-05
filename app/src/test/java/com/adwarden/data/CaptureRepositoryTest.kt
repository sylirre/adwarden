package com.adwarden.data

import com.adwarden.core.ConnectionEvent
import com.adwarden.core.L4Proto
import com.adwarden.core.Verdict
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
        verdict = verdict,
        blockedDomain = if (verdict == Verdict.BLOCK) "ads.test" else null,
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
    fun resetsCountersOnRestart() {
        val repo = CaptureRepository()
        repo.onStarted()
        repo.onEvents(listOf(event(L4Proto.TCP, 443, 100)))
        repo.onStarted() // restart clears counters
        assertEquals(0, repo.stats.value.packets)
        assertEquals(0, repo.stats.value.bytes)
    }
}
