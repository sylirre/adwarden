// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package io.github.sylirre.adwarden.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Covers [StatsRepository.Accumulator] — the in-memory coalescing that turns a
 * stream of per-batch [StatsDelta]s into a single window flushed to Room.
 */
class StatsAccumulatorTest {

    private fun delta(
        packets: Long = 0,
        bytes: Long = 0,
        tcpPackets: Long = 0,
        dnsQueries: Long = 0,
        blocked: Long = 0,
        domains: Map<String, Int> = emptyMap(),
        apps: Map<Int, Int> = emptyMap(),
    ) = StatsDelta(packets, bytes, tcpPackets, dnsQueries, blocked, domains, apps)

    @Test
    fun drainReturnsNullWhenNothingAdded() {
        assertNull(StatsRepository.Accumulator().drain())
    }

    @Test
    fun sumsScalarsAndMergesTallies() {
        val acc = StatsRepository.Accumulator()
        acc.add(delta(packets = 3, bytes = 300, tcpPackets = 2, dnsQueries = 1, blocked = 1, domains = mapOf("ads.test" to 1), apps = mapOf(10001 to 1)))
        acc.add(delta(packets = 2, bytes = 200, tcpPackets = 1, dnsQueries = 1, blocked = 2, domains = mapOf("ads.test" to 1, "trk.test" to 2), apps = mapOf(10001 to 2, 10002 to 1)))

        val s = acc.drain()!!
        assertEquals(5, s.packets)
        assertEquals(500, s.bytes)
        assertEquals(3, s.tcpPackets)
        assertEquals(2, s.dnsQueries)
        assertEquals(3, s.blocked)
        // Domain tallies merged across batches.
        assertEquals(mapOf("ads.test" to 2, "trk.test" to 2), s.domains)
        assertEquals(mapOf(10001 to 3, 10002 to 1), s.apps)
    }

    @Test
    fun drainResetsSoNextWindowStartsClean() {
        val acc = StatsRepository.Accumulator()
        acc.add(delta(packets = 4, blocked = 1, domains = mapOf("a.test" to 1)))
        acc.drain()
        // Nothing added since the drain → empty window.
        assertNull(acc.drain())

        acc.add(delta(packets = 1))
        val s = acc.drain()!!
        assertEquals(1, s.packets)
        assertEquals(0, s.blocked)
        assertEquals(emptyMap<String, Int>(), s.domains)
    }
}
