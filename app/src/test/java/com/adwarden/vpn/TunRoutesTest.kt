package com.adwarden.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunRoutesTest {

    private val excluded = listOf(
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/3",
    )

    private fun ipToLong(addr: String): Long =
        addr.split(".").fold(0L) { acc, p -> (acc shl 8) or p.toLong() }

    /** Half-open `[start, end)` interval covered by a route. */
    private fun interval(r: TunRoutes.Route): LongRange {
        val base = ipToLong(r.address)
        return base until (base + (1L shl (32 - r.prefixLength)))
    }

    private fun covered(routes: List<TunRoutes.Route>, addr: String): Boolean {
        val v = ipToLong(addr)
        return routes.any { v in interval(it) }
    }

    @Test
    fun keepsPrivateAndMulticastOffTheTunnel() {
        val routes = TunRoutes.complementRoutes(excluded)
        // Every RFC1918 / multicast probe must be OUTSIDE the tunnel routes.
        listOf(
            "10.0.0.1", "10.215.173.1", "10.255.255.255",
            "172.16.0.1", "172.31.255.255",
            "192.168.0.1", "192.168.255.255",
            "224.0.0.1", "239.255.255.255", "255.255.255.255",
        ).forEach { assertFalse("$it should stay off-tunnel", covered(routes, it)) }
    }

    @Test
    fun routesPublicAndAdjacentAddresses() {
        val routes = TunRoutes.complementRoutes(excluded)
        // Public addresses and the ones bordering each excluded block must be
        // routed INTO the tunnel.
        listOf(
            "0.0.0.0", "1.1.1.1", "8.8.8.8", "9.255.255.255", // around 10/8
            "11.0.0.0", "172.15.255.255", "172.32.0.0", // around 172.16/12
            "192.167.255.255", "192.169.0.0", // around 192.168/16
            "93.184.216.34", "223.255.255.255", // last routable before 224/3
        ).forEach { assertTrue("$it should be routed", covered(routes, it)) }
    }

    @Test
    fun routesAreSortedAndNonOverlapping() {
        val ivals = TunRoutes.complementRoutes(excluded)
            .map { interval(it) }
            .sortedBy { it.first }
        for (i in 1 until ivals.size) {
            assertTrue(
                "routes overlap: ${ivals[i - 1]} vs ${ivals[i]}",
                ivals[i].first >= ivals[i - 1].last + 1,
            )
        }
    }

    @Test
    fun coverageIsExactComplement() {
        // Union of the routes must equal [0, 2^32) minus the excluded union,
        // exactly. Walk sorted intervals and confirm the only gaps are the
        // excluded blocks.
        val ivals = TunRoutes.complementRoutes(excluded)
            .map { it.let { r -> interval(r).first to interval(r).last } }
            .sortedBy { it.first }
        // Merge adjacent covered intervals.
        val merged = mutableListOf<Pair<Long, Long>>()
        for (iv in ivals) {
            val last = merged.lastOrNull()
            if (last != null && iv.first <= last.second + 1) {
                merged[merged.size - 1] = last.first to maxOf(last.second, iv.second)
            } else {
                merged += iv
            }
        }
        // Expected complement of {10/8, 172.16/12, 192.168/16, 224/3} over
        // [0, 2^32): four contiguous covered runs.
        val expected = listOf(
            0L to (ipToLong("10.0.0.0") - 1),
            ipToLong("11.0.0.0") to (ipToLong("172.16.0.0") - 1),
            ipToLong("172.32.0.0") to (ipToLong("192.168.0.0") - 1),
            ipToLong("192.169.0.0") to (ipToLong("224.0.0.0") - 1),
        )
        assertEquals(expected, merged)
    }
}
