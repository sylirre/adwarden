// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package com.adwarden.vpn

/**
 * Pure IPv4 route math for the tunnel.
 *
 * The tunnel wants to route all of IPv4 into itself *except* a handful of blocks
 * that must keep flowing over the real network: the RFC1918 private LAN ranges
 * (router UI, printers, NAS, casting) and multicast/reserved space. Android's
 * `VpnService.Builder` has no "route everything except X" primitive before API
 * 33 (`excludeRoute`), and we support API 30, so we compute the CIDR complement
 * ourselves and add each block as an included route.
 *
 * Extracted from [AdwardenVpnService] so the arithmetic is unit-testable without
 * the Android framework.
 */
object TunRoutes {

    data class Route(val address: String, val prefixLength: Int)

    /** A CIDR block as an unsigned 32-bit `[start, end]` interval (inclusive). */
    private data class Block(val start: Long, val end: Long)

    private const val MAX_ADDR = 0xFFFF_FFFFL

    /**
     * Minimal, sorted, non-overlapping set of CIDR routes covering all of IPv4
     * except [excluded] (each `"a.b.c.d/prefix"`). Excluded blocks may overlap
     * or be unsorted.
     */
    fun complementRoutes(excluded: List<String>): List<Route> {
        val merged = mergeBlocks(excluded.map { parseCidr(it) }.sortedBy { it.start })
        val routes = mutableListOf<Route>()
        var cursor = 0L
        for (hole in merged) {
            if (hole.start > cursor) {
                routes += rangeToCidrs(cursor, hole.start - 1)
            }
            // Blocks can be nested/overlapping; never let the cursor go backward.
            if (hole.end + 1 > cursor) cursor = hole.end + 1
            if (cursor > MAX_ADDR) break
        }
        if (cursor <= MAX_ADDR) {
            routes += rangeToCidrs(cursor, MAX_ADDR)
        }
        return routes
    }

    private fun mergeBlocks(sorted: List<Block>): List<Block> {
        val out = mutableListOf<Block>()
        for (b in sorted) {
            val last = out.lastOrNull()
            // Merge overlapping and adjacent blocks (end+1 == next start).
            if (last != null && b.start <= last.end + 1) {
                out[out.size - 1] = Block(last.start, maxOf(last.end, b.end))
            } else {
                out += b
            }
        }
        return out
    }

    /** Decompose an inclusive `[start, end]` interval into aligned CIDR blocks. */
    private fun rangeToCidrs(start: Long, end: Long): List<Route> {
        val out = mutableListOf<Route>()
        var s = start
        while (s <= end) {
            // Largest block whose alignment matches `s`...
            val alignBits = if (s == 0L) 32 else java.lang.Long.numberOfTrailingZeros(s)
            var size = alignBits
            // ...then shrink until it fits inside [s, end].
            while (size > 0 && s + (1L shl size) - 1 > end) size--
            out += Route(longToIp(s), 32 - size)
            s += (1L shl size)
        }
        return out
    }

    private fun parseCidr(cidr: String): Block {
        val slash = cidr.indexOf('/')
        require(slash > 0) { "not a CIDR: $cidr" }
        val prefix = cidr.substring(slash + 1).toInt()
        require(prefix in 0..32) { "bad prefix in $cidr" }
        val base = ipToLong(cidr.substring(0, slash)) and prefixMask(prefix)
        return Block(base, base + (1L shl (32 - prefix)) - 1)
    }

    private fun prefixMask(prefix: Int): Long =
        if (prefix == 0) 0L else (MAX_ADDR shl (32 - prefix)) and MAX_ADDR

    private fun ipToLong(addr: String): Long {
        val parts = addr.split(".")
        require(parts.size == 4) { "not an IPv4 address: $addr" }
        return parts.fold(0L) { acc, p ->
            val octet = p.toInt()
            require(octet in 0..255) { "bad octet in $addr" }
            (acc shl 8) or octet.toLong()
        }
    }

    private fun longToIp(v: Long): String =
        "${(v ushr 24) and 0xFF}.${(v ushr 16) and 0xFF}.${(v ushr 8) and 0xFF}.${v and 0xFF}"
}
