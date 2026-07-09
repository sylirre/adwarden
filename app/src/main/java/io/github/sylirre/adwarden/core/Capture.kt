// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package io.github.sylirre.adwarden.core

/** Layer-4 protocol carried by a captured IP packet. */
enum class L4Proto { TCP, UDP, ICMP, OTHER }

/** What the datapath did with a flow. */
enum class Verdict { ALLOW, BLOCK }

/**
 * A window's worth of allowed flows the datapath coalesced instead of surfacing
 * individually, while the live log was closed and no app was engaged (P3-4).
 * Carries only aggregate counters — no endpoint — folded straight into the
 * running/persistent stats so the dashboard totals stay accurate off the hot path.
 */
data class CoarseCounts(
    val packets: Long,
    val bytes: Long,
    val tcpPackets: Long,
    val udpPackets: Long,
    val dnsQueries: Long,
)

/** A single decoded packet/flow surfaced to the live traffic log. */
data class ConnectionEvent(
    val id: Long,
    val timestampMs: Long,
    val ipVersion: Int,
    val proto: L4Proto,
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int,
    val length: Int,
    val uid: Int? = null,
    val verdict: Verdict = Verdict.ALLOW,
    val blockedDomain: String? = null,
    /** HTTPS flow that pinned against our leaf: it forwards raw, so only its
     *  metadata is visible (P2-4). [host] carries the SNI when it was learned. */
    val tlsPinned: Boolean = false,
    val host: String? = null,
    /** Non-null for a coalesced-aggregate record (P3-4); such an event is a
     *  counter carrier, not a real flow, and is never shown in the live log. */
    val coarse: CoarseCounts? = null,
) {
    val isDns: Boolean get() = proto == L4Proto.UDP && (dstPort == 53 || dstPort == 5353)
}

/** Rolling counters for the dashboard. */
data class CaptureStats(
    val running: Boolean = false,
    val startedAtMs: Long = 0L,
    val packets: Long = 0L,
    val bytes: Long = 0L,
    val tcpPackets: Long = 0L,
    val udpPackets: Long = 0L,
    val dnsQueries: Long = 0L,
    val distinctDestinations: Int = 0,
    val blockedQueries: Long = 0L,
)
