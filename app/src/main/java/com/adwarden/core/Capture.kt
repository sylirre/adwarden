package com.adwarden.core

/** Layer-4 protocol carried by a captured IP packet. */
enum class L4Proto { TCP, UDP, ICMP, OTHER }

/** What the datapath did with a flow. */
enum class Verdict { ALLOW, BLOCK }

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
