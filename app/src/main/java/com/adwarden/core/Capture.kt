package com.adwarden.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.InetAddress

/** Layer-4 protocol carried by a captured IP packet. */
enum class L4Proto { TCP, UDP, ICMP, OTHER }

/** A single decoded packet surfaced to the live traffic log. */
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
)

/**
 * Stateless best-effort decoder for IPv4/IPv6 packets read off the TUN device.
 * Extension headers and fragmentation are not reassembled in P0 — that is the
 * job of the userspace TCP/IP core (smoltcp) arriving in P1/P2.
 */
object PacketDecoder {

    fun decode(buf: ByteArray, len: Int): ConnectionEvent? {
        if (len < 20) return null
        return when (buf[0].toInt() and 0xF0 ushr 4) {
            4 -> decodeV4(buf, len)
            6 -> decodeV6(buf, len)
            else -> null
        }
    }

    private fun decodeV4(buf: ByteArray, len: Int): ConnectionEvent? {
        val ihl = (buf[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl > len) return null
        val totalLen = u16(buf, 2)
        val proto = protoOf(buf[9].toInt() and 0xFF)
        val src = v4(buf, 12)
        val dst = v4(buf, 16)
        var sp = 0
        var dp = 0
        if ((proto == L4Proto.TCP || proto == L4Proto.UDP) && len >= ihl + 4) {
            sp = u16(buf, ihl)
            dp = u16(buf, ihl + 2)
        }
        return event(4, proto, src, sp, dst, dp, if (totalLen in 1..len) totalLen else len)
    }

    private fun decodeV6(buf: ByteArray, len: Int): ConnectionEvent? {
        if (len < 40) return null
        val payloadLen = u16(buf, 4)
        val proto = protoOf(buf[6].toInt() and 0xFF)
        val src = v6(buf, 8)
        val dst = v6(buf, 24)
        var sp = 0
        var dp = 0
        if ((proto == L4Proto.TCP || proto == L4Proto.UDP) && len >= 44) {
            sp = u16(buf, 40)
            dp = u16(buf, 42)
        }
        val total = 40 + payloadLen
        return event(6, proto, src, sp, dst, dp, if (total in 1..len) total else len)
    }

    private fun protoOf(n: Int): L4Proto = when (n) {
        6 -> L4Proto.TCP
        17 -> L4Proto.UDP
        1, 58 -> L4Proto.ICMP
        else -> L4Proto.OTHER
    }

    private fun event(v: Int, p: L4Proto, s: String, sp: Int, d: String, dp: Int, size: Int) =
        ConnectionEvent(0L, 0L, v, p, s, sp, d, dp, size)

    private fun u16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    private fun v4(b: ByteArray, o: Int) =
        "${b[o].toInt() and 0xFF}.${b[o + 1].toInt() and 0xFF}.${b[o + 2].toInt() and 0xFF}.${b[o + 3].toInt() and 0xFF}"

    private fun v6(b: ByteArray, o: Int): String = try {
        InetAddress.getByAddress(b.copyOfRange(o, o + 16)).hostAddress ?: "::"
    } catch (_: Exception) {
        "::"
    }
}

/**
 * Process-wide bridge between the capture thread (producer) and the Compose UI
 * (consumer). Publishes are throttled so a busy tunnel cannot flood recomposition.
 * A real datastore-backed repository replaces this once the native core lands.
 */
object CaptureState {

    private const val MAX_EVENTS = 400
    private const val PUBLISH_INTERVAL_MS = 150L

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
}
