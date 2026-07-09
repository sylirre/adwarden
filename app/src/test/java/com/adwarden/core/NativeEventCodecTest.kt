// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package com.adwarden.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Locks the Kotlin decoder to the byte layout emitted by `rust/core/src/event.rs`.
 * If either side changes the wire format, this test should fail.
 */
class NativeEventCodecTest {

    private fun buildEvent(
        buf: ByteBuffer,
        kind: Int,
        ipVersion: Int,
        proto: Int,
        verdict: Int,
        uid: Int,
        srcPort: Int,
        dstPort: Int,
        length: Int,
        timestampMs: Long,
        src: ByteArray,
        dst: ByteArray,
        domain: String?,
    ) {
        buf.put(kind.toByte())
        buf.put(ipVersion.toByte())
        buf.put(proto.toByte())
        buf.put(verdict.toByte())
        buf.putInt(uid)
        buf.putShort(srcPort.toShort())
        buf.putShort(dstPort.toShort())
        buf.putInt(length)
        buf.putLong(timestampMs)
        buf.put(src.copyOf(16))
        buf.put(dst.copyOf(16))
        val domainBytes = domain?.toByteArray(Charsets.UTF_8) ?: ByteArray(0)
        buf.putShort(domainBytes.size.toShort())
        buf.put(domainBytes)
    }

    @Test
    fun decodesBlockedDnsEvent() {
        val domain = "ads.example.com"
        val payload = 4 + (4 + 4 + 4 + 4 + 8 + 16 + 16 + 2 + domain.length)
        val buf = ByteBuffer.allocate(payload).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(1) // count
        buildEvent(
            buf,
            kind = 1, // DNS block
            ipVersion = 4,
            proto = 1, // UDP
            verdict = 1, // BLOCK
            uid = 10123,
            srcPort = 40000,
            dstPort = 53,
            length = 60,
            timestampMs = 12345L,
            src = byteArrayOf(10, 0, 0, 2),
            dst = byteArrayOf(1, 1, 1, 1),
            domain = domain,
        )

        val events = NativeEventCodec.decode(buf.array())
        assertEquals(1, events.size)
        val e = events.first()
        assertEquals(L4Proto.UDP, e.proto)
        assertEquals(Verdict.BLOCK, e.verdict)
        assertEquals(10123, e.uid)
        assertEquals(40000, e.srcPort)
        assertEquals(53, e.dstPort)
        assertEquals(60, e.length)
        assertEquals(12345L, e.timestampMs)
        assertEquals("10.0.0.2", e.srcIp)
        assertEquals("1.1.1.1", e.dstIp)
        assertEquals(domain, e.blockedDomain)
        assertTrue(e.isDns)
    }

    @Test
    fun decodesAllowFlowWithUnknownUid() {
        val payload = 4 + (4 + 4 + 4 + 4 + 8 + 16 + 16 + 2)
        val buf = ByteBuffer.allocate(payload).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(1)
        buildEvent(
            buf,
            kind = 0,
            ipVersion = 4,
            proto = 0, // TCP
            verdict = 0, // ALLOW
            uid = -1,
            srcPort = 51000,
            dstPort = 443,
            length = 120,
            timestampMs = 999L,
            src = byteArrayOf(10, 0, 0, 2),
            dst = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34),
            domain = null,
        )

        val e = NativeEventCodec.decode(buf.array()).single()
        assertEquals(L4Proto.TCP, e.proto)
        assertEquals(Verdict.ALLOW, e.verdict)
        assertNull(e.uid) // -1 maps to null
        assertNull(e.blockedDomain)
        assertEquals("93.184.216.34", e.dstIp)
    }

    @Test
    fun decodesTlsPinnedFlowAsMetadataOnly() {
        val host = "api.bank.example"
        val payload = 4 + (4 + 4 + 4 + 4 + 8 + 16 + 16 + 2 + host.length)
        val buf = ByteBuffer.allocate(payload).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(1)
        buildEvent(
            buf,
            kind = 2, // TLS pinned (metadata only)
            ipVersion = 4,
            proto = 0, // TCP
            verdict = 0, // ALLOW — it still forwards, just raw
            uid = 10200,
            srcPort = 0,
            dstPort = 443,
            length = 0,
            timestampMs = 4242L,
            src = ByteArray(4),
            dst = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34),
            domain = host,
        )

        val e = NativeEventCodec.decode(buf.array()).single()
        assertTrue(e.tlsPinned)
        assertEquals(host, e.host)
        assertNull(e.blockedDomain) // host isn't a DNS-block domain
        assertEquals(Verdict.ALLOW, e.verdict)
        assertEquals(10200, e.uid)
        assertEquals("93.184.216.34", e.dstIp)
    }

    @Test
    fun decodesCoarseAggregateEvent() {
        // Counters packed into the address fields, matching Event::coarse in
        // rust/core/src/event.rs: src = packets|tcp|udp|dns (u32 each), dst = bytes (u64).
        val src = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(1200) // packets
            putInt(700) // tcp
            putInt(500) // udp
            putInt(320) // dns
        }.array()
        val dst = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN).apply {
            putLong(4_500_000L) // bytes
        }.array()

        val payload = 4 + (4 + 4 + 4 + 4 + 8 + 16 + 16 + 2)
        val buf = ByteBuffer.allocate(payload).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(1)
        buildEvent(
            buf,
            kind = 3, // coarse aggregate
            ipVersion = 0,
            proto = 3, // OTHER (unused)
            verdict = 0,
            uid = -1,
            srcPort = 0,
            dstPort = 0,
            length = 0,
            timestampMs = 5150L,
            src = src,
            dst = dst,
            domain = null,
        )

        val e = NativeEventCodec.decode(buf.array()).single()
        val c = e.coarse
        assertEquals(1200L, c!!.packets)
        assertEquals(4_500_000L, c.bytes)
        assertEquals(700L, c.tcpPackets)
        assertEquals(500L, c.udpPackets)
        assertEquals(320L, c.dnsQueries)
        // A coarse record is a counter carrier, not a flow: no domain, not pinned.
        assertNull(e.blockedDomain)
        assertEquals(false, e.tlsPinned)
    }

    @Test
    fun emptyBatchDecodesToEmptyList() {
        assertTrue(NativeEventCodec.decode(ByteArray(0)).isEmpty())
        val buf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0)
        assertTrue(NativeEventCodec.decode(buf.array()).isEmpty())
    }
}
