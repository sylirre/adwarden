package com.adwarden.core

import java.net.Inet4Address
import java.net.Inet6Address
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Decodes the little-endian event batch produced by the Rust core's
 * `event::Batcher`. The layout must stay in lockstep with `rust/core/src/event.rs`:
 *
 *   u32 count, then per event:
 *   kind:u8, ip_version:u8, proto:u8, verdict:u8,
 *   uid:i32, src_port:u16, dst_port:u16, length:u32, timestamp_ms:u64,
 *   src:[u8;16], dst:[u8;16], domain_len:u16, domain:[u8; domain_len]
 */
object NativeEventCodec {

    fun decode(batch: ByteArray): List<ConnectionEvent> {
        if (batch.size < 4) return emptyList()
        val buf = ByteBuffer.wrap(batch).order(ByteOrder.LITTLE_ENDIAN)
        val count = buf.int
        if (count <= 0) return emptyList()

        val out = ArrayList<ConnectionEvent>(count)
        repeat(count) {
            if (buf.remaining() < FIXED_LEN) return out
            val kind = buf.get().toInt() and 0xFF // flow / dns-block / tls-pinned
            val ipVersion = buf.get().toInt() and 0xFF
            val proto = protoOf(buf.get().toInt() and 0xFF)
            val verdict = if ((buf.get().toInt() and 0xFF) == 1) Verdict.BLOCK else Verdict.ALLOW
            val uidRaw = buf.int
            val srcPort = buf.short.toInt() and 0xFFFF
            val dstPort = buf.short.toInt() and 0xFFFF
            val length = buf.int
            val timestampMs = buf.long
            val src = ByteArray(16).also { buf.get(it) }
            val dst = ByteArray(16).also { buf.get(it) }
            val domainLen = buf.short.toInt() and 0xFFFF
            val domain = if (domainLen > 0 && buf.remaining() >= domainLen) {
                ByteArray(domainLen).also { buf.get(it) }.toString(Charsets.UTF_8)
            } else {
                if (domainLen > 0) return out // truncated
                null
            }

            out.add(
                ConnectionEvent(
                    id = 0L,
                    timestampMs = timestampMs,
                    ipVersion = ipVersion,
                    proto = proto,
                    srcIp = ipString(src, ipVersion),
                    srcPort = srcPort,
                    dstIp = ipString(dst, ipVersion),
                    dstPort = dstPort,
                    length = length,
                    uid = if (uidRaw < 0) null else uidRaw,
                    verdict = verdict,
                    blockedDomain = if (kind == KIND_DNS_BLOCK) domain else null,
                    tlsPinned = kind == KIND_TLS_PINNED,
                    host = if (kind == KIND_TLS_PINNED) domain else null,
                ),
            )
        }
        return out
    }

    private fun protoOf(code: Int): L4Proto = when (code) {
        0 -> L4Proto.TCP
        1 -> L4Proto.UDP
        2 -> L4Proto.ICMP
        else -> L4Proto.OTHER
    }

    private fun ipString(raw: ByteArray, ipVersion: Int): String = try {
        if (ipVersion == 4) {
            Inet4Address.getByAddress(raw.copyOfRange(0, 4)).hostAddress ?: "0.0.0.0"
        } else {
            Inet6Address.getByAddress(raw).hostAddress ?: "::"
        }
    } catch (_: Exception) {
        if (ipVersion == 4) "0.0.0.0" else "::"
    }

    // kind+ipver+proto+verdict(4) + uid(4) + ports(4) + length(4) + ts(8) + src(16) + dst(16) + domainLen(2)
    private const val FIXED_LEN = 4 + 4 + 4 + 4 + 8 + 16 + 16 + 2

    // Event kinds — must match rust/core/src/event.rs.
    private const val KIND_DNS_BLOCK = 1
    private const val KIND_TLS_PINNED = 2
}
