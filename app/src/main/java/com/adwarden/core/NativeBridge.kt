// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package com.adwarden.core

import android.net.ConnectivityManager
import androidx.annotation.Keep
import com.adwarden.data.CaptureRepository
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Upcall target the native core holds a global reference to. Methods are called
 * from the core's datapath thread, so they must be cheap and thread-safe.
 *
 * `@Keep` and the explicit signatures are load-bearing: the Rust side resolves
 * these by name/descriptor via JNI.
 *
 * @param protector wraps `VpnService.protect(fd)` so upstream sockets bypass the
 *   tunnel; supplied by the service so this class stays unit-testable.
 * @param connectivity resolves the owning app UID of a flow for the firewall.
 */
class NativeBridge(
    private val capture: CaptureRepository,
    private val connectivity: ConnectivityManager,
    private val protector: (Int) -> Boolean,
) {
    /** Receive an encoded event batch and fan it into the capture repository. */
    @Keep
    fun onEvents(batch: ByteArray) {
        capture.onEvents(NativeEventCodec.decode(batch))
    }

    /**
     * Protect an upstream socket fd so its traffic bypasses the VPN.
     *
     * `VpnService.protect()` alone is the whole mechanism: it fwmarks the socket
     * ("protectedFromVpn", bit 17 / 0x20000) so routing skips the tunnel. We
     * deliberately do NOT also call `Network.bindSocket()` afterwards — it
     * rewrites SO_MARK with the network's netId, silently clearing the
     * protection bit.
     */
    @Keep
    fun protect(fd: Int): Boolean = protector(fd)

    /**
     * Resolve the owning app UID of a connection (IPPROTO_TCP=6 / UDP=17).
     * Returns INVALID_UID (-1) when unattributable.
     */
    @Keep
    fun lookupUid(proto: Int, srcIp: ByteArray, srcPort: Int, dstIp: ByteArray, dstPort: Int): Int =
        try {
            val local = InetSocketAddress(InetAddress.getByAddress(srcIp), srcPort)
            val remote = InetSocketAddress(InetAddress.getByAddress(dstIp), dstPort)
            connectivity.getConnectionOwnerUid(proto, local, remote)
        } catch (_: Exception) {
            -1
        }
}
