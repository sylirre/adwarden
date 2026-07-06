package com.adwarden

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.system.OsConstants
import androidx.core.content.ContextCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.adwarden.vpn.AdwardenVpnService
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * On-device gates for the VPN service lifecycle and per-app UID attribution.
 *
 * Preconditions (why `assumeTrue`, not `assertTrue`): the user must have
 * granted VPN consent to this build once (toggle Adwarden on manually), and no
 * other VPN may be active — neither is something a test can arrange.
 */
@RunWith(AndroidJUnit4::class)
class VpnGateTest {

    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @Suppress("DEPRECATION")
    private fun vpnUp(): Boolean = cm.allNetworks.any { network ->
        cm.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    }

    private fun awaitVpn(up: Boolean, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (vpnUp() == up) return true
            Thread.sleep(250)
        }
        return vpnUp() == up
    }

    private fun startVpn() {
        assumeTrue(
            "VPN consent not granted — toggle Adwarden on once manually first",
            VpnService.prepare(context) == null,
        )
        assumeTrue("another VPN is already active", !vpnUp())
        val intent = Intent(context, AdwardenVpnService::class.java)
            .setAction(AdwardenVpnService.ACTION_START)
        ContextCompat.startForegroundService(context, intent)
        assertTrue("tunnel did not come up within 15s", awaitVpn(up = true, timeoutMs = 15_000))
    }

    private fun stopVpn() {
        val intent = Intent(context, AdwardenVpnService::class.java)
            .setAction(AdwardenVpnService.ACTION_STOP)
        context.startService(intent)
        assertTrue("tunnel did not tear down within 10s", awaitVpn(up = false, timeoutMs = 10_000))
    }

    @After
    fun tearDown() {
        // Never leave the tunnel up after a failed assertion mid-test.
        if (vpnUp()) stopVpn()
    }

    @Test
    fun lifecycle_tunnelComesUpAndDown() {
        startVpn()
        stopVpn()
    }

    /**
     * The firewall's attribution goes through
     * `ConnectivityManager.getConnectionOwnerUid` ([NativeBridge.lookupUid]). Its
     * critical safety contract is the *negative* branch: an unknown 5-tuple must
     * come back as `INVALID_UID` (-1), which the core treats as "unattributable →
     * allow" ([Forwarder.policy_blocks]) so a lookup miss never wrongly blocks.
     *
     * This asserts that branch hermetically. Positive attribution can't be tested
     * in-process — `getConnectionOwnerUid` does not resolve loopback flows, and
     * anything routable would make the test depend on live network egress — so it
     * is validated on-device by the P1-D firewall gate instead (a blocked app's
     * flows show up attributed and dropped in the core heartbeat).
     */
    @Test
    fun uidMapping_unknownFlowIsUnattributable() {
        // A 5-tuple in TEST-NET-1 (RFC 5737) that no socket on the device owns.
        val local = InetSocketAddress(InetAddress.getByName("192.0.2.1"), 12345)
        val remote = InetSocketAddress(InetAddress.getByName("192.0.2.2"), 443)
        val uid = cm.getConnectionOwnerUid(OsConstants.IPPROTO_TCP, local, remote)
        assertEquals("unowned flow must be INVALID_UID", -1, uid)
    }
}
