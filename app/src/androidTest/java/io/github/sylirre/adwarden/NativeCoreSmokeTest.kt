// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package io.github.sylirre.adwarden

import android.content.Context
import android.net.ConnectivityManager
import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.sylirre.adwarden.core.NativeBridge
import io.github.sylirre.adwarden.core.NativeCore
import io.github.sylirre.adwarden.data.CaptureRepository
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.FileDescriptor

/**
 * On-device smoke tests for the JNI boundary: the .so loads for this ABI, a
 * session starts and stops cleanly (datapath thread + fd ownership), and the
 * filter-engine compiler works through the array-marshalling JNI entry point.
 * Packet-level logic is covered by the Rust host tests; none of this needs the
 * real TUN or VPN consent.
 */
@RunWith(AndroidJUnit4::class)
class NativeCoreSmokeTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun library_loadsAndReportsAbiVersion() {
        assertTrue(NativeCore.ensureLoaded())
        assertTrue(NativeCore.nativeAbiVersion() > 0)
    }

    @Test
    fun session_startsAndStopsOnSocketpairFd() {
        assertTrue(NativeCore.ensureLoaded())

        // One end of a socketpair stands in for the TUN fd: read/write/epoll all
        // behave, and the core owns and closes it after nativeStart.
        val ours = FileDescriptor()
        val cores = FileDescriptor()
        Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_STREAM, 0, ours, cores)
        val coreFd = ParcelFileDescriptor.dup(cores).detachFd()
        Os.close(cores)

        val bridge = NativeBridge(
            capture = CaptureRepository(),
            connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager,
            protector = { true },
        )
        val config = """{"mtu":1500,"encrypted_dns_mode":"off","dns_servers":["1.1.1.1"]}"""
        val handle = NativeCore.nativeStart(coreFd, config, bridge)
        assertNotEquals("nativeStart must return a live session handle", 0L, handle)

        // Let the datapath thread attach to the JVM and complete a poll pass.
        Thread.sleep(500)

        // Must join the thread and close the fd without crashing the process.
        NativeCore.nativeStop(handle)
        Os.close(ours)
    }

    @Test
    fun engineCompiler_producesLoadableCacheFile() {
        assertTrue(NativeCore.ensureLoaded())
        val list = File(context.cacheDir, "smoke-list.txt")
        list.writeText("||smoke-test-domain.example^\n")
        val out = File(context.cacheDir, "smoke-engine.bin")
        out.delete()

        val ok = NativeCore.nativeCompileEngine(
            arrayOf(list.absolutePath),
            intArrayOf(0), // 0 = adblock format
            arrayOf("||custom-rule.example^"),
            out.absolutePath,
        )

        assertTrue("nativeCompileEngine must succeed", ok)
        assertTrue("serialized engine cache must be non-empty", out.length() > 0)
        list.delete()
        out.delete()
    }
}
