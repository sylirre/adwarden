// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package io.github.sylirre.adwarden.data

import io.github.sylirre.adwarden.data.db.AppRule
import io.github.sylirre.adwarden.data.db.AppRuleDao
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Verifies the firewall blob matches the format `parse_firewall` expects in Rust. */
class AppRuleRepositoryTest {

    private val repository = AppRuleRepository(mockk<AppRuleDao>(relaxed = true))

    @Test
    fun encodesRulesLittleEndian() {
        val blob = repository.encodeBlob(
            listOf(
                AppRule(packageName = "a", uid = 10123, allowWifi = false, allowCellular = true, inspectTls = true),
                AppRule(packageName = "b", uid = 10456, allowWifi = true, allowCellular = false, inspectTls = false),
            ),
        )

        val buf = ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(2, buf.int)

        assertEquals(10123, buf.int)
        assertEquals(0.toByte(), buf.get()) // wifi blocked
        assertEquals(1.toByte(), buf.get()) // cellular allowed
        assertEquals(1.toByte(), buf.get()) // inspect on

        assertEquals(10456, buf.int)
        assertEquals(1.toByte(), buf.get())
        assertEquals(0.toByte(), buf.get())
        assertEquals(0.toByte(), buf.get()) // inspect off

        assertEquals(4 + 2 * 7, blob.size)
    }

    @Test
    fun encodesEmptyRules() {
        val blob = repository.encodeBlob(emptyList())
        assertEquals(4, blob.size)
        assertEquals(0, ByteBuffer.wrap(blob).order(ByteOrder.LITTLE_ENDIAN).int)
    }
}
