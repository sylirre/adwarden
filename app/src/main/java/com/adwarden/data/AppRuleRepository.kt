package com.adwarden.data

import com.adwarden.data.db.AppRule
import com.adwarden.data.db.AppRuleDao
import kotlinx.coroutines.flow.Flow
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Owns per-app firewall rules. A row is kept only while an app has a
 * non-default policy; setting it back to allow-everywhere removes the row.
 */
@Singleton
class AppRuleRepository @Inject constructor(
    private val appRuleDao: AppRuleDao,
) {
    val rules: Flow<List<AppRule>> = appRuleDao.rules()

    suspend fun rulesOnce(): List<AppRule> = appRuleDao.rulesOnce()

    suspend fun setPolicy(
        packageName: String,
        uid: Int,
        allowWifi: Boolean,
        allowCellular: Boolean,
        inspectTls: Boolean,
    ) {
        // Keep a row only while the app has any non-default setting.
        if (allowWifi && allowCellular && !inspectTls) {
            appRuleDao.deleteByPackage(packageName)
        } else {
            appRuleDao.upsert(AppRule(packageName, uid, allowWifi, allowCellular, inspectTls))
        }
    }

    /**
     * Pack the rules into the native firewall blob: u32 count, then per rule
     * [i32 uid, u8 allowWifi, u8 allowCellular, u8 inspectTls], all
     * little-endian. Must match `parse_firewall` in the Rust core.
     */
    fun encodeBlob(rules: List<AppRule>): ByteArray {
        val buffer = ByteBuffer.allocate(4 + rules.size * 7).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(rules.size)
        for (rule in rules) {
            buffer.putInt(rule.uid)
            buffer.put(if (rule.allowWifi) 1 else 0)
            buffer.put(if (rule.allowCellular) 1 else 0)
            buffer.put(if (rule.inspectTls) 1 else 0)
        }
        return buffer.array()
    }
}
