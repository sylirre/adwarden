package com.adwarden.data

import com.adwarden.data.db.CustomRule
import com.adwarden.data.db.FilterDao
import com.adwarden.data.db.FilterFormat
import com.adwarden.data.db.FilterSubscription
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Owns filter subscriptions and user-authored custom rules.
 *
 * In this commit it is the persistence + UI source of truth. The P1-C sync
 * worker later downloads the lists and updates [FilterSubscription.ruleCount]
 * and the sync metadata; the native engine consumes the enabled set.
 */
@Singleton
class FilterRepository @Inject constructor(
    private val filterDao: FilterDao,
) {
    val subscriptions: Flow<List<FilterSubscription>> = filterDao.subscriptions()
    val customRules: Flow<List<CustomRule>> = filterDao.customRules()

    /** Seed the default subscription set on first launch (idempotent). */
    suspend fun ensureSeeded() {
        if (filterDao.subscriptionCount() == 0) {
            filterDao.upsertSubscriptions(DEFAULT_SUBSCRIPTIONS)
        }
    }

    suspend fun setSubscriptionEnabled(id: String, enabled: Boolean) =
        filterDao.setEnabled(id, enabled)

    suspend fun addCustomRule(rule: String) {
        val trimmed = rule.trim()
        if (trimmed.isEmpty()) return
        filterDao.insertCustomRule(CustomRule(rule = trimmed, createdMs = System.currentTimeMillis()))
    }

    suspend fun deleteCustomRule(rule: CustomRule) = filterDao.deleteCustomRule(rule)

    companion object {
        // Canonical raw-list URLs. ruleCount is seeded with an approximate size
        // so the UI reads sensibly before the first sync overwrites it with the
        // real count.
        val DEFAULT_SUBSCRIPTIONS = listOf(
            FilterSubscription(
                id = "adguard_base",
                name = "AdGuard Base filter",
                url = "https://filters.adtidy.org/extension/ublock/filters/2.txt",
                format = FilterFormat.ADBLOCK,
                enabled = true,
                ruleCount = 78_000,
            ),
            FilterSubscription(
                id = "easylist",
                name = "EasyList",
                url = "https://easylist.to/easylist/easylist.txt",
                format = FilterFormat.ADBLOCK,
                enabled = true,
                ruleCount = 64_000,
            ),
            FilterSubscription(
                id = "easyprivacy",
                name = "EasyPrivacy",
                url = "https://easylist.to/easylist/easyprivacy.txt",
                format = FilterFormat.ADBLOCK,
                enabled = true,
                ruleCount = 51_000,
            ),
            FilterSubscription(
                id = "adguard_tracking",
                name = "AdGuard Tracking Protection",
                url = "https://filters.adtidy.org/extension/ublock/filters/3.txt",
                format = FilterFormat.ADBLOCK,
                enabled = false,
                ruleCount = 33_000,
            ),
            FilterSubscription(
                id = "stevenblack_hosts",
                name = "StevenBlack Hosts",
                url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
                format = FilterFormat.HOSTS,
                enabled = true,
                ruleCount = 130_000,
            ),
        )
    }
}
