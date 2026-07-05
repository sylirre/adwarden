package com.adwarden.data.db

import androidx.room.Entity
import androidx.room.PrimaryKey

/** Format of a downloadable filter list, deciding how the engine parses it. */
enum class FilterFormat { ADBLOCK, HOSTS }

/**
 * A subscribable filter list. [id] is a stable slug (not the URL) so a list can
 * change hosting without losing its enabled state. Sync metadata (etag /
 * lastModified / lastSyncMs / ruleCount) is populated by the P1-C sync worker.
 */
@Entity(tableName = "filter_subscription")
data class FilterSubscription(
    @PrimaryKey val id: String,
    val name: String,
    val url: String,
    val format: FilterFormat,
    val enabled: Boolean,
    val etag: String? = null,
    val lastModified: String? = null,
    val lastSyncMs: Long = 0L,
    val ruleCount: Int = 0,
)

/** A user-authored ABP-syntax rule (e.g. `||ads.example.com^`, `@@||cdn^`). */
@Entity(tableName = "custom_rule")
data class CustomRule(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val rule: String,
    val enabled: Boolean = true,
    val createdMs: Long = 0L,
)

/**
 * Per-app firewall policy. Keyed by the stable [packageName]; [uid] is the
 * last-resolved kernel uid (may change across reinstalls, re-resolved from
 * PackageManager at enforcement time). A row exists only for apps with a
 * non-default policy — absence means "allowed on every network".
 */
@Entity(tableName = "app_rule")
data class AppRule(
    @PrimaryKey val packageName: String,
    val uid: Int,
    val allowWifi: Boolean = true,
    val allowCellular: Boolean = true,
)
