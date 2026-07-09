// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package io.github.sylirre.adwarden.data.db

import androidx.room.ColumnInfo
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

/**
 * The scriptlet resource pack (P4-3): a runtime-downloaded JSON array of
 * `adblock` resources supplying the JS implementations that `##+js(...)` rules
 * reference. Kept out of the APK for licensing (the uBO/AdGuard scriptlet library
 * is GPL) — only this URL ships; the pack is fetched at runtime, exactly like a
 * filter list. A single row (mirroring [FilterSubscription]'s sync metadata).
 */
@Entity(tableName = "scriptlet_pack")
data class ScriptletPack(
    @PrimaryKey val id: String,
    val name: String,
    val url: String,
    val enabled: Boolean,
    val etag: String? = null,
    val lastModified: String? = null,
    val lastSyncMs: Long = 0L,
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
    /** Opt this app's HTTPS into TLS interception (P2). Default off. */
    val inspectTls: Boolean = false,
)

/**
 * One row per calendar day (local-zone epoch-day, as [java.time.LocalDate.toEpochDay])
 * holding the running totals for that day. Written by [io.github.sylirre.adwarden.data.StatsRepository]
 * via increment-upsert, so the dashboard's "blocked today / this week" survives
 * process death and protection restarts (the live [io.github.sylirre.adwarden.core.CaptureStats]
 * resets every session). Days with no traffic simply have no row.
 */
@Entity(tableName = "daily_stat")
data class DailyStat(
    @PrimaryKey val dateEpochDay: Long,
    @ColumnInfo(defaultValue = "0") val packets: Long = 0,
    @ColumnInfo(defaultValue = "0") val bytes: Long = 0,
    @ColumnInfo(defaultValue = "0") val tcpPackets: Long = 0,
    @ColumnInfo(defaultValue = "0") val dnsQueries: Long = 0,
    @ColumnInfo(defaultValue = "0") val blocked: Long = 0,
)

/** What a [BlockedTally] row counts: a blocked domain, or a blocked app (by uid). */
enum class TallyKind { DOMAIN, APP }

/**
 * Per-day "top blocked" tally. [key] is the blocked domain (for [TallyKind.DOMAIN])
 * or the owning uid as a string (for [TallyKind.APP], resolved to an app label at
 * display time). Aggregated across a window to rank the worst offenders without
 * keeping a full per-event history.
 */
@Entity(tableName = "blocked_tally", primaryKeys = ["dateEpochDay", "kind", "key"])
data class BlockedTally(
    val dateEpochDay: Long,
    val kind: TallyKind,
    val key: String,
    @ColumnInfo(defaultValue = "0") val count: Long = 0,
)
