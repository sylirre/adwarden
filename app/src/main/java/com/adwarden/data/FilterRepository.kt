package com.adwarden.data

import android.content.Context
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.adwarden.core.NativeCore
import com.adwarden.data.db.CustomRule
import com.adwarden.data.db.FilterDao
import com.adwarden.data.db.FilterFormat
import com.adwarden.data.db.FilterSubscription
import com.adwarden.work.FilterSyncWorker
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Owns filter subscriptions and user-authored custom rules, the on-disk list
 * files, and the compiled native engine cache.
 *
 * The compiled engine lives in native memory; [engineVersion] bumps whenever a
 * fresh cache is written so the running service can reload it.
 */
@Singleton
class FilterRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val filterDao: FilterDao,
) {
    val subscriptions: Flow<List<FilterSubscription>> = filterDao.subscriptions()
    val customRules: Flow<List<CustomRule>> = filterDao.customRules()

    private val _engineVersion = MutableStateFlow(0)
    /** Increments each time the engine cache is recompiled. */
    val engineVersion: StateFlow<Int> = _engineVersion.asStateFlow()

    private val listDir: File by lazy { File(context.filesDir, "filters").apply { mkdirs() } }

    /** Serialized engine cache. The name embeds a schema tag so a format change invalidates it. */
    val engineCacheFile: File by lazy { File(context.filesDir, "filter_engine_v$ENGINE_SCHEMA.bin") }

    fun listFile(id: String): File = File(listDir, "$id.txt")

    fun hasCompiledEngine(): Boolean = engineCacheFile.exists()

    /** Seed the default subscription set on first launch (idempotent). */
    suspend fun ensureSeeded() {
        if (filterDao.subscriptionCount() == 0) {
            filterDao.upsertSubscriptions(DEFAULT_SUBSCRIPTIONS)
        }
        // Repoint already-seeded rows whose default URL we have since replaced.
        // User state on the row (enabled, sync meta) is otherwise preserved.
        SUPERSEDED_URLS.forEach { (id, urls) ->
            filterDao.migrateUrl(id, oldUrl = urls.first, newUrl = urls.second)
        }
    }

    suspend fun setSubscriptionEnabled(id: String, enabled: Boolean) {
        filterDao.setEnabled(id, enabled)
        scheduleSync(expedited = true)
    }

    suspend fun addCustomRule(rule: String) {
        val trimmed = rule.trim()
        if (trimmed.isEmpty()) return
        filterDao.insertCustomRule(CustomRule(rule = trimmed, createdMs = System.currentTimeMillis()))
        scheduleSync(expedited = true)
    }

    suspend fun deleteCustomRule(rule: CustomRule) {
        filterDao.deleteCustomRule(rule)
        scheduleSync(expedited = true)
    }

    suspend fun subscriptionsOnce(): List<FilterSubscription> = filterDao.subscriptionsOnce()

    suspend fun enabledCustomRules(): List<String> =
        filterDao.enabledCustomRules().map { it.rule }

    suspend fun updateSyncMeta(
        id: String,
        etag: String?,
        lastModified: String?,
        ruleCount: Int,
    ) = filterDao.updateSyncMeta(id, etag, lastModified, System.currentTimeMillis(), ruleCount)

    /**
     * Recompile the native engine from all enabled, downloaded lists + enabled
     * custom rules. Called by the sync worker after downloads settle.
     */
    suspend fun recompileEngine(): Boolean {
        val enabled = filterDao.subscriptionsOnce().filter { it.enabled && listFile(it.id).exists() }
        val paths = enabled.map { listFile(it.id).absolutePath }.toTypedArray()
        val formats = enabled.map { if (it.format == FilterFormat.HOSTS) 1 else 0 }.toIntArray()
        val custom = enabledCustomRules().toTypedArray()

        if (!NativeCore.ensureLoaded()) return false
        val ok = NativeCore.nativeCompileEngine(
            paths,
            formats,
            custom,
            engineCacheFile.absolutePath,
        )
        if (ok) _engineVersion.value += 1
        return ok
    }

    /** Enqueue a background sync (periodic on first call + an optional immediate run). */
    fun scheduleSync(expedited: Boolean) {
        val wm = WorkManager.getInstance(context)
        wm.enqueueUniquePeriodicWork(
            PERIODIC_WORK,
            ExistingPeriodicWorkPolicy.KEEP,
            PeriodicWorkRequestBuilder<FilterSyncWorker>(1, TimeUnit.DAYS)
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.UNMETERED)
                        .setRequiresBatteryNotLow(true)
                        .build(),
                )
                .build(),
        )
        if (expedited) {
            wm.enqueueUniqueWork(
                ONESHOT_WORK,
                ExistingWorkPolicy.REPLACE,
                OneTimeWorkRequestBuilder<FilterSyncWorker>()
                    .setConstraints(
                        Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build(),
                    )
                    .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
                    .build(),
            )
        }
    }

    companion object {
        // Bump when the serialized engine format or adblock crate version changes.
        private const val ENGINE_SCHEMA = 1
        private const val PERIODIC_WORK = "adwarden_filter_sync_periodic"
        private const val ONESHOT_WORK = "adwarden_filter_sync_now"

        // Canonical raw-list URLs. ruleCount is seeded with an approximate size
        // so the UI reads sensibly before the first sync overwrites it with the
        // real count.
        val DEFAULT_SUBSCRIPTIONS = listOf(
            FilterSubscription(
                id = "adguard_base",
                name = "AdGuard Base filter",
                url = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt",
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
                url = "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt",
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

        // filters.adtidy.org rejects non-browser User-Agents with 403 and
        // rate-bans probing IPs; AdGuard's FiltersRegistry on GitHub serves the
        // same compiled lists without games, so seeded rows are repointed.
        private val SUPERSEDED_URLS = mapOf(
            "adguard_base" to (
                "https://filters.adtidy.org/extension/ublock/filters/2.txt" to
                    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_2_Base/filter.txt"
            ),
            "adguard_tracking" to (
                "https://filters.adtidy.org/extension/ublock/filters/3.txt" to
                    "https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt"
            ),
        )
    }
}
