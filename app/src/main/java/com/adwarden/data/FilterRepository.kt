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
import com.adwarden.data.db.ScriptletPack
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
    val scriptletPack: Flow<ScriptletPack?> = filterDao.scriptletPack()

    private val _engineVersion = MutableStateFlow(0)
    /** Increments each time the engine cache is recompiled. */
    val engineVersion: StateFlow<Int> = _engineVersion.asStateFlow()

    private val listDir: File by lazy { File(context.filesDir, "filters").apply { mkdirs() } }

    /** Serialized engine cache. The name embeds a schema tag so a format change invalidates it. */
    val engineCacheFile: File by lazy { File(context.filesDir, "filter_engine_v$ENGINE_SCHEMA.bin") }

    /** Optional user-downloaded scriptlet override pack (P4-3), never bundled. */
    val scriptletPackFile: File by lazy { File(context.filesDir, "scriptlet_resources.json") }

    /** The bundled first-party (MIT) scriptlet pack, extracted from assets so the
     *  datapath can load it by path. Re-extracted per process so app updates ship. */
    val builtinScriptletFile: File by lazy {
        File(context.filesDir, "scriptlet_builtin.json").also { file ->
            runCatching {
                context.assets.open("scriptlets_builtin.json").use { input ->
                    file.outputStream().use { input.copyTo(it) }
                }
            }
        }
    }

    fun listFile(id: String): File = File(listDir, "$id.txt")

    fun hasCompiledEngine(): Boolean = engineCacheFile.exists()

    /**
     * Path to the scriptlet pack for the datapath's engine load, or `""` if none.
     * A user-downloaded override pack wins; otherwise the bundled first-party pack
     * is used, so scriptlets work out of the box. The pack is loaded whenever
     * present; injection itself is gated by the "Run scriptlets" switch (P4-4).
     */
    fun scriptletPackPath(): String {
        if (scriptletPackFile.exists()) return scriptletPackFile.absolutePath
        val builtin = builtinScriptletFile
        return if (builtin.exists()) builtin.absolutePath else ""
    }

    suspend fun scriptletPackOnce(): ScriptletPack? = filterDao.scriptletPackOnce()

    /** Enable/disable fetching the scriptlet pack; enabling schedules a sync. */
    suspend fun setScriptletPackEnabled(enabled: Boolean) {
        filterDao.setScriptletPackEnabled(DEFAULT_SCRIPTLET_PACK.id, enabled)
        if (enabled) scheduleSync(expedited = true)
    }

    suspend fun updateScriptletPackSyncMeta(etag: String?, lastModified: String?) =
        filterDao.updateScriptletPackSyncMeta(
            DEFAULT_SCRIPTLET_PACK.id, etag, lastModified, System.currentTimeMillis(),
        )

    /** Seed the default subscription set on first launch (idempotent). */
    suspend fun ensureSeeded() {
        if (filterDao.subscriptionCount() == 0) {
            filterDao.upsertSubscriptions(DEFAULT_SUBSCRIPTIONS)
        }
        if (filterDao.scriptletPackCount() == 0) {
            filterDao.upsertScriptletPack(DEFAULT_SCRIPTLET_PACK)
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
        // v2: cosmetic rules retained in the cache (P4) — invalidates network-only caches.
        private const val ENGINE_SCHEMA = 2

        // Optional user-configurable scriptlet OVERRIDE pack (P4-3): a runtime-
        // downloaded `adblock`-crate resource JSON that replaces the bundled
        // first-party pack when set + enabled (e.g. a full uBO/AdGuard set the user
        // supplies). Empty/disabled by default — the built-in MIT pack in
        // assets/scriptlets_builtin.json is the working default, so scriptlets fire
        // out of the box with no download and no bundled GPL code.
        val DEFAULT_SCRIPTLET_PACK = ScriptletPack(
            id = "override",
            name = "Custom scriptlet pack",
            url = "",
            enabled = false,
        )
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
