// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package com.adwarden.work

import android.content.Context
import android.util.Log
import androidx.hilt.work.HiltWorker
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import com.adwarden.data.FilterRepository
import com.adwarden.data.db.FilterSubscription
import com.adwarden.data.db.ScriptletPack
import dagger.assisted.Assisted
import dagger.assisted.AssistedInject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Downloads enabled filter lists (conditional on ETag / Last-Modified), persists
 * them, and recompiles the native engine. Runs periodically and on demand.
 */
@HiltWorker
class FilterSyncWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val repository: FilterRepository,
    private val client: OkHttpClient,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        repository.ensureSeeded()
        val subscriptions = repository.subscriptionsOnce().filter { it.enabled }
        for (subscription in subscriptions) {
            runCatching { syncOne(subscription) }.onFailure { error ->
                Log.w(TAG, "sync failed for ${subscription.id}", error)
            }
        }
        // Fetch the optional scriptlet override pack when configured (P4-3). The
        // built-in first-party pack ships in the APK and needs no download.
        repository.scriptletPackOnce()?.takeIf { it.enabled && it.url.isNotBlank() }?.let { pack ->
            runCatching { syncPack(pack) }.onFailure { error ->
                Log.w(TAG, "scriptlet pack sync failed", error)
            }
        }
        // Recompile even when every list 304s, so enable/disable and custom-rule
        // edits take effect. The bump also re-loads the (possibly refreshed) pack.
        if (repository.recompileEngine()) Result.success() else Result.retry()
    }

    private suspend fun syncPack(pack: ScriptletPack) {
        val file = repository.scriptletPackFile
        val builder = Request.Builder().url(pack.url)
        if (file.exists()) {
            pack.etag?.let { builder.header("If-None-Match", it) }
            pack.lastModified?.let { builder.header("If-Modified-Since", it) }
        }
        client.newCall(builder.build()).execute().use { response ->
            when {
                response.code == 304 -> return
                response.isSuccessful -> {
                    val body = response.body?.string() ?: return
                    file.writeText(body)
                    repository.updateScriptletPackSyncMeta(
                        etag = response.header("ETag"),
                        lastModified = response.header("Last-Modified"),
                    )
                }
                else -> Log.w(TAG, "scriptlet pack sync: HTTP ${response.code} from ${pack.url}")
            }
        }
    }

    private suspend fun syncOne(subscription: FilterSubscription) {
        val listFile = repository.listFile(subscription.id)
        val builder = Request.Builder().url(subscription.url)
        // Only send conditional headers when we still have the cached file.
        if (listFile.exists()) {
            subscription.etag?.let { builder.header("If-None-Match", it) }
            subscription.lastModified?.let { builder.header("If-Modified-Since", it) }
        }

        client.newCall(builder.build()).execute().use { response ->
            when {
                response.code == 304 -> return // already current
                response.isSuccessful -> {
                    val body = response.body?.string() ?: return
                    listFile.writeText(body)
                    repository.updateSyncMeta(
                        id = subscription.id,
                        etag = response.header("ETag"),
                        lastModified = response.header("Last-Modified"),
                        ruleCount = countRules(body),
                    )
                }
                // Leave the previous download (if any) in place, but say why the
                // list is stale — a silent 403 here cost a day of head-scratching.
                else -> Log.w(TAG, "sync ${subscription.id}: HTTP ${response.code} from ${subscription.url}")
            }
        }
    }

    /** Approximate rule count: non-blank, non-comment lines. */
    private fun countRules(body: String): Int =
        body.lineSequence().count { line ->
            val trimmed = line.trim()
            trimmed.isNotEmpty() &&
                !trimmed.startsWith("!") &&
                !trimmed.startsWith("#") &&
                !trimmed.startsWith("[")
        }

    private companion object {
        const val TAG = "Adwarden"
    }
}
