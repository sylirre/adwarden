// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package com.adwarden.firewall

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.inject.Inject
import javax.inject.Singleton

/** An installed, network-capable app the firewall can govern. */
data class InstalledApp(
    val packageName: String,
    val label: String,
    val uid: Int,
    val isSystem: Boolean,
)

/**
 * Enumerates installed apps that request the INTERNET permission — the only
 * ones the firewall can meaningfully block. Requires QUERY_ALL_PACKAGES.
 */
@Singleton
class AppInventory @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    suspend fun load(): List<InstalledApp> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val self = context.packageName
        val packages = pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        packages.asSequence()
            .filter { it.packageName != self }
            .filter { it.requestedPermissions?.contains(android.Manifest.permission.INTERNET) == true }
            .mapNotNull { pkg ->
                val info = pkg.applicationInfo ?: return@mapNotNull null
                InstalledApp(
                    packageName = pkg.packageName,
                    label = pm.getApplicationLabel(info).toString(),
                    uid = info.uid,
                    isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                )
            }
            // User apps first, then alphabetical by label.
            .sortedWith(compareBy({ it.isSystem }, { it.label.lowercase() }))
            .toList()
    }
}
