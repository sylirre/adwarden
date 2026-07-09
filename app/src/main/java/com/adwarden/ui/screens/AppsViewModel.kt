// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package com.adwarden.ui.screens

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adwarden.data.AppRuleRepository
import com.adwarden.firewall.AppInventory
import com.adwarden.firewall.InstalledApp
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

/** An installed app plus its current per-network firewall policy. */
data class AppPolicy(
    val app: InstalledApp,
    val allowWifi: Boolean,
    val allowCellular: Boolean,
    val inspectTls: Boolean,
)

@HiltViewModel
class AppsViewModel @Inject constructor(
    private val inventory: AppInventory,
    private val appRules: AppRuleRepository,
) : ViewModel() {

    private val installed = MutableStateFlow<List<InstalledApp>>(emptyList())

    private val _loading = MutableStateFlow(true)
    val loading: StateFlow<Boolean> = _loading

    val apps: StateFlow<List<AppPolicy>> =
        combine(installed, appRules.rules) { apps, rules ->
            val byPackage = rules.associateBy { it.packageName }
            apps.map { app ->
                val rule = byPackage[app.packageName]
                AppPolicy(
                    app = app,
                    allowWifi = rule?.allowWifi ?: true,
                    allowCellular = rule?.allowCellular ?: true,
                    inspectTls = rule?.inspectTls ?: false,
                )
            }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    init {
        viewModelScope.launch {
            installed.value = inventory.load()
            _loading.value = false
        }
    }

    fun setWifi(policy: AppPolicy, allow: Boolean) = update(policy, allowWifi = allow)

    fun setCellular(policy: AppPolicy, allow: Boolean) = update(policy, allowCellular = allow)

    fun setInspect(policy: AppPolicy, inspect: Boolean) = update(policy, inspectTls = inspect)

    private fun update(
        policy: AppPolicy,
        allowWifi: Boolean = policy.allowWifi,
        allowCellular: Boolean = policy.allowCellular,
        inspectTls: Boolean = policy.inspectTls,
    ) {
        viewModelScope.launch {
            appRules.setPolicy(
                policy.app.packageName,
                policy.app.uid,
                allowWifi,
                allowCellular,
                inspectTls,
            )
        }
    }
}
