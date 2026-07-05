package com.adwarden.ui.screens

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.adwarden.data.FilterRepository
import com.adwarden.data.db.CustomRule
import com.adwarden.data.db.FilterSubscription
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class FiltersViewModel @Inject constructor(
    private val repository: FilterRepository,
) : ViewModel() {

    val subscriptions: StateFlow<List<FilterSubscription>> = repository.subscriptions
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val customRules: StateFlow<List<CustomRule>> = repository.customRules
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    val totalRules: StateFlow<Long> = repository.subscriptions
        .map { subs -> subs.filter { it.enabled }.sumOf { it.ruleCount.toLong() } }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), 0L)

    init {
        viewModelScope.launch {
            repository.ensureSeeded()
            // Download lists + compile the engine on first open if we have none.
            repository.scheduleSync(expedited = !repository.hasCompiledEngine())
        }
    }

    fun setEnabled(id: String, enabled: Boolean) {
        viewModelScope.launch { repository.setSubscriptionEnabled(id, enabled) }
    }

    fun addRule(rule: String) {
        viewModelScope.launch { repository.addCustomRule(rule) }
    }

    fun deleteRule(rule: CustomRule) {
        viewModelScope.launch { repository.deleteCustomRule(rule) }
    }
}
