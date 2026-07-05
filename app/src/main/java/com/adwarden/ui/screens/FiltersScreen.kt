package com.adwarden.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adwarden.data.db.CustomRule
import com.adwarden.data.db.FilterSubscription
import com.adwarden.ui.components.AdwCard
import com.adwarden.ui.components.SectionTitle
import com.adwarden.ui.components.formatCount

@Composable
fun FiltersScreen(viewModel: FiltersViewModel = hiltViewModel()) {
    val subscriptions by viewModel.subscriptions.collectAsStateWithLifecycle()
    val customRules by viewModel.customRules.collectAsStateWithLifecycle()
    val totalRules by viewModel.totalRules.collectAsStateWithLifecycle()
    var draft by remember { mutableStateOf("") }

    Column(
        Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
    ) {
        Text(
            "Filters",
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.onBackground,
            modifier = Modifier.padding(top = 16.dp, bottom = 12.dp),
        )

        LazyColumn(
            Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                AdwCard(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(18.dp)) {
                        Text(
                            "${formatCount(totalRules)} rules active",
                            style = MaterialTheme.typography.headlineSmall,
                            color = MaterialTheme.colorScheme.onSurface,
                        )
                        Text(
                            "Network-level rules apply on the VPN. Cosmetic and scriptlet rules need a browser and are ignored.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 4.dp),
                        )
                    }
                }
            }

            item { SectionTitle("Subscriptions") }
            items(subscriptions, key = { it.id }) { sub ->
                SubscriptionCard(sub, onToggle = { viewModel.setEnabled(sub.id, it) })
            }

            item { SectionTitle("Custom rules") }
            item {
                CustomRulesCard(
                    rules = customRules,
                    draft = draft,
                    onDraftChange = { draft = it },
                    onAdd = {
                        viewModel.addRule(draft)
                        draft = ""
                    },
                    onDelete = viewModel::deleteRule,
                )
            }
            item { Spacer(Modifier.height(12.dp)) }
        }
    }
}

@Composable
private fun SubscriptionCard(sub: FilterSubscription, onToggle: (Boolean) -> Unit) {
    AdwCard(Modifier.fillMaxWidth()) {
        Row(
            Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f)) {
                Text(sub.name, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    "${formatCount(sub.ruleCount.toLong())} rules · ${hostOf(sub.url)}",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Switch(checked = sub.enabled, onCheckedChange = onToggle)
        }
    }
}

@Composable
private fun CustomRulesCard(
    rules: List<CustomRule>,
    draft: String,
    onDraftChange: (String) -> Unit,
    onAdd: () -> Unit,
    onDelete: (CustomRule) -> Unit,
) {
    AdwCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(bottom = 6.dp)) {
            Row(
                Modifier.padding(start = 16.dp, end = 8.dp, top = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OutlinedTextField(
                    value = draft,
                    onValueChange = onDraftChange,
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("||domain.com^ or @@exception") },
                    singleLine = true,
                    shape = RoundedCornerShape(14.dp),
                )
                IconButton(onClick = { if (draft.isNotBlank()) onAdd() }) {
                    Icon(Icons.Rounded.Add, contentDescription = "Add rule", tint = MaterialTheme.colorScheme.primary)
                }
            }
            rules.forEachIndexed { i, rule ->
                if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                Row(
                    Modifier.padding(start = 16.dp, end = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        rule.rule,
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Medium,
                        color = MaterialTheme.colorScheme.onSurface,
                        modifier = Modifier
                            .weight(1f)
                            .padding(vertical = 12.dp),
                    )
                    IconButton(onClick = { onDelete(rule) }) {
                        Icon(
                            Icons.Rounded.Close,
                            contentDescription = "Delete rule",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}

private fun hostOf(url: String): String =
    url.substringAfter("://").substringBefore('/')
