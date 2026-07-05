package com.adwarden.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.adwarden.ui.components.AdwCard
import com.adwarden.ui.components.SectionTitle
import com.adwarden.ui.components.formatCount

private data class FilterList(val name: String, val source: String, val rules: Long, val enabledDefault: Boolean)

private val filterLists = listOf(
    FilterList("AdGuard Base filter", "filters.adtidy.org", 78_000, true),
    FilterList("EasyList", "easylist.to", 64_000, true),
    FilterList("EasyPrivacy", "easylist.to", 51_000, true),
    FilterList("AdGuard Tracking Protection", "filters.adtidy.org", 33_000, false),
    FilterList("StevenBlack Hosts", "github.com/StevenBlack", 130_000, true),
)

@Composable
fun FiltersScreen() {
    val enabled = remember { mutableStateMapOf<String, Boolean>() }
    val customRules = remember { mutableStateListOf("||ads.example.com^", "@@||cdn.example.net^") }
    var draft by remember { mutableStateOf("") }

    val totalRules = remember(enabled.toMap()) {
        filterLists.filter { enabled[it.name] ?: it.enabledDefault }.sumOf { it.rules }
    }

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
            items(filterLists, key = { it.name }) { list ->
                AdwCard(Modifier.fillMaxWidth()) {
                    Row(
                        Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(list.name, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
                            Text(
                                "${formatCount(list.rules)} rules · ${list.source}",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Switch(
                            checked = enabled[list.name] ?: list.enabledDefault,
                            onCheckedChange = { enabled[list.name] = it },
                        )
                    }
                }
            }

            item { SectionTitle("Custom rules") }
            item {
                AdwCard(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(bottom = 6.dp)) {
                        Row(
                            Modifier.padding(start = 16.dp, end = 8.dp, top = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            OutlinedTextField(
                                value = draft,
                                onValueChange = { draft = it },
                                modifier = Modifier.weight(1f),
                                placeholder = { Text("||domain.com^ or @@exception") },
                                singleLine = true,
                                shape = RoundedCornerShape(14.dp),
                            )
                            IconButton(onClick = {
                                if (draft.isNotBlank()) {
                                    customRules.add(0, draft.trim())
                                    draft = ""
                                }
                            }) {
                                Icon(Icons.Rounded.Add, contentDescription = "Add rule", tint = MaterialTheme.colorScheme.primary)
                            }
                        }
                        customRules.forEachIndexed { i, rule ->
                            if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                            Text(
                                rule,
                                style = MaterialTheme.typography.bodyLarge,
                                fontWeight = FontWeight.Medium,
                                color = MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                            )
                        }
                    }
                }
            }
            item { Spacer(Modifier.height(12.dp)) }
        }
    }
}
