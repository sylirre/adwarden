package com.adwarden.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.SignalCellularAlt
import androidx.compose.material.icons.rounded.Wifi
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adwarden.ui.components.AdwCard
import com.adwarden.ui.theme.AdwShapes
import com.adwarden.ui.theme.BrandBlue
import com.adwarden.ui.theme.BrandCyan
import com.adwarden.ui.theme.BrandViolet
import com.adwarden.ui.theme.Success
import com.adwarden.ui.theme.Warning

private val TINTS = listOf(BrandBlue, BrandViolet, BrandCyan, Success, Warning)

@Composable
fun AppsScreen(viewModel: AppsViewModel = hiltViewModel()) {
    val apps by viewModel.apps.collectAsStateWithLifecycle()
    val loading by viewModel.loading.collectAsStateWithLifecycle()
    var query by remember { mutableStateOf("") }

    Column(
        Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
    ) {
        Text(
            "Apps",
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.onBackground,
            modifier = Modifier.padding(top = 16.dp, bottom = 2.dp),
        )
        Text(
            "Block an app on Wi-Fi and mobile independently, or opt it into HTTPS inspection " +
                "(lock). Enforced while protection is on.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 12.dp),
        )

        if (loading && apps.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                CircularProgressIndicator()
            }
            return
        }

        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text("Search apps") },
            leadingIcon = { Icon(Icons.Rounded.Search, contentDescription = null) },
            singleLine = true,
            shape = RoundedCornerShape(16.dp),
        )
        Spacer(Modifier.height(12.dp))

        val filtered = remember(apps, query) {
            if (query.isBlank()) apps
            else apps.filter {
                it.app.label.contains(query, ignoreCase = true) ||
                    it.app.packageName.contains(query, ignoreCase = true)
            }
        }

        if (filtered.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text(
                    "No apps match \"$query\"",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            return
        }

        LazyColumn(
            Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            items(filtered, key = { it.app.packageName }) { policy ->
                AppCard(
                    policy = policy,
                    onWifi = { viewModel.setWifi(policy, !policy.allowWifi) },
                    onMobile = { viewModel.setCellular(policy, !policy.allowCellular) },
                    onInspect = { viewModel.setInspect(policy, !policy.inspectTls) },
                )
            }
            item { Spacer(Modifier.height(12.dp)) }
        }
    }
}

@Composable
private fun AppCard(
    policy: AppPolicy,
    onWifi: () -> Unit,
    onMobile: () -> Unit,
    onInspect: () -> Unit,
) {
    val tint = TINTS[(policy.app.packageName.hashCode() and 0x7fffffff) % TINTS.size]
    val label = policy.app.label
    val wifi = policy.allowWifi
    val mobile = policy.allowCellular

    AdwCard(Modifier.fillMaxWidth()) {
        Row(
            Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier
                    .size(42.dp)
                    .clip(RoundedCornerShape(13.dp))
                    .background(tint.copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    label.firstOrNull()?.uppercase() ?: "?",
                    style = MaterialTheme.typography.titleMedium,
                    color = tint,
                    fontWeight = FontWeight.Bold,
                )
            }
            Column(
                Modifier
                    .weight(1f)
                    .padding(horizontal = 12.dp),
            ) {
                Text(label, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    statusText(wifi, mobile) + if (policy.inspectTls) " · Inspecting HTTPS" else "",
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (!wifi || !mobile) Warning else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            MiniToggle(Icons.Rounded.Wifi, wifi, "Wi-Fi for $label", onWifi)
            Spacer(Modifier.size(8.dp))
            MiniToggle(Icons.Rounded.SignalCellularAlt, mobile, "Mobile data for $label", onMobile)
            Spacer(Modifier.size(8.dp))
            MiniToggle(Icons.Rounded.Lock, policy.inspectTls, "HTTPS inspection for $label", onInspect)
        }
    }
}

private fun statusText(wifi: Boolean, mobile: Boolean): String = when {
    !wifi && !mobile -> "Blocked everywhere"
    !wifi -> "Wi-Fi blocked"
    !mobile -> "Mobile blocked"
    else -> "Allowed"
}

@Composable
private fun MiniToggle(icon: ImageVector, on: Boolean, label: String, onClick: () -> Unit) {
    val bg = if (on) MaterialTheme.colorScheme.primaryContainer else Color.Transparent
    val fg = if (on) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.outline
    Box(
        Modifier
            // Keep the 40dp visual but guarantee a >=48dp touch target for a11y.
            .minimumInteractiveComponentSize()
            .size(40.dp)
            .clip(AdwShapes.Chip)
            .background(bg)
            .border(1.dp, if (on) Color.Transparent else MaterialTheme.colorScheme.outlineVariant, AdwShapes.Chip)
            .toggleable(value = on, role = Role.Switch, onValueChange = { onClick() })
            .semantics { contentDescription = label },
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, contentDescription = null, tint = fg, modifier = Modifier.size(20.dp))
    }
}
