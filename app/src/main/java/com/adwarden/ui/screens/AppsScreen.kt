package com.adwarden.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.rounded.SignalCellularAlt
import androidx.compose.material.icons.rounded.Wifi
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adwarden.ui.components.AdwCard
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

        LazyColumn(
            Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            items(apps, key = { it.app.packageName }) { policy ->
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
            MiniToggle(Icons.Rounded.Wifi, wifi, onWifi)
            Spacer(Modifier.size(8.dp))
            MiniToggle(Icons.Rounded.SignalCellularAlt, mobile, onMobile)
            Spacer(Modifier.size(8.dp))
            MiniToggle(Icons.Rounded.Lock, policy.inspectTls, onInspect)
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
private fun MiniToggle(icon: ImageVector, on: Boolean, onClick: () -> Unit) {
    val bg = if (on) MaterialTheme.colorScheme.primaryContainer else Color.Transparent
    val fg = if (on) MaterialTheme.colorScheme.onPrimaryContainer else MaterialTheme.colorScheme.outline
    Box(
        Modifier
            .size(40.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(bg)
            .border(1.dp, if (on) Color.Transparent else MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, contentDescription = null, tint = fg, modifier = Modifier.size(20.dp))
    }
}
