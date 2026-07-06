package com.adwarden.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Block
import androidx.compose.material.icons.rounded.DataUsage
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Pause
import androidx.compose.material.icons.rounded.PlayArrow
import androidx.compose.material.icons.rounded.Public
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.SwapVert
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adwarden.MainViewModel
import com.adwarden.ui.components.AdwCard
import com.adwarden.ui.components.SectionTitle
import com.adwarden.ui.components.Sparkline
import com.adwarden.ui.components.StatTile
import com.adwarden.ui.components.formatBytes
import com.adwarden.ui.components.formatCount
import com.adwarden.ui.components.formatDuration
import com.adwarden.ui.components.gradientBrush
import com.adwarden.ui.theme.BrandBlue
import com.adwarden.ui.theme.BrandCyan
import com.adwarden.ui.theme.BrandViolet
import com.adwarden.ui.theme.Success
import com.adwarden.ui.theme.Warning
import kotlinx.coroutines.delay

@Composable
fun DashboardScreen(
    viewModel: MainViewModel,
    onToggleProtection: () -> Unit,
) {
    val stats by viewModel.stats.collectAsStateWithLifecycle()
    val running by viewModel.running.collectAsStateWithLifecycle()
    val events by viewModel.events.collectAsStateWithLifecycle()

    val pps = remember { mutableStateListOf<Float>() }
    LaunchedEffect(running) {
        if (!running) {
            pps.clear()
            return@LaunchedEffect
        }
        var last = viewModel.stats.value.packets
        while (true) {
            delay(1000)
            val now = viewModel.stats.value.packets
            pps.add((now - last).coerceAtLeast(0).toFloat())
            last = now
            while (pps.size > 40) pps.removeAt(0)
        }
    }

    val topDests = remember(events) {
        events.groupingBy { it.dstIp }.eachCount()
            .entries.sortedByDescending { it.value }.take(5)
    }

    Column(
        Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
    ) {
        HeroCard(
            running = running,
            uptimeMs = if (running) System.currentTimeMillis() - stats.startedAtMs else 0L,
            packets = stats.packets,
            onToggle = onToggleProtection,
        )

        if (running) {
            Spacer(Modifier.height(12.dp))
            FilteringBanner()
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle("Session")
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile(Icons.Rounded.SwapVert, formatCount(stats.packets), "Packets", BrandBlue, Modifier.weight(1f))
            StatTile(Icons.Rounded.DataUsage, formatBytes(stats.bytes), "Data seen", BrandViolet, Modifier.weight(1f))
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile(Icons.Rounded.Dns, formatCount(stats.dnsQueries), "DNS queries", BrandCyan, Modifier.weight(1f))
            StatTile(Icons.Rounded.Block, formatCount(stats.blockedQueries), "Blocked", Warning, Modifier.weight(1f))
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile(Icons.Rounded.Public, stats.distinctDestinations.toString(), "Destinations", Success, Modifier.weight(1f))
            StatTile(Icons.Rounded.Shield, formatCount(stats.tcpPackets), "TCP flows", BrandViolet, Modifier.weight(1f))
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle("Throughput")
        AdwCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "${(pps.lastOrNull() ?: 0f).toInt()}",
                        style = androidx.compose.material3.MaterialTheme.typography.headlineMedium,
                        color = androidx.compose.material3.MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        " packets/sec",
                        style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                        color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 6.dp, bottom = 3.dp),
                    )
                }
                Spacer(Modifier.height(12.dp))
                if (pps.size < 2) {
                    Text(
                        if (running) "Sampling…" else "Turn on protection to see live throughput",
                        style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                        color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    Sparkline(
                        values = pps.toList(),
                        lineColor = BrandBlue,
                        fillColor = BrandBlue,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(72.dp),
                    )
                }
            }
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle("Top destinations")
        AdwCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(vertical = 6.dp)) {
                if (topDests.isEmpty()) {
                    Text(
                        "No traffic captured yet.",
                        style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                        color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(16.dp),
                    )
                } else {
                    topDests.forEach { (ip, count) ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Box(
                                Modifier
                                    .size(8.dp)
                                    .clip(RoundedCornerShape(4.dp))
                                    .background(Success),
                            )
                            Text(
                                ip,
                                style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                                color = androidx.compose.material3.MaterialTheme.colorScheme.onSurface,
                                modifier = Modifier
                                    .weight(1f)
                                    .padding(start = 12.dp),
                            )
                            Text(
                                "$count",
                                style = androidx.compose.material3.MaterialTheme.typography.labelLarge,
                                color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }
        }
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun HeroCard(
    running: Boolean,
    uptimeMs: Long,
    packets: Long,
    onToggle: () -> Unit,
) {
    val brush = if (running) {
        gradientBrush(listOf(BrandBlue, BrandViolet))
    } else {
        gradientBrush(listOf(Color(0xFF3A3F55), Color(0xFF23273A)))
    }
    Box(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(28.dp))
            .background(brush)
            .padding(22.dp),
    ) {
        Column(Modifier.fillMaxWidth()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (running) "Protected" else "Paused",
                    style = androidx.compose.material3.MaterialTheme.typography.labelLarge,
                    color = Color.White.copy(alpha = 0.85f),
                )
                Spacer(Modifier.weight(1f))
                Box(
                    Modifier
                        .clip(RoundedCornerShape(20.dp))
                        .background(Color.White.copy(alpha = 0.16f))
                        .padding(horizontal = 10.dp, vertical = 4.dp),
                ) {
                    Text(
                        if (running) "Filtering" else "Off",
                        style = androidx.compose.material3.MaterialTheme.typography.labelMedium,
                        color = Color.White,
                    )
                }
            }
            Spacer(Modifier.height(18.dp))
            Text(
                if (running) "Inspecting traffic" else "Protection is off",
                style = androidx.compose.material3.MaterialTheme.typography.headlineMedium,
                color = Color.White,
                fontWeight = FontWeight.Bold,
            )
            Text(
                if (running) "Up ${formatDuration(uptimeMs)} · ${formatCount(packets)} packets seen"
                else "Start to filter and inspect on-device traffic",
                style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                color = Color.White.copy(alpha = 0.85f),
                modifier = Modifier.padding(top = 4.dp),
            )
            Spacer(Modifier.height(20.dp))
            Row(
                Modifier
                    .fillMaxWidth()
                    .height(52.dp)
                    .clip(RoundedCornerShape(16.dp))
                    .background(Color.White)
                    .toggleable(
                        value = running,
                        role = Role.Switch,
                        onValueChange = { onToggle() },
                    )
                    .semantics { stateDescription = if (running) "Protected" else "Off" }
                    .testTag("protection_toggle"),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Center,
            ) {
                androidx.compose.material3.Icon(
                    if (running) Icons.Rounded.Pause else Icons.Rounded.PlayArrow,
                    contentDescription = null,
                    tint = BrandBlue,
                    modifier = Modifier.size(22.dp),
                )
                Text(
                    if (running) "Pause protection" else "Turn on protection",
                    style = androidx.compose.material3.MaterialTheme.typography.titleMedium,
                    color = BrandBlue,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
        }
    }
}

@Composable
private fun FilteringBanner() {
    AdwCard(Modifier.fillMaxWidth()) {
        Row(
            Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            androidx.compose.material3.Icon(
                Icons.Rounded.Info,
                contentDescription = null,
                tint = Success,
                modifier = Modifier.size(20.dp),
            )
            Text(
                "Allowed traffic is forwarded through the native core; blocked domains and apps are dropped.",
                style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 12.dp),
            )
        }
    }
}
