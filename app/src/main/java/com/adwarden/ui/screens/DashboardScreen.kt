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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adwarden.MainViewModel
import com.adwarden.R
import com.adwarden.RankedItem
import com.adwarden.ui.components.AdwCard
import com.adwarden.ui.components.BarChart
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
import com.adwarden.ui.theme.Danger
import com.adwarden.ui.theme.Success
import com.adwarden.ui.theme.Warning
import kotlinx.coroutines.delay
import java.time.LocalDate
import java.time.format.TextStyle
import java.util.Locale

@Composable
fun DashboardScreen(
    viewModel: MainViewModel,
    onToggleProtection: () -> Unit,
) {
    val stats by viewModel.stats.collectAsStateWithLifecycle()
    val running by viewModel.running.collectAsStateWithLifecycle()
    val events by viewModel.events.collectAsStateWithLifecycle()

    val weekBlocked by viewModel.weekBlockedPerDay.collectAsStateWithLifecycle()
    val blockedToday by viewModel.blockedToday.collectAsStateWithLifecycle()
    val blockedThisWeek by viewModel.blockedThisWeek.collectAsStateWithLifecycle()
    val topDomains by viewModel.topBlockedDomains.collectAsStateWithLifecycle()
    val topApps by viewModel.topBlockedApps.collectAsStateWithLifecycle()

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
        SectionTitle(stringResource(R.string.dash_session))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile(Icons.Rounded.SwapVert, formatCount(stats.packets), stringResource(R.string.dash_packets), BrandBlue, Modifier.weight(1f))
            StatTile(Icons.Rounded.DataUsage, formatBytes(stats.bytes), stringResource(R.string.dash_data_seen), BrandViolet, Modifier.weight(1f))
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile(Icons.Rounded.Dns, formatCount(stats.dnsQueries), stringResource(R.string.dash_dns_queries), BrandCyan, Modifier.weight(1f))
            StatTile(Icons.Rounded.Block, formatCount(stats.blockedQueries), stringResource(R.string.dash_blocked), Warning, Modifier.weight(1f))
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile(Icons.Rounded.Public, stats.distinctDestinations.toString(), stringResource(R.string.dash_destinations), Success, Modifier.weight(1f))
            StatTile(Icons.Rounded.Shield, formatCount(stats.tcpPackets), stringResource(R.string.dash_tcp_flows), BrandViolet, Modifier.weight(1f))
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle(stringResource(R.string.dash_throughput))
        AdwCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "${(pps.lastOrNull() ?: 0f).toInt()}",
                        style = androidx.compose.material3.MaterialTheme.typography.headlineMedium,
                        color = androidx.compose.material3.MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        stringResource(R.string.dash_packets_per_sec),
                        style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                        color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(start = 6.dp, bottom = 3.dp),
                    )
                }
                Spacer(Modifier.height(12.dp))
                if (pps.size < 2) {
                    Text(
                        if (running) stringResource(R.string.dash_sampling) else stringResource(R.string.dash_throughput_hint),
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
        SectionTitle(stringResource(R.string.dash_top_destinations))
        AdwCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(vertical = 6.dp)) {
                if (topDests.isEmpty()) {
                    Text(
                        stringResource(R.string.dash_no_traffic),
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
        Spacer(Modifier.height(20.dp))
        SectionTitle(stringResource(R.string.dash_history))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile(Icons.Rounded.Block, formatCount(blockedToday), stringResource(R.string.dash_blocked_today), Danger, Modifier.weight(1f))
            StatTile(Icons.Rounded.Shield, formatCount(blockedThisWeek), stringResource(R.string.dash_blocked_week), BrandViolet, Modifier.weight(1f))
        }

        Spacer(Modifier.height(12.dp))
        AdwCard(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp)) {
                Text(
                    stringResource(R.string.dash_blocked_per_day),
                    style = androidx.compose.material3.MaterialTheme.typography.labelLarge,
                    color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                if (blockedThisWeek == 0L) {
                    Text(
                        stringResource(R.string.dash_no_blocks),
                        style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                        color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    BarChart(
                        values = weekBlocked.map { it.toFloat() },
                        barColor = Danger,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(96.dp),
                    )
                    Spacer(Modifier.height(6.dp))
                    Row(Modifier.fillMaxWidth()) {
                        lastNDayLabels(weekBlocked.size).forEach { label ->
                            Text(
                                label,
                                style = androidx.compose.material3.MaterialTheme.typography.labelSmall,
                                color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                                modifier = Modifier.weight(1f),
                            )
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle(stringResource(R.string.dash_top_blocked_domains))
        RankedCard(items = topDomains, dotColor = Danger, emptyText = stringResource(R.string.dash_no_domains))

        Spacer(Modifier.height(20.dp))
        SectionTitle(stringResource(R.string.dash_top_blocked_apps))
        RankedCard(items = topApps, dotColor = Warning, emptyText = stringResource(R.string.dash_no_app_blocks))

        Spacer(Modifier.height(16.dp))
    }
}

/** Short weekday initials for the last [n] days, oldest→newest, matching the bar order. */
private fun lastNDayLabels(n: Int): List<String> {
    if (n <= 0) return emptyList()
    val today = LocalDate.now()
    return (0 until n).map { i ->
        today.minusDays((n - 1 - i).toLong())
            .dayOfWeek.getDisplayName(TextStyle.NARROW, Locale.getDefault())
    }
}

/** A card of ranked rows (a colored dot, a label, and its count), or an empty note. */
@Composable
private fun RankedCard(items: List<RankedItem>, dotColor: Color, emptyText: String) {
    AdwCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(vertical = 6.dp)) {
            if (items.isEmpty()) {
                Text(
                    emptyText,
                    style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                    color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(16.dp),
                )
            } else {
                items.forEach { item ->
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
                                .background(dotColor),
                        )
                        Text(
                            item.label,
                            style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                            color = androidx.compose.material3.MaterialTheme.colorScheme.onSurface,
                            maxLines = 1,
                            overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                            modifier = Modifier
                                .weight(1f)
                                .padding(start = 12.dp),
                        )
                        Text(
                            formatCount(item.count),
                            style = androidx.compose.material3.MaterialTheme.typography.labelLarge,
                            color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
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
            val stateDesc = if (running) stringResource(R.string.hero_protected) else stringResource(R.string.hero_off)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    if (running) stringResource(R.string.hero_protected) else stringResource(R.string.hero_paused),
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
                        if (running) stringResource(R.string.hero_filtering) else stringResource(R.string.hero_off),
                        style = androidx.compose.material3.MaterialTheme.typography.labelMedium,
                        color = Color.White,
                    )
                }
            }
            Spacer(Modifier.height(18.dp))
            Text(
                if (running) stringResource(R.string.hero_inspecting) else stringResource(R.string.hero_protection_off),
                style = androidx.compose.material3.MaterialTheme.typography.headlineMedium,
                color = Color.White,
                fontWeight = FontWeight.Bold,
            )
            Text(
                if (running) stringResource(R.string.hero_uptime, formatDuration(uptimeMs), formatCount(packets))
                else stringResource(R.string.hero_start_hint),
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
                    .semantics { stateDescription = stateDesc }
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
                    if (running) stringResource(R.string.hero_pause) else stringResource(R.string.hero_turn_on),
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
                stringResource(R.string.filtering_banner),
                style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                color = androidx.compose.material3.MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 12.dp),
            )
        }
    }
}
