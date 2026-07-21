// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package io.github.sylirre.adwarden.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.github.sylirre.adwarden.R
import io.github.sylirre.adwarden.core.ConnectionEvent
import io.github.sylirre.adwarden.core.L4Proto
import io.github.sylirre.adwarden.core.Verdict
import io.github.sylirre.adwarden.ui.theme.Danger
import io.github.sylirre.adwarden.ui.theme.Success

/**
 * Per-request detail for a tapped live-traffic row: protocol, endpoints, owning
 * app, allow/block status and any decoded host (DNS query name or TLS SNI). The
 * Block button writes a user filter rule for that host; it is disabled when the
 * flow carries no hostname to key a rule on.
 *
 * @param event the selected flow.
 * @param appLabel resolved owning-app label, or null when unattributed/unknown.
 * @param onBlock invoked with the host to block (only reachable when one exists).
 */
@Composable
fun TrafficDetailDialog(
    event: ConnectionEvent,
    appLabel: String?,
    onBlock: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    val blocked = event.verdict == Verdict.BLOCK
    val decoded = event.host ?: event.blockedDomain

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.traffic_detail_title)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                DetailRow(stringResource(R.string.traffic_detail_protocol), protoText(event))
                DetailRow(stringResource(R.string.traffic_detail_source), endpoint(event.srcIp, event.srcPort))
                DetailRow(stringResource(R.string.traffic_detail_dest), endpoint(event.dstIp, event.dstPort))
                DetailRow(
                    stringResource(R.string.traffic_detail_app),
                    appLabel ?: stringResource(R.string.traffic_detail_unknown),
                )
                DetailRow(
                    stringResource(R.string.traffic_detail_status),
                    stringResource(if (blocked) R.string.traffic_status_blocked else R.string.traffic_status_allowed),
                    valueColor = if (blocked) Danger else Success,
                )
                DetailRow(stringResource(R.string.traffic_detail_decoded), decoded ?: "—")
            }
        },
        confirmButton = {
            TextButton(
                enabled = decoded != null,
                onClick = {
                    decoded?.let(onBlock)
                    onDismiss()
                },
            ) {
                Text(
                    stringResource(R.string.traffic_detail_block),
                    // Explicit accent while enabled; when disabled, inherit the
                    // button's dimmed content color.
                    color = if (decoded != null) Danger else Color.Unspecified,
                )
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.traffic_detail_close)) }
        },
    )
}

@Composable
private fun DetailRow(label: String, value: String, valueColor: Color = Color.Unspecified) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 6.dp),
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(104.dp),
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            color = if (valueColor == Color.Unspecified) MaterialTheme.colorScheme.onSurface else valueColor,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.weight(1f),
        )
    }
}

private fun protoText(event: ConnectionEvent): String {
    val base = when (event.proto) {
        L4Proto.TCP -> "TCP"
        L4Proto.UDP -> "UDP"
        L4Proto.ICMP -> "ICMP"
        L4Proto.OTHER -> "IP"
    }
    return when {
        event.tlsPinned -> "$base · TLS"
        event.isDns -> "$base · DNS"
        else -> base
    }
}

/** Format `ip:port`, collapsing the zeroed placeholder used by server-only events
 *  (SNI / pinned / encrypted-DNS records carry no local endpoint) to a dash. */
private fun endpoint(ip: String, port: Int): String =
    if (port == 0 && (ip.isEmpty() || ip == "0.0.0.0" || ip == "::")) "—" else "$ip:$port"
