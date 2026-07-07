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
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.DataObject
import androidx.compose.material.icons.rounded.Save
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material.icons.rounded.Stop
import androidx.compose.material.icons.rounded.Timeline
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adwarden.MainViewModel
import com.adwarden.R
import com.adwarden.core.ConnectionEvent
import com.adwarden.core.L4Proto
import com.adwarden.ui.components.ProtoBadge
import com.adwarden.ui.components.formatBytes
import com.adwarden.ui.theme.BrandBlue
import com.adwarden.ui.theme.BrandViolet
import com.adwarden.ui.theme.Warning
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@Composable
fun TrafficScreen(
    viewModel: MainViewModel,
    pcapViewModel: TrafficViewModel = hiltViewModel(),
) {
    val events by viewModel.events.collectAsStateWithLifecycle()
    val capturing by pcapViewModel.capturing.collectAsStateWithLifecycle()
    val running by pcapViewModel.running.collectAsStateWithLifecycle()
    var query by remember { mutableStateOf("") }

    // While this screen is visible, the datapath keeps full per-flow telemetry;
    // leaving it (tab switch or app backgrounded) lets the core drop into its
    // coalescing battery fast-path (P3-4). addObserver replays the current state,
    // so ON_START fires on entry; onDispose covers the tab-switch case where no
    // ON_STOP is dispatched.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner, pcapViewModel) {
        val observer = LifecycleEventObserver { _, event ->
            when (event) {
                Lifecycle.Event.ON_START -> pcapViewModel.onScreenActive()
                Lifecycle.Event.ON_STOP -> pcapViewModel.onScreenInactive()
                else -> {}
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose {
            lifecycleOwner.lifecycle.removeObserver(observer)
            pcapViewModel.onScreenInactive()
        }
    }

    val createDocument = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri -> uri?.let(pcapViewModel::startCapture) }

    val exportHar = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/json"),
    ) { uri -> uri?.let(pcapViewModel::exportHar) }

    val filtered = remember(events, query) {
        if (query.isBlank()) events
        else events.filter {
            it.dstIp.contains(query, true) ||
                it.srcIp.contains(query, true) ||
                it.dstPort.toString().contains(query)
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
    ) {
        Row(
            Modifier.fillMaxWidth().padding(top = 16.dp, bottom = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                stringResource(R.string.traffic_title),
                style = MaterialTheme.typography.headlineMedium,
                color = MaterialTheme.colorScheme.onBackground,
                modifier = Modifier.weight(1f),
            )
            if (running) {
                TextButton(onClick = { exportHar.launch(pcapViewModel.defaultHarFileName()) }) {
                    Icon(Icons.Rounded.DataObject, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text("  " + stringResource(R.string.traffic_har))
                }
                CaptureAction(
                    capturing = capturing,
                    onStart = { createDocument.launch(pcapViewModel.defaultFileName()) },
                    onStop = pcapViewModel::stopCapture,
                )
            }
        }
        OutlinedTextField(
            value = query,
            onValueChange = { query = it },
            modifier = Modifier.fillMaxWidth(),
            placeholder = { Text(stringResource(R.string.traffic_search)) },
            leadingIcon = { Icon(Icons.Rounded.Search, contentDescription = null) },
            singleLine = true,
            shape = RoundedCornerShape(16.dp),
        )
        Spacer(Modifier.height(12.dp))

        if (filtered.isEmpty()) {
            EmptyTraffic()
        } else {
            LazyColumn(
                Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(filtered, key = { it.id }) { TrafficRow(it) }
            }
        }
    }
}

@Composable
private fun CaptureAction(capturing: Boolean, onStart: () -> Unit, onStop: () -> Unit) {
    if (capturing) {
        TextButton(onClick = onStop) {
            Icon(Icons.Rounded.Stop, contentDescription = null, tint = Warning, modifier = Modifier.size(18.dp))
            Text("  " + stringResource(R.string.traffic_stop), color = Warning)
        }
    } else {
        TextButton(onClick = onStart) {
            Icon(Icons.Rounded.Save, contentDescription = null, modifier = Modifier.size(18.dp))
            Text("  " + stringResource(R.string.traffic_capture))
        }
    }
}

@Composable
private fun TrafficRow(event: ConnectionEvent) {
    val (label, color) = when (event.proto) {
        L4Proto.TCP -> "TCP" to BrandBlue
        L4Proto.UDP -> "UDP" to BrandViolet
        L4Proto.ICMP -> "ICMP" to Warning
        L4Proto.OTHER -> "IP" to MaterialTheme.colorScheme.onSurfaceVariant
    }
    val (badge, badgeColor) = when {
        event.tlsPinned -> "TLS" to Warning
        event.isDns -> "DNS" to Warning
        else -> label to color
    }
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.padding(end = 12.dp)) {
            ProtoBadge(badge, badgeColor)
        }
        Column(Modifier.weight(1f)) {
            Text(
                if (event.tlsPinned) event.host ?: "${event.dstIp}:${event.dstPort}"
                else "${event.dstIp}:${event.dstPort}",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
                fontWeight = FontWeight.Medium,
                maxLines = 1,
            )
            Text(
                if (event.tlsPinned) stringResource(R.string.traffic_metadata_pinned)
                else stringResource(R.string.traffic_row_meta, event.srcPort, event.ipVersion, formatBytes(event.length.toLong())),
                style = MaterialTheme.typography.bodyMedium,
                color = if (event.tlsPinned) Warning else MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
            )
        }
        Text(
            timeFormat.format(Date(event.timestampMs)),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun EmptyTraffic() {
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                Icons.Rounded.Timeline,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.outline,
                modifier = Modifier.height(48.dp),
            )
            Spacer(Modifier.height(12.dp))
            Text(
                stringResource(R.string.traffic_empty_title),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Text(
                stringResource(R.string.traffic_empty_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)
