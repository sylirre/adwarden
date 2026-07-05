package com.adwarden.ui.screens

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.DarkMode
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adwarden.MainViewModel
import com.adwarden.ui.components.AdwCard
import com.adwarden.ui.components.SectionTitle
import com.adwarden.ui.components.ToggleRow

@Composable
fun SettingsScreen(viewModel: MainViewModel) {
    val dynamicColor by viewModel.dynamicColor.collectAsStateWithLifecycle()
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
    ) {
        Text(
            "Settings",
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.onBackground,
            modifier = Modifier.padding(top = 16.dp, bottom = 12.dp),
        )

        SectionTitle("Appearance")
        AdwCard(Modifier.fillMaxWidth()) {
            ToggleRow(
                title = "Material You colors",
                subtitle = "Match the system wallpaper palette (Android 12+)",
                checked = dynamicColor,
                onCheckedChange = viewModel::setDynamicColor,
                leading = Icons.Rounded.DarkMode,
            )
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle("HTTPS inspection")
        AdwCard(Modifier.fillMaxWidth()) {
            Column {
                InfoRow(
                    Icons.Rounded.Lock,
                    "Certificate authority",
                    "Generate and install Adwarden's CA to decrypt cooperating apps. Guided wizard arrives in P2.",
                )
                InfoRow(
                    Icons.Rounded.Info,
                    "Non-root limits",
                    "Without root, Android only lets us decrypt apps that trust user certificates (e.g. Chrome). Blocking, logging and PCAP still work for every app.",
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle("About")
        AdwCard(Modifier.fillMaxWidth()) {
            Column {
                InfoRow(Icons.Rounded.Verified, "Adwarden", "Version 0.1.0 · P0 preview")
                InfoRow(
                    Icons.Rounded.Info,
                    "Capture mode",
                    "Monitor — packets are inspected, not yet forwarded. Transparent forwarding lands with the native core (P1/P2).",
                )
            }
        }
        Spacer(Modifier.height(24.dp))
    }
}

@Composable
private fun InfoRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    subtitle: String,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier
                .padding(end = 14.dp, top = 2.dp)
                .height(22.dp),
        )
        Column(Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurface, fontWeight = FontWeight.Medium)
            Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
