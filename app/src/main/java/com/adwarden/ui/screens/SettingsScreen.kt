package com.adwarden.ui.screens

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.DarkMode
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Verified
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adwarden.MainViewModel
import com.adwarden.data.settings.ThemeMode
import com.adwarden.ui.components.AdwCard
import com.adwarden.ui.components.SectionTitle
import com.adwarden.ui.components.ToggleRow
import com.adwarden.ui.theme.AdwShapes

@Composable
fun SettingsScreen(viewModel: MainViewModel) {
    val dynamicColor by viewModel.dynamicColor.collectAsStateWithLifecycle()
    val themeMode by viewModel.themeMode.collectAsStateWithLifecycle()
    val blockEncryptedDns by viewModel.blockEncryptedDns.collectAsStateWithLifecycle()
    val interceptTls by viewModel.interceptTls.collectAsStateWithLifecycle()
    val caCertPem by viewModel.caCertPem.collectAsStateWithLifecycle()
    var showCaWizard by remember { mutableStateOf(false) }
    val context = LocalContext.current
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
            Column {
                ThemeModePicker(selected = themeMode, onSelect = viewModel::setThemeMode)
                ToggleRow(
                    title = "Material You colors",
                    subtitle = "Match the system wallpaper palette (Android 12+)",
                    checked = dynamicColor,
                    onCheckedChange = viewModel::setDynamicColor,
                    leading = Icons.Rounded.DarkMode,
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle("DNS filtering")
        AdwCard(Modifier.fillMaxWidth()) {
            Column {
                ToggleRow(
                    title = "Block encrypted DNS",
                    subtitle = "Deny DoT/DoH so queries fall back to plaintext we can filter.",
                    checked = blockEncryptedDns,
                    onCheckedChange = viewModel::setBlockEncryptedDns,
                    leading = Icons.Rounded.Dns,
                )
                InfoRow(
                    Icons.Rounded.Info,
                    "Limitation",
                    "Android Private DNS and DoH over 443 can still bypass plaintext filtering; this only forces the common fallbacks.",
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle("HTTPS inspection")
        AdwCard(Modifier.fillMaxWidth()) {
            Column {
                ToggleRow(
                    title = "Enable HTTPS inspection",
                    subtitle = "Master switch. Choose which apps to inspect on the Apps tab; nothing is intercepted until you do. Install the CA first. Applies on next connection.",
                    checked = interceptTls,
                    onCheckedChange = viewModel::setInterceptTls,
                    leading = Icons.Rounded.Lock,
                )
                ActionRow(
                    icon = Icons.Rounded.Shield,
                    title = "Install Adwarden CA",
                    subtitle = "Trust the root certificate so decryption can work.",
                    onClick = {
                        viewModel.prepareCaForInstall()
                        showCaWizard = true
                    },
                )
                InfoRow(
                    Icons.Rounded.Info,
                    "Non-root limits",
                    "Without root, Android only lets us decrypt apps that trust user certificates (e.g. Chrome). Blocking, logging and PCAP still work for every app.",
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle("System integration")
        AdwCard(Modifier.fillMaxWidth()) {
            Column {
                ActionRow(
                    icon = Icons.Rounded.VpnKey,
                    title = "Always-on VPN",
                    subtitle = "Open Android's VPN settings to keep Adwarden always connected, and optionally block traffic while it's off (lockdown).",
                    onClick = {
                        runCatching {
                            context.startActivity(
                                Intent(Settings.ACTION_VPN_SETTINGS)
                                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                            )
                        }
                    },
                )
                InfoRow(
                    Icons.Rounded.Info,
                    "Quick Settings tile",
                    "Add the Adwarden tile from the Quick Settings edit panel to toggle protection without opening the app.",
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

    if (showCaWizard) {
        CaInstallDialog(certPem = caCertPem, onDismiss = { showCaWizard = false })
    }
}

@Composable
private fun ThemeModePicker(selected: ThemeMode, onSelect: (ThemeMode) -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Text(
            "Theme",
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Spacer(Modifier.height(10.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ThemeMode.entries.forEach { mode ->
                val label = when (mode) {
                    ThemeMode.SYSTEM -> "System"
                    ThemeMode.LIGHT -> "Light"
                    ThemeMode.DARK -> "Dark"
                }
                val chosen = mode == selected
                Box(
                    Modifier
                        .weight(1f)
                        .clip(AdwShapes.Field)
                        .background(
                            if (chosen) MaterialTheme.colorScheme.primaryContainer else Color.Transparent,
                        )
                        .border(
                            1.dp,
                            if (chosen) Color.Transparent else MaterialTheme.colorScheme.outlineVariant,
                            AdwShapes.Field,
                        )
                        .selectable(selected = chosen, role = Role.RadioButton) { onSelect(mode) }
                        .padding(vertical = 10.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        label,
                        style = MaterialTheme.typography.labelLarge,
                        color = if (chosen) MaterialTheme.colorScheme.onPrimaryContainer
                        else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun ActionRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    subtitle: String,
    onClick: () -> Unit,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
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
