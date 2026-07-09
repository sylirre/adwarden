// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package io.github.sylirre.adwarden.ui.screens

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
import androidx.compose.material.icons.rounded.Code
import androidx.compose.material.icons.rounded.DarkMode
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Lock
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.VisibilityOff
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.sylirre.adwarden.BuildConfig
import io.github.sylirre.adwarden.MainViewModel
import io.github.sylirre.adwarden.R
import io.github.sylirre.adwarden.data.settings.ThemeMode
import io.github.sylirre.adwarden.ui.components.AdwCard
import io.github.sylirre.adwarden.ui.components.SectionTitle
import io.github.sylirre.adwarden.ui.components.ToggleRow
import io.github.sylirre.adwarden.ui.theme.AdwShapes

@Composable
fun SettingsScreen(viewModel: MainViewModel) {
    val dynamicColor by viewModel.dynamicColor.collectAsStateWithLifecycle()
    val themeMode by viewModel.themeMode.collectAsStateWithLifecycle()
    val blockEncryptedDns by viewModel.blockEncryptedDns.collectAsStateWithLifecycle()
    val interceptTls by viewModel.interceptTls.collectAsStateWithLifecycle()
    val cosmeticElementHiding by viewModel.cosmeticElementHiding.collectAsStateWithLifecycle()
    val cosmeticScriptlets by viewModel.cosmeticScriptlets.collectAsStateWithLifecycle()
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
            stringResource(R.string.settings_title),
            style = MaterialTheme.typography.headlineMedium,
            color = MaterialTheme.colorScheme.onBackground,
            modifier = Modifier.padding(top = 16.dp, bottom = 12.dp),
        )

        SectionTitle(stringResource(R.string.settings_appearance))
        AdwCard(Modifier.fillMaxWidth()) {
            Column {
                ThemeModePicker(selected = themeMode, onSelect = viewModel::setThemeMode)
                ToggleRow(
                    title = stringResource(R.string.settings_material_you),
                    subtitle = stringResource(R.string.settings_material_you_sub),
                    checked = dynamicColor,
                    onCheckedChange = viewModel::setDynamicColor,
                    leading = Icons.Rounded.DarkMode,
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle(stringResource(R.string.settings_dns_filtering))
        AdwCard(Modifier.fillMaxWidth()) {
            Column {
                ToggleRow(
                    title = stringResource(R.string.settings_block_encrypted_dns),
                    subtitle = stringResource(R.string.settings_block_encrypted_dns_sub),
                    checked = blockEncryptedDns,
                    onCheckedChange = viewModel::setBlockEncryptedDns,
                    leading = Icons.Rounded.Dns,
                )
                InfoRow(
                    Icons.Rounded.Info,
                    stringResource(R.string.settings_limitation),
                    stringResource(R.string.settings_limitation_body),
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle(stringResource(R.string.settings_https_inspection))
        AdwCard(Modifier.fillMaxWidth()) {
            Column {
                ToggleRow(
                    title = stringResource(R.string.settings_enable_https),
                    subtitle = stringResource(R.string.settings_enable_https_sub),
                    checked = interceptTls,
                    onCheckedChange = viewModel::setInterceptTls,
                    leading = Icons.Rounded.Lock,
                )
                ActionRow(
                    icon = Icons.Rounded.Shield,
                    title = stringResource(R.string.settings_install_ca),
                    subtitle = stringResource(R.string.settings_install_ca_sub),
                    onClick = {
                        viewModel.prepareCaForInstall()
                        showCaWizard = true
                    },
                )
                InfoRow(
                    Icons.Rounded.Info,
                    stringResource(R.string.settings_nonroot_limits),
                    stringResource(R.string.settings_nonroot_limits_body),
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle(stringResource(R.string.settings_cosmetic_filtering))
        AdwCard(Modifier.fillMaxWidth()) {
            Column {
                ToggleRow(
                    title = stringResource(R.string.settings_hide_ad_elements),
                    subtitle = stringResource(R.string.settings_hide_ad_elements_sub),
                    checked = cosmeticElementHiding,
                    onCheckedChange = viewModel::setCosmeticElementHiding,
                    leading = Icons.Rounded.VisibilityOff,
                )
                ToggleRow(
                    title = stringResource(R.string.settings_run_scriptlets),
                    subtitle = stringResource(R.string.settings_run_scriptlets_sub),
                    checked = cosmeticScriptlets,
                    onCheckedChange = viewModel::setCosmeticScriptlets,
                    leading = Icons.Rounded.Code,
                    enabled = cosmeticElementHiding,
                )
                InfoRow(
                    Icons.Rounded.Info,
                    stringResource(R.string.settings_cosmetic_requires),
                    stringResource(R.string.settings_cosmetic_requires_body),
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle(stringResource(R.string.settings_system_integration))
        AdwCard(Modifier.fillMaxWidth()) {
            Column {
                ActionRow(
                    icon = Icons.Rounded.VpnKey,
                    title = stringResource(R.string.settings_always_on),
                    subtitle = stringResource(R.string.settings_always_on_sub),
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
                    stringResource(R.string.settings_qs_tile),
                    stringResource(R.string.settings_qs_tile_sub),
                )
            }
        }

        Spacer(Modifier.height(20.dp))
        SectionTitle(stringResource(R.string.settings_about))
        AdwCard(Modifier.fillMaxWidth()) {
            Column {
                InfoRow(
                    Icons.Rounded.Verified,
                    stringResource(R.string.app_name),
                    stringResource(R.string.settings_about_version, BuildConfig.VERSION_NAME),
                )
                InfoRow(
                    Icons.Rounded.Info,
                    stringResource(R.string.settings_core_title),
                    stringResource(R.string.settings_core_body),
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
            stringResource(R.string.settings_theme),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Spacer(Modifier.height(10.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            ThemeMode.entries.forEach { mode ->
                val label = when (mode) {
                    ThemeMode.SYSTEM -> stringResource(R.string.settings_theme_system)
                    ThemeMode.LIGHT -> stringResource(R.string.settings_theme_light)
                    ThemeMode.DARK -> stringResource(R.string.settings_theme_dark)
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
