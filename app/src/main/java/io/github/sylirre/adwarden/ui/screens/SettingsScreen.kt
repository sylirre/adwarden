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
import androidx.compose.foundation.text.KeyboardOptions
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
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.sylirre.adwarden.BuildConfig
import io.github.sylirre.adwarden.MainViewModel
import io.github.sylirre.adwarden.ProxyUiState
import io.github.sylirre.adwarden.R
import io.github.sylirre.adwarden.data.settings.EncryptedDnsMode
import io.github.sylirre.adwarden.data.settings.ProxyKind
import io.github.sylirre.adwarden.data.settings.ThemeMode
import io.github.sylirre.adwarden.ui.components.AdwCard
import io.github.sylirre.adwarden.ui.components.SectionTitle
import io.github.sylirre.adwarden.ui.components.ToggleRow
import io.github.sylirre.adwarden.ui.theme.AdwShapes

@Composable
fun SettingsScreen(viewModel: MainViewModel) {
    val dynamicColor by viewModel.dynamicColor.collectAsStateWithLifecycle()
    val themeMode by viewModel.themeMode.collectAsStateWithLifecycle()
    val encryptedDnsMode by viewModel.encryptedDnsMode.collectAsStateWithLifecycle()
    val interceptTls by viewModel.interceptTls.collectAsStateWithLifecycle()
    val cosmeticElementHiding by viewModel.cosmeticElementHiding.collectAsStateWithLifecycle()
    val cosmeticScriptlets by viewModel.cosmeticScriptlets.collectAsStateWithLifecycle()
    val proxy by viewModel.proxy.collectAsStateWithLifecycle()
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
                EncryptedDnsPicker(selected = encryptedDnsMode, onSelect = viewModel::setEncryptedDnsMode)
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
        SectionTitle(stringResource(R.string.settings_proxy))
        AdwCard(Modifier.fillMaxWidth()) {
            Column {
                ProxySection(proxy = proxy, onApply = viewModel::setProxy)
                InfoRow(
                    Icons.Rounded.Info,
                    stringResource(R.string.settings_proxy_note),
                    stringResource(R.string.settings_proxy_note_body),
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
private fun EncryptedDnsPicker(selected: EncryptedDnsMode, onSelect: (EncryptedDnsMode) -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Text(
            stringResource(R.string.settings_block_encrypted_dns),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Spacer(Modifier.height(10.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            EncryptedDnsMode.entries.forEach { mode ->
                val label = when (mode) {
                    EncryptedDnsMode.OFF -> stringResource(R.string.settings_encrypted_dns_off)
                    EncryptedDnsMode.BLOCK -> stringResource(R.string.settings_encrypted_dns_block)
                    EncryptedDnsMode.FILTER -> stringResource(R.string.settings_encrypted_dns_filter)
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
        Spacer(Modifier.height(8.dp))
        Text(
            when (selected) {
                EncryptedDnsMode.OFF -> stringResource(R.string.settings_encrypted_dns_off_sub)
                EncryptedDnsMode.BLOCK -> stringResource(R.string.settings_encrypted_dns_block_sub)
                EncryptedDnsMode.FILTER -> stringResource(R.string.settings_encrypted_dns_filter_sub)
            },
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun ProxySection(
    proxy: ProxyUiState,
    onApply: (ProxyKind, String, Int, String, String) -> Unit,
) {
    // Seed local edit state from the saved config; re-seed whenever it changes
    // (e.g. right after Apply, when the DataStore flow re-emits the new values).
    var kind by remember(proxy) { mutableStateOf(proxy.kind) }
    var host by remember(proxy) { mutableStateOf(proxy.host) }
    var port by remember(proxy) { mutableStateOf(if (proxy.port in 1..65535) proxy.port.toString() else "") }
    var username by remember(proxy) { mutableStateOf(proxy.username) }
    var password by remember(proxy) { mutableStateOf(proxy.password) }

    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 12.dp),
    ) {
        Text(
            stringResource(R.string.settings_proxy_type),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
        )
        Spacer(Modifier.height(10.dp))
        ProxyKindPicker(selected = kind, onSelect = { kind = it })

        if (kind != ProxyKind.NONE) {
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = host,
                    onValueChange = { host = it },
                    label = { Text(stringResource(R.string.settings_proxy_host)) },
                    singleLine = true,
                    modifier = Modifier.weight(2f),
                )
                OutlinedTextField(
                    value = port,
                    onValueChange = { new -> port = new.filter { it.isDigit() }.take(5) },
                    label = { Text(stringResource(R.string.settings_proxy_port)) },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.weight(1f),
                )
            }
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = username,
                onValueChange = { username = it },
                label = { Text(stringResource(R.string.settings_proxy_username)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text(stringResource(R.string.settings_proxy_password)) },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
        }

        Spacer(Modifier.height(12.dp))
        val portNum = port.toIntOrNull() ?: 0
        val valid = kind == ProxyKind.NONE || (host.isNotBlank() && portNum in 1..65535)
        val dirty = kind != proxy.kind || host.trim() != proxy.host ||
            portNum != proxy.port || username != proxy.username || password != proxy.password
        Button(
            onClick = { onApply(kind, host.trim(), portNum, username, password) },
            enabled = valid && dirty,
            modifier = Modifier.align(Alignment.End),
        ) {
            Text(stringResource(R.string.settings_proxy_apply))
        }
    }
}

@Composable
private fun ProxyKindPicker(selected: ProxyKind, onSelect: (ProxyKind) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        ProxyKind.entries.forEach { kind ->
            val label = when (kind) {
                ProxyKind.NONE -> stringResource(R.string.settings_proxy_off)
                ProxyKind.HTTP -> "HTTP"
                ProxyKind.HTTPS -> "HTTPS"
                ProxyKind.SOCKS5 -> "SOCKS5"
            }
            val chosen = kind == selected
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
                    .selectable(selected = chosen, role = Role.RadioButton) { onSelect(kind) }
                    .padding(vertical = 10.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    label,
                    style = MaterialTheme.typography.labelMedium,
                    maxLines = 1,
                    color = if (chosen) MaterialTheme.colorScheme.onPrimaryContainer
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                )
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
