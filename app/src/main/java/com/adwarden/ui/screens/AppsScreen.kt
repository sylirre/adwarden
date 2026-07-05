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
import androidx.compose.material.icons.rounded.SignalCellularAlt
import androidx.compose.material.icons.rounded.Wifi
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.adwarden.ui.components.AdwCard
import com.adwarden.ui.theme.BrandBlue
import com.adwarden.ui.theme.BrandCyan
import com.adwarden.ui.theme.BrandViolet
import com.adwarden.ui.theme.Success
import com.adwarden.ui.theme.Warning

private data class SampleApp(val name: String, val pkg: String, val tint: Color)

private val sampleApps = listOf(
    SampleApp("Chrome", "com.android.chrome", BrandBlue),
    SampleApp("YouTube", "com.google.android.youtube", Warning),
    SampleApp("Maps", "com.google.android.apps.maps", Success),
    SampleApp("Gmail", "com.google.android.gm", BrandViolet),
    SampleApp("Photos", "com.google.android.apps.photos", BrandCyan),
    SampleApp("Play Store", "com.android.vending", Success),
    SampleApp("Messages", "com.google.android.apps.messaging", BrandBlue),
    SampleApp("Files", "com.google.android.documentsui", BrandViolet),
)

@Composable
fun AppsScreen() {
    val wifiAllowed = remember { mutableStateMapOf<String, Boolean>() }
    val mobileAllowed = remember { mutableStateMapOf<String, Boolean>() }

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
            "Per-app firewall preview · enforcement lands in P1",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(bottom = 12.dp),
        )
        LazyColumn(
            Modifier.fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            items(sampleApps, key = { it.pkg }) { app ->
                AppCard(
                    app = app,
                    wifi = wifiAllowed[app.pkg] ?: true,
                    mobile = mobileAllowed[app.pkg] ?: true,
                    onWifi = { wifiAllowed[app.pkg] = !(wifiAllowed[app.pkg] ?: true) },
                    onMobile = { mobileAllowed[app.pkg] = !(mobileAllowed[app.pkg] ?: true) },
                )
            }
            item { Spacer(Modifier.height(12.dp)) }
        }
    }
}

@Composable
private fun AppCard(
    app: SampleApp,
    wifi: Boolean,
    mobile: Boolean,
    onWifi: () -> Unit,
    onMobile: () -> Unit,
) {
    AdwCard(Modifier.fillMaxWidth()) {
        Row(
            Modifier.padding(14.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                Modifier
                    .size(42.dp)
                    .clip(RoundedCornerShape(13.dp))
                    .background(app.tint.copy(alpha = 0.16f)),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    app.name.first().toString(),
                    style = MaterialTheme.typography.titleMedium,
                    color = app.tint,
                    fontWeight = FontWeight.Bold,
                )
            }
            Column(
                Modifier
                    .weight(1f)
                    .padding(horizontal = 12.dp),
            ) {
                Text(app.name, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    if (!wifi && !mobile) "Blocked everywhere" else if (!wifi) "Wi-Fi blocked" else if (!mobile) "Mobile blocked" else "Allowed",
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (!wifi || !mobile) Warning else MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            MiniToggle(Icons.Rounded.Wifi, wifi, onWifi)
            Spacer(Modifier.size(8.dp))
            MiniToggle(Icons.Rounded.SignalCellularAlt, mobile, onMobile)
        }
    }
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
