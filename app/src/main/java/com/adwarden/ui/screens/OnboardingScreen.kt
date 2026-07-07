package com.adwarden.ui.screens

import android.Manifest
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Bolt
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.FilterAlt
import androidx.compose.material.icons.rounded.Notifications
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Timeline
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adwarden.MainViewModel
import com.adwarden.R
import com.adwarden.ui.components.gradientBrush
import com.adwarden.ui.theme.BrandBlue
import com.adwarden.ui.theme.BrandCyan
import com.adwarden.ui.theme.BrandViolet
import kotlinx.coroutines.launch

private enum class OnbPage { WELCOME, VPN, NOTIFICATIONS, DONE }

/**
 * First-run priming wizard (P3-6). A short pager that explains the app, then asks
 * for the permissions it needs *in context* — VPN consent, then (Android 13+) the
 * status-notification permission — and points at the optional HTTPS-inspection CA.
 * Every permission page is skippable; the app stays usable either way, and the
 * `onboarded` flag is only set when the user finishes, so it isn't re-triggered.
 *
 * The permission launchers live here (Compose `rememberLauncherForActivityResult`)
 * rather than in the Activity, so priming is owned by onboarding. `MainActivity`
 * keeps the imperative consent path as a fallback for the dashboard toggle.
 */
@Composable
fun OnboardingScreen(viewModel: MainViewModel) {
    val context = LocalContext.current
    val caCertPem by viewModel.caCertPem.collectAsStateWithLifecycle()
    var showCaDialog by remember { mutableStateOf(false) }

    // The notification step only exists where the runtime permission does.
    val pages = remember {
        buildList {
            add(OnbPage.WELCOME)
            add(OnbPage.VPN)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) add(OnbPage.NOTIFICATIONS)
            add(OnbPage.DONE)
        }
    }
    val pagerState = rememberPagerState(pageCount = { pages.size })
    val scope = rememberCoroutineScope()

    fun advance() {
        val next = pagerState.currentPage + 1
        if (next < pages.size) {
            scope.launch { pagerState.animateScrollToPage(next) }
        } else {
            viewModel.completeOnboarding()
        }
    }

    // Advance whether consent/permission is granted or declined — this is priming,
    // never a gate.
    val vpnConsent = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { advance() }
    val notifPermission = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { advance() }

    fun requestVpn() {
        val intent = runCatching { VpnService.prepare(context) }.getOrNull()
        if (intent != null) vpnConsent.launch(intent) else advance() // already granted
    }

    fun requestNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            advance()
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .systemBarsPadding()
            .padding(horizontal = 24.dp),
    ) {
        HorizontalPager(
            state = pagerState,
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
        ) { index ->
            when (pages[index]) {
                OnbPage.WELCOME -> WelcomePage()
                OnbPage.VPN -> PrimingPage(
                    icon = Icons.Rounded.VpnKey,
                    tint = BrandBlue,
                    title = stringResource(R.string.onb_vpn_title),
                    body = stringResource(R.string.onb_vpn_body),
                )
                OnbPage.NOTIFICATIONS -> PrimingPage(
                    icon = Icons.Rounded.Notifications,
                    tint = BrandViolet,
                    title = stringResource(R.string.onb_notif_title),
                    body = stringResource(R.string.onb_notif_body),
                )
                OnbPage.DONE -> DonePage(
                    onInstallCa = {
                        viewModel.prepareCaForInstall()
                        showCaDialog = true
                    },
                )
            }
        }

        PagerDots(current = pagerState.currentPage, count = pages.size)
        Spacer(Modifier.height(16.dp))

        val page = pages[pagerState.currentPage]
        val (primaryLabel, primaryAction) = when (page) {
            OnbPage.WELCOME -> stringResource(R.string.onb_continue) to ::advance
            OnbPage.VPN -> stringResource(R.string.onb_vpn_cta) to ::requestVpn
            OnbPage.NOTIFICATIONS -> stringResource(R.string.onb_notif_cta) to ::requestNotifications
            OnbPage.DONE -> stringResource(R.string.onb_start) to viewModel::completeOnboarding
        }
        Button(
            onClick = primaryAction,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = RoundedCornerShape(18.dp),
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.primary),
        ) {
            Text(primaryLabel, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onPrimary)
        }
        // Permission pages are always skippable.
        if (page == OnbPage.VPN || page == OnbPage.NOTIFICATIONS) {
            TextButton(onClick = ::advance, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.onb_skip), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        } else {
            Spacer(Modifier.height(8.dp))
        }
    }

    if (showCaDialog) {
        CaInstallDialog(certPem = caCertPem, onDismiss = { showCaDialog = false })
    }
}

@Composable
private fun WelcomePage() {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
    ) {
        Spacer(Modifier.height(24.dp))
        Box(
            Modifier
                .size(76.dp)
                .clip(RoundedCornerShape(22.dp))
                .background(gradientBrush(listOf(BrandBlue, BrandViolet))),
            contentAlignment = Alignment.Center,
        ) {
            Icon(Icons.Rounded.Shield, contentDescription = null, tint = Color.White, modifier = Modifier.size(40.dp))
        }
        Spacer(Modifier.height(24.dp))
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.displaySmall, color = MaterialTheme.colorScheme.onBackground)
        Text(
            stringResource(R.string.onb_tagline),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(top = 10.dp),
        )
        Spacer(Modifier.height(32.dp))
        FeatureRow(Icons.Rounded.FilterAlt, BrandBlue, stringResource(R.string.onb_feat_filter_title), stringResource(R.string.onb_feat_filter_sub))
        FeatureRow(Icons.Rounded.Bolt, BrandViolet, stringResource(R.string.onb_feat_firewall_title), stringResource(R.string.onb_feat_firewall_sub))
        FeatureRow(Icons.Rounded.Timeline, BrandCyan, stringResource(R.string.onb_feat_traffic_title), stringResource(R.string.onb_feat_traffic_sub))
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun PrimingPage(icon: ImageVector, tint: Color, title: String, body: String) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Box(
            Modifier
                .size(96.dp)
                .clip(RoundedCornerShape(28.dp))
                .background(tint.copy(alpha = 0.15f)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(48.dp))
        }
        Spacer(Modifier.height(28.dp))
        Text(
            title,
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onBackground,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            body,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun DonePage(onInstallCa: () -> Unit) {
    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState()),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Box(
            Modifier
                .size(96.dp)
                .clip(RoundedCornerShape(28.dp))
                .background(gradientBrush(listOf(BrandBlue, BrandCyan))),
            contentAlignment = Alignment.Center,
        ) {
            Icon(Icons.Rounded.CheckCircle, contentDescription = null, tint = Color.White, modifier = Modifier.size(48.dp))
        }
        Spacer(Modifier.height(28.dp))
        Text(
            stringResource(R.string.onb_done_title),
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onBackground,
            fontWeight = FontWeight.SemiBold,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(12.dp))
        Text(
            stringResource(R.string.onb_done_body),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(20.dp))
        TextButton(onClick = onInstallCa) {
            Text(stringResource(R.string.onb_install_ca), color = MaterialTheme.colorScheme.primary)
        }
    }
}

@Composable
private fun PagerDots(current: Int, count: Int) {
    Row(
        Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        repeat(count) { i ->
            val active = i == current
            Box(
                Modifier
                    .padding(horizontal = 4.dp)
                    .size(if (active) 9.dp else 7.dp)
                    .clip(CircleShape)
                    .background(
                        if (active) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.3f),
                    ),
            )
        }
    }
}

@Composable
private fun FeatureRow(icon: ImageVector, tint: Color, title: String, subtitle: String) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            Modifier
                .size(46.dp)
                .clip(RoundedCornerShape(14.dp))
                .background(tint.copy(alpha = 0.15f)),
            contentAlignment = Alignment.Center,
        ) {
            Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(24.dp))
        }
        Column(Modifier.padding(start = 14.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onBackground, fontWeight = FontWeight.SemiBold)
            Text(subtitle, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}
