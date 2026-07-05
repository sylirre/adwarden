package com.adwarden.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Apps
import androidx.compose.material.icons.rounded.FilterAlt
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Timeline
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.adwarden.MainViewModel
import com.adwarden.ui.screens.AppsScreen
import com.adwarden.ui.screens.DashboardScreen
import com.adwarden.ui.screens.FiltersScreen
import com.adwarden.ui.screens.OnboardingScreen
import com.adwarden.ui.screens.SettingsScreen
import com.adwarden.ui.screens.TrafficScreen

private enum class Destination(val label: String, val icon: ImageVector) {
    DASHBOARD("Shield", Icons.Rounded.Shield),
    APPS("Apps", Icons.Rounded.Apps),
    TRAFFIC("Traffic", Icons.Rounded.Timeline),
    FILTERS("Filters", Icons.Rounded.FilterAlt),
    SETTINGS("Settings", Icons.Rounded.Settings),
}

@Composable
fun AdwardenRoot(
    viewModel: MainViewModel,
    onToggleProtection: () -> Unit,
) {
    val onboarded by viewModel.onboarded.collectAsStateWithLifecycle()
    if (!onboarded) {
        OnboardingScreen(onGetStarted = viewModel::completeOnboarding)
        return
    }
    MainScaffold(viewModel, onToggleProtection)
}

@Composable
private fun MainScaffold(
    viewModel: MainViewModel,
    onToggleProtection: () -> Unit,
) {
    var index by rememberSaveable { mutableIntStateOf(0) }
    val destinations = Destination.entries

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = {
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surface,
            ) {
                destinations.forEachIndexed { i, dest ->
                    NavigationBarItem(
                        selected = index == i,
                        onClick = { index = i },
                        icon = { Icon(dest.icon, contentDescription = dest.label) },
                        label = { Text(dest.label) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = MaterialTheme.colorScheme.onPrimaryContainer,
                            indicatorColor = MaterialTheme.colorScheme.primaryContainer,
                            selectedTextColor = MaterialTheme.colorScheme.primary,
                        ),
                    )
                }
            }
        },
    ) { innerPadding ->
        Box(
            Modifier
                .fillMaxSize()
                .padding(innerPadding),
        ) {
            when (destinations[index]) {
                Destination.DASHBOARD -> DashboardScreen(viewModel, onToggleProtection)
                Destination.APPS -> AppsScreen()
                Destination.TRAFFIC -> TrafficScreen(viewModel)
                Destination.FILTERS -> FiltersScreen()
                Destination.SETTINGS -> SettingsScreen(viewModel)
            }
        }
    }
}
