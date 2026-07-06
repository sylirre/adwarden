package com.adwarden.ui

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.layout.windowInsetsPadding
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
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.NavigationRailItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.windowsizeclass.WindowWidthSizeClass
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
    DASHBOARD("Dashboard", Icons.Rounded.Shield),
    APPS("Apps", Icons.Rounded.Apps),
    TRAFFIC("Traffic", Icons.Rounded.Timeline),
    FILTERS("Filters", Icons.Rounded.FilterAlt),
    SETTINGS("Settings", Icons.Rounded.Settings),
}

@Composable
fun AdwardenRoot(
    viewModel: MainViewModel,
    onToggleProtection: () -> Unit,
    widthSizeClass: WindowWidthSizeClass,
) {
    val onboarded by viewModel.onboarded.collectAsStateWithLifecycle()
    if (!onboarded) {
        OnboardingScreen(onGetStarted = viewModel::completeOnboarding)
        return
    }
    MainScaffold(viewModel, onToggleProtection, widthSizeClass)
}

@Composable
private fun MainScaffold(
    viewModel: MainViewModel,
    onToggleProtection: () -> Unit,
    widthSizeClass: WindowWidthSizeClass,
) {
    var index by rememberSaveable { mutableIntStateOf(0) }
    val destinations = Destination.entries
    val dest = destinations[index]

    // Compact (phones in portrait) keeps the bottom bar; wider layouts — tablets,
    // unfolded foldables, landscape — switch to a side rail so navigation doesn't
    // eat vertical space and the reach is better on large screens.
    val useRail = widthSizeClass != WindowWidthSizeClass.Compact

    if (useRail) {
        Row(Modifier.fillMaxSize()) {
            NavigationRail(containerColor = MaterialTheme.colorScheme.surface) {
                destinations.forEachIndexed { i, d ->
                    NavigationRailItem(
                        selected = index == i,
                        onClick = { index = i },
                        icon = { Icon(d.icon, contentDescription = d.label) },
                        label = { Text(d.label) },
                        colors = NavigationRailItemDefaults.colors(
                            selectedIconColor = MaterialTheme.colorScheme.onPrimaryContainer,
                            indicatorColor = MaterialTheme.colorScheme.primaryContainer,
                            selectedTextColor = MaterialTheme.colorScheme.primary,
                        ),
                    )
                }
            }
            Box(
                Modifier
                    .fillMaxSize()
                    // The rail owns the start + vertical insets; the content pane
                    // only needs to clear the status bar (top), the far edge (end)
                    // and the gesture area (bottom).
                    .windowInsetsPadding(
                        WindowInsets.systemBars.only(
                            WindowInsetsSides.Top + WindowInsetsSides.End + WindowInsetsSides.Bottom,
                        ),
                    ),
            ) {
                ScreenContent(dest, viewModel, onToggleProtection)
            }
        }
    } else {
        Scaffold(
            containerColor = MaterialTheme.colorScheme.background,
            bottomBar = {
                NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                    destinations.forEachIndexed { i, d ->
                        NavigationBarItem(
                            selected = index == i,
                            onClick = { index = i },
                            icon = { Icon(d.icon, contentDescription = d.label) },
                            label = { Text(d.label) },
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
                ScreenContent(dest, viewModel, onToggleProtection)
            }
        }
    }
}

@Composable
private fun ScreenContent(
    destination: Destination,
    viewModel: MainViewModel,
    onToggleProtection: () -> Unit,
) {
    when (destination) {
        Destination.DASHBOARD -> DashboardScreen(viewModel, onToggleProtection)
        Destination.APPS -> AppsScreen()
        Destination.TRAFFIC -> TrafficScreen(viewModel)
        Destination.FILTERS -> FiltersScreen()
        Destination.SETTINGS -> SettingsScreen(viewModel)
    }
}
