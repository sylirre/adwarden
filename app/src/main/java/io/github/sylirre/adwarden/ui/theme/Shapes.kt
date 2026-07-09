// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package io.github.sylirre.adwarden.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

// Adwarden's surfaces are softer than stock M3. These map the recurring radii that
// were previously hardcoded inline across screens/components into one place, and
// feed MaterialTheme so `MaterialTheme.shapes.*` is available too.
val AdwardenShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(24.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

/** Named tokens for component radii so call sites stop repeating magic dp values. */
object AdwShapes {
    val Card = RoundedCornerShape(24.dp)   // AdwCard, StatTile container
    val Field = RoundedCornerShape(16.dp)  // search fields, primary buttons
    val Chip = RoundedCornerShape(12.dp)   // toggles, badges, icon chips
    val Hero = RoundedCornerShape(28.dp)   // dashboard hero card
    val Pill = RoundedCornerShape(20.dp)   // small status pills
}
