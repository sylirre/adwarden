// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package io.github.sylirre.adwarden.data.settings

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import androidx.datastore.preferences.SharedPreferencesMigration
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

/** How the app resolves light/dark, independent of the Material You palette. */
enum class ThemeMode { SYSTEM, LIGHT, DARK }

/** User preferences persisted to a Preferences DataStore. */
data class AppSettings(
    val onboarded: Boolean = false,
    val dynamicColor: Boolean = false,
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    val blockEncryptedDns: Boolean = false,
    val interceptTls: Boolean = false,
    /** The user's intended protection state, persisted across process death so the
     *  Quick Settings tile and boot/always-on reasoning know what was asked (P3-5).
     *  This is intent, not the live running state (that's NativeSessionHolder). */
    val desiredProtection: Boolean = false,
    /** Element hiding (P4): inject cosmetic CSS into HTML on inspected apps. */
    val cosmeticElementHiding: Boolean = false,
    /** Scriptlet injection (P4): gated behind element hiding + a downloaded pack. */
    val cosmeticScriptlets: Boolean = false,
)

// One process-wide DataStore. The migration imports the P0 onboarding flag from
// the legacy "adwarden" SharedPreferences file (matching key + type), so an
// upgrading user is not re-onboarded.
private val Context.settingsDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "adwarden_settings",
    produceMigrations = { ctx -> listOf(SharedPreferencesMigration(ctx, "adwarden")) },
)

@Singleton
class SettingsRepository @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val store get() = context.settingsDataStore

    val settings: Flow<AppSettings> = store.data.map { prefs ->
        AppSettings(
            onboarded = prefs[KEY_ONBOARDED] ?: false,
            dynamicColor = prefs[KEY_DYNAMIC_COLOR] ?: false,
            themeMode = prefs[KEY_THEME_MODE]?.let { runCatching { ThemeMode.valueOf(it) }.getOrNull() }
                ?: ThemeMode.SYSTEM,
            blockEncryptedDns = prefs[KEY_BLOCK_ENCRYPTED_DNS] ?: false,
            interceptTls = prefs[KEY_INTERCEPT_TLS] ?: false,
            desiredProtection = prefs[KEY_DESIRED_PROTECTION] ?: false,
            cosmeticElementHiding = prefs[KEY_COSMETIC_ELEMENT_HIDING] ?: false,
            cosmeticScriptlets = prefs[KEY_COSMETIC_SCRIPTLETS] ?: false,
        )
    }

    suspend fun setOnboarded(value: Boolean) = store.edit { it[KEY_ONBOARDED] = value }

    suspend fun setDynamicColor(value: Boolean) = store.edit { it[KEY_DYNAMIC_COLOR] = value }

    suspend fun setThemeMode(value: ThemeMode) = store.edit { it[KEY_THEME_MODE] = value.name }

    suspend fun setBlockEncryptedDns(value: Boolean) =
        store.edit { it[KEY_BLOCK_ENCRYPTED_DNS] = value }

    suspend fun setInterceptTls(value: Boolean) =
        store.edit { it[KEY_INTERCEPT_TLS] = value }

    suspend fun setDesiredProtection(value: Boolean) =
        store.edit { it[KEY_DESIRED_PROTECTION] = value }

    suspend fun setCosmeticElementHiding(value: Boolean) =
        store.edit { it[KEY_COSMETIC_ELEMENT_HIDING] = value }

    suspend fun setCosmeticScriptlets(value: Boolean) =
        store.edit { it[KEY_COSMETIC_SCRIPTLETS] = value }

    private companion object {
        val KEY_ONBOARDED = booleanPreferencesKey("onboarded")
        val KEY_DYNAMIC_COLOR = booleanPreferencesKey("dynamic_color")
        val KEY_THEME_MODE = stringPreferencesKey("theme_mode")
        val KEY_BLOCK_ENCRYPTED_DNS = booleanPreferencesKey("block_encrypted_dns")
        val KEY_INTERCEPT_TLS = booleanPreferencesKey("intercept_tls")
        val KEY_DESIRED_PROTECTION = booleanPreferencesKey("desired_protection")
        val KEY_COSMETIC_ELEMENT_HIDING = booleanPreferencesKey("cosmetic_element_hiding")
        val KEY_COSMETIC_SCRIPTLETS = booleanPreferencesKey("cosmetic_scriptlets")
    }
}
