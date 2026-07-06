package com.adwarden.data.settings

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.preferencesDataStore
import androidx.datastore.preferences.SharedPreferencesMigration
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import javax.inject.Inject
import javax.inject.Singleton

/** User preferences persisted to a Preferences DataStore. */
data class AppSettings(
    val onboarded: Boolean = false,
    val dynamicColor: Boolean = false,
    val blockEncryptedDns: Boolean = false,
    val interceptTls: Boolean = false,
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
            blockEncryptedDns = prefs[KEY_BLOCK_ENCRYPTED_DNS] ?: false,
            interceptTls = prefs[KEY_INTERCEPT_TLS] ?: false,
        )
    }

    suspend fun setOnboarded(value: Boolean) = store.edit { it[KEY_ONBOARDED] = value }

    suspend fun setDynamicColor(value: Boolean) = store.edit { it[KEY_DYNAMIC_COLOR] = value }

    suspend fun setBlockEncryptedDns(value: Boolean) =
        store.edit { it[KEY_BLOCK_ENCRYPTED_DNS] = value }

    suspend fun setInterceptTls(value: Boolean) =
        store.edit { it[KEY_INTERCEPT_TLS] = value }

    private companion object {
        val KEY_ONBOARDED = booleanPreferencesKey("onboarded")
        val KEY_DYNAMIC_COLOR = booleanPreferencesKey("dynamic_color")
        val KEY_BLOCK_ENCRYPTED_DNS = booleanPreferencesKey("block_encrypted_dns")
        val KEY_INTERCEPT_TLS = booleanPreferencesKey("intercept_tls")
    }
}
