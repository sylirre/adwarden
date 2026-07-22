// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Sylirre

package io.github.sylirre.adwarden.data.settings

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
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

/**
 * Upstream proxy protocol (P5). Serialized to the native config JSON as the
 * lowercase [name] (`none`/`http`/`https`/`socks5`), matching the Rust `ProxyKind`.
 *  - NONE: dial origins directly (default).
 *  - HTTP: HTTP `CONNECT` over a plaintext link to the proxy.
 *  - HTTPS: HTTP `CONNECT` tunneled inside TLS to the proxy.
 *  - SOCKS5: SOCKS5 with optional username/password auth.
 */
enum class ProxyKind { NONE, HTTP, HTTPS, SOCKS5 }

/**
 * How the datapath treats encrypted DNS (DoT/DoH).
 *  - OFF: leave it alone.
 *  - BLOCK: drop it so clients fall back to plaintext we can filter.
 *  - FILTER: TLS-intercept it and run the inner queries through the blocklist,
 *    degrading to a drop when a flow can't be intercepted (requires the CA).
 * Serialized to the native config JSON as the lowercase [name].
 */
enum class EncryptedDnsMode { OFF, BLOCK, FILTER }

/** User preferences persisted to a Preferences DataStore. */
data class AppSettings(
    val onboarded: Boolean = false,
    val dynamicColor: Boolean = false,
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    val encryptedDnsMode: EncryptedDnsMode = EncryptedDnsMode.OFF,
    val interceptTls: Boolean = false,
    /** The user's intended protection state, persisted across process death so the
     *  Quick Settings tile and boot/always-on reasoning know what was asked (P3-5).
     *  This is intent, not the live running state (that's NativeSessionHolder). */
    val desiredProtection: Boolean = false,
    /** Element hiding (P4): inject cosmetic CSS into HTML on inspected apps. */
    val cosmeticElementHiding: Boolean = false,
    /** Scriptlet injection (P4): gated behind element hiding + a downloaded pack. */
    val cosmeticScriptlets: Boolean = false,
    /** Live traffic monitoring: whether the Traffic screen streams and displays
     *  per-flow telemetry. Off by default; a pure display/telemetry preference that
     *  never affects filtering (it only gates the [LiveLogState] demand signal). */
    val liveTrafficMonitoring: Boolean = false,
    /** Upstream proxy (P5). A start-time setting: changing any field re-establishes
     *  the tunnel. [proxyHost] may be a hostname or IP (resolved at start). */
    val proxyKind: ProxyKind = ProxyKind.NONE,
    val proxyHost: String = "",
    val proxyPort: Int = 0,
    val proxyUsername: String = "",
    val proxyPassword: String = "",
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
            // New tri-state key wins; fall back to the legacy boolean (true ⇒ BLOCK)
            // so an upgrading user who was blocking keeps blocking.
            encryptedDnsMode = prefs[KEY_ENCRYPTED_DNS_MODE]
                ?.let { runCatching { EncryptedDnsMode.valueOf(it) }.getOrNull() }
                ?: if (prefs[KEY_BLOCK_ENCRYPTED_DNS] == true) EncryptedDnsMode.BLOCK else EncryptedDnsMode.OFF,
            interceptTls = prefs[KEY_INTERCEPT_TLS] ?: false,
            desiredProtection = prefs[KEY_DESIRED_PROTECTION] ?: false,
            cosmeticElementHiding = prefs[KEY_COSMETIC_ELEMENT_HIDING] ?: false,
            cosmeticScriptlets = prefs[KEY_COSMETIC_SCRIPTLETS] ?: false,
            liveTrafficMonitoring = prefs[KEY_LIVE_TRAFFIC] ?: false,
            proxyKind = prefs[KEY_PROXY_KIND]
                ?.let { runCatching { ProxyKind.valueOf(it) }.getOrNull() }
                ?: ProxyKind.NONE,
            proxyHost = prefs[KEY_PROXY_HOST] ?: "",
            proxyPort = prefs[KEY_PROXY_PORT] ?: 0,
            proxyUsername = prefs[KEY_PROXY_USERNAME] ?: "",
            proxyPassword = prefs[KEY_PROXY_PASSWORD] ?: "",
        )
    }

    suspend fun setOnboarded(value: Boolean) = store.edit { it[KEY_ONBOARDED] = value }

    suspend fun setDynamicColor(value: Boolean) = store.edit { it[KEY_DYNAMIC_COLOR] = value }

    suspend fun setThemeMode(value: ThemeMode) = store.edit { it[KEY_THEME_MODE] = value.name }

    suspend fun setEncryptedDnsMode(value: EncryptedDnsMode) =
        store.edit { it[KEY_ENCRYPTED_DNS_MODE] = value.name }

    suspend fun setInterceptTls(value: Boolean) =
        store.edit { it[KEY_INTERCEPT_TLS] = value }

    suspend fun setDesiredProtection(value: Boolean) =
        store.edit { it[KEY_DESIRED_PROTECTION] = value }

    suspend fun setCosmeticElementHiding(value: Boolean) =
        store.edit { it[KEY_COSMETIC_ELEMENT_HIDING] = value }

    suspend fun setCosmeticScriptlets(value: Boolean) =
        store.edit { it[KEY_COSMETIC_SCRIPTLETS] = value }

    suspend fun setLiveTrafficMonitoring(value: Boolean) =
        store.edit { it[KEY_LIVE_TRAFFIC] = value }

    /** Persist the whole proxy config in one edit, so a change fans out as a single
     *  settings emission (one tunnel re-establish, not one per field). */
    suspend fun setProxy(kind: ProxyKind, host: String, port: Int, username: String, password: String) =
        store.edit {
            it[KEY_PROXY_KIND] = kind.name
            it[KEY_PROXY_HOST] = host.trim()
            it[KEY_PROXY_PORT] = port
            it[KEY_PROXY_USERNAME] = username
            it[KEY_PROXY_PASSWORD] = password
        }

    private companion object {
        val KEY_ONBOARDED = booleanPreferencesKey("onboarded")
        val KEY_DYNAMIC_COLOR = booleanPreferencesKey("dynamic_color")
        val KEY_THEME_MODE = stringPreferencesKey("theme_mode")
        // Legacy boolean, read only for migration into KEY_ENCRYPTED_DNS_MODE.
        val KEY_BLOCK_ENCRYPTED_DNS = booleanPreferencesKey("block_encrypted_dns")
        val KEY_ENCRYPTED_DNS_MODE = stringPreferencesKey("encrypted_dns_mode")
        val KEY_INTERCEPT_TLS = booleanPreferencesKey("intercept_tls")
        val KEY_DESIRED_PROTECTION = booleanPreferencesKey("desired_protection")
        val KEY_COSMETIC_ELEMENT_HIDING = booleanPreferencesKey("cosmetic_element_hiding")
        val KEY_COSMETIC_SCRIPTLETS = booleanPreferencesKey("cosmetic_scriptlets")
        val KEY_LIVE_TRAFFIC = booleanPreferencesKey("live_traffic_monitoring")
        val KEY_PROXY_KIND = stringPreferencesKey("proxy_kind")
        val KEY_PROXY_HOST = stringPreferencesKey("proxy_host")
        val KEY_PROXY_PORT = intPreferencesKey("proxy_port")
        val KEY_PROXY_USERNAME = stringPreferencesKey("proxy_username")
        val KEY_PROXY_PASSWORD = stringPreferencesKey("proxy_password")
    }
}
