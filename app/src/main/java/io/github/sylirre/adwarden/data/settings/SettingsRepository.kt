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

/** Saved connection details for one proxy type (P5). HTTP, HTTPS and SOCKS5 each
 *  keep their own, so switching the active type never discards the others. */
data class ProxyEndpoint(
    val host: String = "",
    val port: Int = 0,
    val username: String = "",
    val password: String = "",
)

/**
 * How the datapath treats encrypted DNS (DoT/DoH).
 *  - OFF: leave it alone.
 *  - BLOCK: drop it so clients fall back to plaintext we can filter.
 *  - FILTER: TLS-intercept it and run the inner queries through the blocklist,
 *    degrading to a drop when a flow can't be intercepted (requires the CA).
 * Serialized to the native config JSON as the lowercase [name].
 */
enum class EncryptedDnsMode { OFF, BLOCK, FILTER }

/**
 * Transport used to reach the *upstream* resolver for allowed DNS (P6).
 *  - PLAIN: cleartext Do53 (an IP + port).
 *  - DOT: DNS-over-TLS to a named resolver (RFC 7858).
 *  - DOH: DNS-over-HTTPS to a resolver URL (RFC 8484).
 * Serialized to the native config JSON as the lowercase [name] (`plain`/`dot`/`doh`),
 * matching the Rust `DnsTransport`. Orthogonal to [EncryptedDnsMode].
 */
enum class DnsTransport { PLAIN, DOT, DOH }

/** User preferences persisted to a Preferences DataStore. */
data class AppSettings(
    val onboarded: Boolean = false,
    val dynamicColor: Boolean = false,
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    val encryptedDnsMode: EncryptedDnsMode = EncryptedDnsMode.OFF,
    val interceptTls: Boolean = false,
    /** Custom upstream resolver (P6), applied live via nativeUpdateConfig.
     *  [dnsTransport] selects the transport; each transport keeps its own fields so
     *  switching doesn't lose the others.
     *  - PLAIN: [dnsServer] (blank ⇒ built-in default 1.1.1.1) + [dnsPort].
     *  - DOT: [dnsDotHost] (resolver hostname) + [dnsDotPort] (853).
     *  - DOH: [dnsDohUrl] (e.g. https://cloudflare-dns.com/dns-query). */
    val dnsTransport: DnsTransport = DnsTransport.PLAIN,
    val dnsServer: String = "",
    val dnsPort: Int = 53,
    val dnsDotHost: String = "",
    val dnsDotPort: Int = 853,
    val dnsDohUrl: String = "",
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
    /** Upstream proxy (P5). [proxyKind] selects the active type; each type keeps its
     *  own saved [ProxyEndpoint] so switching types doesn't lose the others' details.
     *  A start-time setting: changing the active config re-establishes the tunnel.
     *  A host may be a hostname or IP (resolved at start). */
    val proxyKind: ProxyKind = ProxyKind.NONE,
    val httpProxy: ProxyEndpoint = ProxyEndpoint(),
    val httpsProxy: ProxyEndpoint = ProxyEndpoint(),
    val socks5Proxy: ProxyEndpoint = ProxyEndpoint(),
    /** Route DNS through an HTTP/HTTPS proxy via DNS-over-TCP (P5). Live; no effect
     *  without an HTTP/HTTPS proxy (SOCKS5 always carries DNS itself). Off by
     *  default — needs the proxy to allow CONNECT to the resolver's port. */
    val proxyDnsOverTcp: Boolean = false,
)

/** The saved endpoint for the active [AppSettings.proxyKind], or null when off. */
fun AppSettings.activeProxy(): ProxyEndpoint? = when (proxyKind) {
    ProxyKind.HTTP -> httpProxy
    ProxyKind.HTTPS -> httpsProxy
    ProxyKind.SOCKS5 -> socks5Proxy
    ProxyKind.NONE -> null
}

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
            dnsTransport = prefs[KEY_DNS_TRANSPORT]
                ?.let { runCatching { DnsTransport.valueOf(it) }.getOrNull() }
                ?: DnsTransport.PLAIN,
            dnsServer = prefs[KEY_DNS_SERVER] ?: "",
            dnsPort = prefs[KEY_DNS_PORT]?.takeIf { it in 1..65535 } ?: 53,
            dnsDotHost = prefs[KEY_DNS_DOT_HOST] ?: "",
            dnsDotPort = prefs[KEY_DNS_DOT_PORT]?.takeIf { it in 1..65535 } ?: 853,
            dnsDohUrl = prefs[KEY_DNS_DOH_URL] ?: "",
            desiredProtection = prefs[KEY_DESIRED_PROTECTION] ?: false,
            cosmeticElementHiding = prefs[KEY_COSMETIC_ELEMENT_HIDING] ?: false,
            cosmeticScriptlets = prefs[KEY_COSMETIC_SCRIPTLETS] ?: false,
            liveTrafficMonitoring = prefs[KEY_LIVE_TRAFFIC] ?: false,
            proxyKind = prefs[KEY_PROXY_KIND]
                ?.let { runCatching { ProxyKind.valueOf(it) }.getOrNull() }
                ?: ProxyKind.NONE,
            httpProxy = readEndpoint(prefs, "http"),
            httpsProxy = readEndpoint(prefs, "https"),
            socks5Proxy = readEndpoint(prefs, "socks5"),
            proxyDnsOverTcp = prefs[KEY_PROXY_DNS_OVER_TCP] ?: false,
        )
    }

    suspend fun setOnboarded(value: Boolean) = store.edit { it[KEY_ONBOARDED] = value }

    suspend fun setDynamicColor(value: Boolean) = store.edit { it[KEY_DYNAMIC_COLOR] = value }

    suspend fun setThemeMode(value: ThemeMode) = store.edit { it[KEY_THEME_MODE] = value.name }

    suspend fun setEncryptedDnsMode(value: EncryptedDnsMode) =
        store.edit { it[KEY_ENCRYPTED_DNS_MODE] = value.name }

    suspend fun setInterceptTls(value: Boolean) =
        store.edit { it[KEY_INTERCEPT_TLS] = value }

    /** Persist the custom upstream resolver (P6) in one edit ⇒ one settings
     *  emission ⇒ one live config push. Stores the transport plus every transport's
     *  fields so switching between plain/DoT/DoH never loses the others. A blank
     *  plain [server] clears the override (back to the default resolver). Ports are
     *  expected pre-validated (1..65535). */
    suspend fun setCustomDns(
        transport: DnsTransport,
        server: String,
        port: Int,
        dotHost: String,
        dotPort: Int,
        dohUrl: String,
    ) = store.edit {
        it[KEY_DNS_TRANSPORT] = transport.name
        it[KEY_DNS_SERVER] = server.trim()
        it[KEY_DNS_PORT] = port
        it[KEY_DNS_DOT_HOST] = dotHost.trim()
        it[KEY_DNS_DOT_PORT] = dotPort
        it[KEY_DNS_DOH_URL] = dohUrl.trim()
    }

    suspend fun setDesiredProtection(value: Boolean) =
        store.edit { it[KEY_DESIRED_PROTECTION] = value }

    suspend fun setCosmeticElementHiding(value: Boolean) =
        store.edit { it[KEY_COSMETIC_ELEMENT_HIDING] = value }

    suspend fun setCosmeticScriptlets(value: Boolean) =
        store.edit { it[KEY_COSMETIC_SCRIPTLETS] = value }

    suspend fun setLiveTrafficMonitoring(value: Boolean) =
        store.edit { it[KEY_LIVE_TRAFFIC] = value }

    /** Persist the active proxy kind and, when a type is selected, that type's
     *  endpoint — in one edit (a single settings emission ⇒ one tunnel
     *  re-establish). Each type is stored under its own keys, so switching kinds
     *  keeps the others intact. */
    suspend fun setProxy(kind: ProxyKind, endpoint: ProxyEndpoint) = store.edit { prefs ->
        prefs[KEY_PROXY_KIND] = kind.name
        endpointPrefix(kind)?.let { type ->
            prefs[stringPreferencesKey("proxy_${type}_host")] = endpoint.host.trim()
            prefs[intPreferencesKey("proxy_${type}_port")] = endpoint.port
            prefs[stringPreferencesKey("proxy_${type}_username")] = endpoint.username
            prefs[stringPreferencesKey("proxy_${type}_password")] = endpoint.password
        }
    }

    suspend fun setProxyDnsOverTcp(value: Boolean) =
        store.edit { it[KEY_PROXY_DNS_OVER_TCP] = value }

    private companion object {
        val KEY_ONBOARDED = booleanPreferencesKey("onboarded")
        val KEY_DYNAMIC_COLOR = booleanPreferencesKey("dynamic_color")
        val KEY_THEME_MODE = stringPreferencesKey("theme_mode")
        // Legacy boolean, read only for migration into KEY_ENCRYPTED_DNS_MODE.
        val KEY_BLOCK_ENCRYPTED_DNS = booleanPreferencesKey("block_encrypted_dns")
        val KEY_ENCRYPTED_DNS_MODE = stringPreferencesKey("encrypted_dns_mode")
        val KEY_INTERCEPT_TLS = booleanPreferencesKey("intercept_tls")
        val KEY_DNS_TRANSPORT = stringPreferencesKey("dns_transport")
        val KEY_DNS_SERVER = stringPreferencesKey("dns_server")
        val KEY_DNS_PORT = intPreferencesKey("dns_port")
        val KEY_DNS_DOT_HOST = stringPreferencesKey("dns_dot_host")
        val KEY_DNS_DOT_PORT = intPreferencesKey("dns_dot_port")
        val KEY_DNS_DOH_URL = stringPreferencesKey("dns_doh_url")
        val KEY_DESIRED_PROTECTION = booleanPreferencesKey("desired_protection")
        val KEY_COSMETIC_ELEMENT_HIDING = booleanPreferencesKey("cosmetic_element_hiding")
        val KEY_COSMETIC_SCRIPTLETS = booleanPreferencesKey("cosmetic_scriptlets")
        val KEY_LIVE_TRAFFIC = booleanPreferencesKey("live_traffic_monitoring")
        val KEY_PROXY_KIND = stringPreferencesKey("proxy_kind")
        // Per-type proxy keys are `proxy_<type>_{host,port,username,password}`,
        // built on demand from [endpointPrefix] / [readEndpoint].
        val KEY_PROXY_DNS_OVER_TCP = booleanPreferencesKey("proxy_dns_over_tcp")
    }
}

/** Storage prefix for a proxy type's per-type keys (`http`/`https`/`socks5`), or
 *  null for [ProxyKind.NONE]. */
private fun endpointPrefix(kind: ProxyKind): String? = when (kind) {
    ProxyKind.HTTP -> "http"
    ProxyKind.HTTPS -> "https"
    ProxyKind.SOCKS5 -> "socks5"
    ProxyKind.NONE -> null
}

/** Read one type's saved [ProxyEndpoint] from `proxy_<type>_*` keys. */
private fun readEndpoint(prefs: Preferences, type: String) = ProxyEndpoint(
    host = prefs[stringPreferencesKey("proxy_${type}_host")] ?: "",
    port = prefs[intPreferencesKey("proxy_${type}_port")] ?: 0,
    username = prefs[stringPreferencesKey("proxy_${type}_username")] ?: "",
    password = prefs[stringPreferencesKey("proxy_${type}_password")] ?: "",
)
