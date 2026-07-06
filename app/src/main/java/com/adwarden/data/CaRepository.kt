package com.adwarden.data

import android.content.Context
import com.adwarden.core.NativeCore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/** The TLS-interception root CA, PEM-encoded. */
data class CaMaterial(val certPem: String, val keyPem: String)

/**
 * Owns the TLS-interception root CA lifecycle (P2): generate it once via the
 * native core, persist it app-privately, and restore it on later runs so the
 * user installs the CA only once.
 *
 * The private key stays in app-private storage (`filesDir`, unreadable by other
 * apps); only the certificate is ever exported, for the install wizard. Hardware
 * Keystore wrapping of the key is a future hardening step.
 */
@Singleton
class CaRepository @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val dir: File get() = File(context.filesDir, "ca")
    private val certFile: File get() = File(dir, "root_cert.pem")
    private val keyFile: File get() = File(dir, "root_key.pem")

    /** True once a CA has been generated and persisted. */
    fun exists(): Boolean = certFile.exists() && keyFile.exists()

    /**
     * Return the CA, generating and persisting it on first call. Requires the
     * native core `.so`; returns null if it can't load or generation fails.
     */
    suspend fun ensureCa(): CaMaterial? = withContext(Dispatchers.IO) {
        load() ?: generateAndStore()
    }

    /** The CA certificate PEM (for export / the install wizard), or null. */
    suspend fun caCertPem(): String? = ensureCa()?.certPem

    private fun load(): CaMaterial? {
        if (!exists()) return null
        return runCatching { CaMaterial(certFile.readText(), keyFile.readText()) }.getOrNull()
    }

    private fun generateAndStore(): CaMaterial? {
        if (!NativeCore.ensureLoaded()) return null
        val pair = NativeCore.nativeGenerateCa() ?: return null
        if (pair.size < 2) return null
        val material = CaMaterial(certPem = pair[0], keyPem = pair[1])
        return runCatching {
            dir.mkdirs()
            certFile.writeText(material.certPem)
            keyFile.writeText(material.keyPem)
            material
        }.getOrNull()
    }
}
