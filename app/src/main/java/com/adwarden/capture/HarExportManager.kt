package com.adwarden.capture

import android.content.Context
import android.net.Uri
import com.adwarden.core.NativeCore
import com.adwarden.core.NativeSessionHolder
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Exports the decrypted HTTP transactions (from TLS-intercepted flows) as a HAR
 * 1.2 file. The user picks a destination via SAF; we hand the detached fd to the
 * native core, which writes the buffered transactions and closes it (P2-3).
 */
@Singleton
class HarExportManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val sessionHolder: NativeSessionHolder,
) {
    /** Suggested filename for the SAF create-document intent. */
    fun defaultFileName(): String = "adwarden-${System.currentTimeMillis()}.har"

    /**
     * Write the HAR to [target]. Returns false if the core isn't running or the
     * document can't be opened.
     */
    fun export(target: Uri): Boolean {
        val handle = sessionHolder.handle
        if (handle == 0L) return false
        val pfd = runCatching { context.contentResolver.openFileDescriptor(target, "w") }
            .getOrNull() ?: return false
        // Ownership of the fd transfers to native; do not close pfd afterwards.
        val fd = pfd.detachFd()
        return NativeCore.nativeExportHar(handle, fd)
    }
}
