package com.adwarden.ui.screens

import android.os.Build
import android.security.KeyChain
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory

/**
 * The per-Android-version CA-install wizard (P2). Hands the interception root CA
 * to the system certificate installer and offers a manual `.pem` export, with an
 * honest note about what non-root interception can and cannot decrypt.
 *
 * @param certPem the CA certificate PEM, or null while it's still being prepared.
 */
@Composable
fun CaInstallDialog(certPem: String?, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val exportLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/x-pem-file"),
    ) { uri ->
        if (uri != null && certPem != null) {
            runCatching {
                context.contentResolver.openOutputStream(uri)?.use { it.write(certPem.toByteArray()) }
            }
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Install Adwarden CA") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    installSteps(),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(14.dp))
                Text(
                    "What this can decrypt",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "Since Android 7, apps only trust user-installed CAs if they opt in. " +
                        "Browsers like Chrome and Firefox do; many apps pin their certificates " +
                        "and stay opaque. Blocking, logging and PCAP keep working for every app — " +
                        "only full HTTPS decode is limited to the cooperating subset.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (certPem == null) {
                    Spacer(Modifier.height(12.dp))
                    Text(
                        "Preparing certificate…",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = certPem != null,
                onClick = {
                    certPem?.let { pem ->
                        pemToDer(pem)?.let { der ->
                            val intent = KeyChain.createInstallIntent().apply {
                                putExtra(KeyChain.EXTRA_CERTIFICATE, der)
                                putExtra(KeyChain.EXTRA_NAME, "Adwarden Root CA")
                            }
                            runCatching { context.startActivity(intent) }
                        }
                    }
                },
            ) { Text("Install certificate") }
        },
        dismissButton = {
            TextButton(
                enabled = certPem != null,
                onClick = { exportLauncher.launch("adwarden-ca.pem") },
            ) { Text("Export .pem") }
        },
    )
}

/** Guidance tuned to the installer flow on the running Android version. */
private fun installSteps(): String = when {
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE -> // 34+
        "1. Tap Install certificate below.\n" +
            "2. The system will ask what to install — choose \"CA certificate\".\n" +
            "3. Confirm the security warning to trust the Adwarden CA.\n" +
            "If the picker doesn't appear, use Export .pem, then Settings ▸ Security & " +
            "privacy ▸ More security ▸ Encryption & credentials ▸ Install a certificate ▸ " +
            "CA certificate, and pick the exported file."
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.R -> // 30–33
        "1. Tap Install certificate below and choose \"CA certificate\".\n" +
            "2. Confirm the security warning.\n" +
            "Otherwise Export .pem and install it via Settings ▸ Security ▸ Encryption & " +
            "credentials ▸ Install a certificate ▸ CA certificate."
    else ->
        "Tap Install certificate and choose \"CA certificate\", or Export .pem and install " +
            "it from Settings ▸ Security ▸ Install from storage."
}

private fun pemToDer(pem: String): ByteArray? = runCatching {
    CertificateFactory.getInstance("X.509")
        .generateCertificate(ByteArrayInputStream(pem.toByteArray()))
        .encoded
}.getOrNull()
