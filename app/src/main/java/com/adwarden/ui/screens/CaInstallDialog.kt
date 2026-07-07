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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.adwarden.R
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
        title = { Text(stringResource(R.string.settings_install_ca)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(
                    installSteps(),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(14.dp))
                Text(
                    stringResource(R.string.ca_what_decrypts),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    stringResource(R.string.ca_what_decrypts_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                if (certPem == null) {
                    Spacer(Modifier.height(12.dp))
                    Text(
                        stringResource(R.string.ca_preparing),
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
            ) { Text(stringResource(R.string.ca_install_cert)) }
        },
        dismissButton = {
            TextButton(
                enabled = certPem != null,
                onClick = { exportLauncher.launch("adwarden-ca.pem") },
            ) { Text(stringResource(R.string.ca_export_pem)) }
        },
    )
}

/** Guidance tuned to the installer flow on the running Android version. */
@Composable
private fun installSteps(): String = stringResource(
    when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE -> R.string.ca_steps_34
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.R -> R.string.ca_steps_30
        else -> R.string.ca_steps_legacy
    },
)

private fun pemToDer(pem: String): ByteArray? = runCatching {
    CertificateFactory.getInstance("X.509")
        .generateCertificate(ByteArrayInputStream(pem.toByteArray()))
        .encoded
}.getOrNull()
