package app.rootscanner.integrity

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import app.rootscanner.domain.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date

/** Reads signing certificates of user apps; flags debug/expired/multiple-signer certs. Never claims "modified" without a trusted reference. */
class CertificateAnalyzer(private val ctx: Context) : Detector {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02X".format(it) }

    override suspend fun run(): List<Detection> = withContext(Dispatchers.IO) {
        val pm = ctx.packageManager
        val pkgs = pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()))
        val cf = CertificateFactory.getInstance("X.509")
        val out = mutableListOf<Detection>(); var ok = 0; var unknown = 0
        for (p in pkgs) {
            val ai = p.applicationInfo ?: continue
            if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0) continue
            val info = p.signingInfo
            val sigs = if (info == null) null else if (info.hasMultipleSigners()) info.apkContentsSigners else info.signingCertificateHistory
            if (sigs.isNullOrEmpty()) { unknown++; continue }
            val cert = runCatching { cf.generateCertificate(ByteArrayInputStream(sigs.first().toByteArray())) as X509Certificate }.getOrNull()
            if (cert == null) { unknown++; continue }
            val sha256 = hex(MessageDigest.getInstance("SHA-256").digest(cert.encoded))
            val ev = mutableListOf("Subject: ${cert.subjectX500Principal.name}", "Issuer: ${cert.issuerX500Principal.name}",
                "Valid: ${cert.notBefore} to ${cert.notAfter}", "SHA-256: $sha256")
            val warn = mutableListOf<String>()
            if (cert.subjectX500Principal.name.contains("Android Debug", true)) warn += "Signed with the Android debug certificate"
            if (Date().after(cert.notAfter)) warn += "Certificate validity period has ended (Android does not enforce this at install)"
            if (info.hasMultipleSigners()) warn += "Multiple signers present"
            if (warn.isEmpty()) { ok++; continue }
            out += Detection("cert.${p.packageName}", Category.CERTIFICATE, "Certificate warning: ${p.packageName}",
                if (warn.any { it.contains("debug", true) }) Severity.MEDIUM else Severity.LOW, Confidence.MEDIUM, Status.DETECTED,
                warn + ev, "Certificate metadata differs from what production release builds normally show.",
                "Expired certificates are common for long-lived apps; debug certificates are expected for apps you built yourself.",
                "Confirm the app came from a source you trust.")
        }
        out += Detection("cert.summary", Category.CERTIFICATE, "Certificates: $ok normal, ${out.size} warnings, $unknown unreadable",
            Severity.INFO, Confidence.HIGH, Status.NOT_DETECTED, listOf("Signature validity is checked by Android at install time"),
            "No trusted reference hashes are bundled, so signature mismatch against expected publishers is not evaluated.",
            "UNKNOWN is reported when signing data is unavailable.", "No action needed.")
        out
    }
}
