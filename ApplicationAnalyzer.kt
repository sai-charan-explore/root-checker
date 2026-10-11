package app.rootscanner.applications

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import app.rootscanner.domain.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Scores each installed app from observable metadata only. Capability alone never flags an app;
 * an app is reported when several independent risk factors combine (score >= 30).
 */
class ApplicationAnalyzer(private val ctx: Context) : Detector {
    private val trustedInstallers = setOf("com.android.vending", "com.sec.android.app.samsungapps", "com.amazon.venezia", "com.huawei.appmarket")
    private val dangerous = setOf(
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO", "android.permission.READ_CALL_LOG",
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.CAMERA", "android.permission.REQUEST_INSTALL_PACKAGES"
    )

    override suspend fun run(): List<Detection> = withContext(Dispatchers.IO) {
        val pm = ctx.packageManager
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES
        val pkgs = pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags.toLong()))
        var user = 0; var flagged = 0
        val out = mutableListOf<Detection>()
        for (p in pkgs) {
            val ai = p.applicationInfo ?: continue
            if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0) continue
            user++
            val (score, reasons) = scoreApp(pm, p, ai)
            if (score < 30) continue
            flagged++
            out += Detection(
                id = "app.${p.packageName}", category = Category.APPS,
                title = "App risk $score/100: ${pm.getApplicationLabel(ai)} (${p.packageName})",
                severity = when { score >= 70 -> Severity.HIGH; score >= 50 -> Severity.MEDIUM; else -> Severity.LOW },
                confidence = if (score >= 70) Confidence.MEDIUM else Confidence.LOW,
                status = Status.DETECTED, evidence = reasons,
                explanation = "Risk comes from the combination of factors above, not from any single permission.",
                falsePositiveNote = "Legitimate sideloaded, enterprise and developer apps commonly score here. Requesting permissions does not make an app malicious.",
                recommendation = "If you do not recognise this app or installed it from an unofficial source, review it in system settings and remove it if unneeded."
            )
        }
        out += Detection("apps.summary", Category.APPS, "Analysed $user user apps, $flagged flagged", Severity.INFO, Confidence.HIGH,
            Status.NOT_DETECTED, listOf("System apps are skipped; package visibility is limited by Android on API 30+"),
            "Only apps visible to this app via PackageManager were inspected.", "Apps hidden by Android package visibility cannot be assessed.", "No action needed.")
        out
    }

    private fun scoreApp(pm: PackageManager, p: PackageInfo, ai: ApplicationInfo): Pair<Int, List<String>> {
        var s = 0; val r = mutableListOf<String>()
        val src: String? = runCatching { pm.getInstallSourceInfo(p.packageName).installingPackageName }.getOrNull()
        if (src == null || src !in trustedInstallers) { s += 20; r += "Install source: ${src ?: "unknown/sideloaded"}" }
        if (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) { s += 20; r += "Debuggable build" }
        val perms = p.requestedPermissions?.toSet().orEmpty()
        val d = perms.intersect(dangerous).size
        if (d >= 4) { s += 15; r += "$d sensitive permissions requested" }
        if ("android.permission.SYSTEM_ALERT_WINDOW" in perms) { s += 10; r += "Can draw over other apps" }
        val bind = p.services?.mapNotNull { it.permission }.orEmpty()
        mapOf("android.permission.BIND_ACCESSIBILITY_SERVICE" to "Declares an accessibility service",
              "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE" to "Declares a notification listener",
              "android.permission.BIND_VPN_SERVICE" to "Declares a VPN service",
              "android.permission.BIND_DEVICE_ADMIN" to "Device-admin capability")
            .forEach { (perm, label) -> if (perm in bind || perm in perms) { s += 12; r += label } }
        if (ai.nativeLibraryDir != null && java.io.File(ai.nativeLibraryDir).list()?.isNotEmpty() == true) { s += 3; r += "Bundles native libraries" }
        // Combination bonus: the signal the spec calls out (capability + other indicators).
        if (src !in trustedInstallers && r.any { it.startsWith("Declares an accessibility") || it.startsWith("Can draw") }) { s += 10; r += "Combination: sideloaded + overlay/accessibility capability" }
        return s.coerceAtMost(100) to r
    }
}
