package app.rootscanner.root

import android.content.Context
import android.os.Build
import app.rootscanner.domain.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/** Read-only, multi-signal root indicators. Never executes su or modifies anything. */
class RootDetector(private val ctx: Context) : Detector {
    private val rootPackages = listOf(
        "com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser",
        "com.noshufou.android.su", "me.weishu.kernelsu", "com.thirdparty.superuser"
    )
    private val suPaths = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sbin/su",
        "/vendor/bin/su", "/system/app/Superuser.apk", "/data/local/bin/su", "/data/local/xbin/su"
    )

    override suspend fun run(): List<Detection> = withContext(Dispatchers.IO) {
        val ev = mutableListOf<String>()
        var strong = 0
        val pm = ctx.packageManager
        rootPackages.forEach {
            runCatching { pm.getPackageInfo(it, 0) }.onSuccess { ev += "Root-management package installed: $it"; strong++ }
        }
        suPaths.filter { runCatching { File(it).exists() }.getOrDefault(false) }
            .forEach { ev += "su artifact present at $it"; strong++ }
        if (Build.TAGS?.contains("test-keys") == true) ev += "Build signed with test-keys (Build.TAGS)"
        runCatching {
            File("/proc/mounts").readLines().filter {
                val p = it.split(" ")
                p.size > 3 && p[1] == "/system" && p[3].split(",").contains("rw")
            }.forEach { ev += "/system mounted read-write: $it" }
        }
        val conf = when { strong >= 2 -> Confidence.HIGH; ev.isNotEmpty() -> Confidence.MEDIUM; else -> Confidence.HIGH }
        val found = ev.isNotEmpty()
        listOf(Detection(
            id = "root.multi", category = Category.ROOT,
            title = if (found) "Root indicators detected" else "No root indicators detected",
            severity = when { strong >= 2 -> Severity.CRITICAL; strong == 1 -> Severity.HIGH; found -> Severity.MEDIUM; else -> Severity.INFO },
            confidence = conf, status = if (found) Status.DETECTED else Status.NOT_DETECTED,
            evidence = ev.ifEmpty { listOf("Checked ${rootPackages.size} packages, ${suPaths.size} su paths, build tags, mount table") },
            explanation = if (found) "One or more root-related indicators were found. This does not prove compromise." 
                          else "No reliable root indicators were found through the checks available to this app.",
            falsePositiveNote = "test-keys builds and custom ROMs can trigger weak signals without root. Absence of indicators is not proof of an unmodified device; hardware attestation (Play Integrity) is stronger.",
            recommendation = if (found) "Verify whether you intentionally modified this device. If not, review installed apps and restore via official recovery." else "No action needed."
        ))
    }
}
