package app.rootscanner.integrity

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Debug
import android.provider.Settings
import app.rootscanner.domain.*

class DebugDetector(private val ctx: Context) : Detector {
    override suspend fun run(): List<Detection> {
        val cr = ctx.contentResolver
        val dev = Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        val adb = Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1
        val dbgApp = (ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val attached = Debug.isDebuggerConnected() || Debug.waitingForDebugger()
        val tracer = runCatching {
            java.io.File("/proc/self/status").readLines().firstOrNull { it.startsWith("TracerPid") }
                ?.substringAfter(":")?.trim()?.toIntOrNull() ?: 0
        }.getOrDefault(0)
        val ev = buildList {
            if (dev) add("Developer options enabled")
            if (adb) add("USB debugging (ADB) enabled")
            if (dbgApp) add("This app build is debuggable")
            if (attached) add("Debugger attached to this process")
            if (tracer != 0) add("Process is being traced (TracerPid=$tracer)")
        }
        val sev = when { attached || tracer != 0 -> Severity.HIGH; dbgApp -> Severity.MEDIUM; ev.isNotEmpty() -> Severity.LOW; else -> Severity.INFO }
        return listOf(Detection(
            id = "debug.state", category = Category.DEBUG,
            title = if (ev.isEmpty()) "Debugging not detected" else "Debugging indicators detected",
            severity = sev, confidence = Confidence.HIGH,
            status = if (ev.isEmpty()) Status.NOT_DETECTED else Status.DETECTED,
            evidence = ev.ifEmpty { listOf("No developer, ADB, debugger or tracer signals") },
            explanation = "Checks developer settings, ADB state, debuggable flag, debugger attachment and ptrace tracer.",
            falsePositiveNote = "Developer options and ADB are legitimate configurations, not malware.",
            recommendation = if (ev.isEmpty()) "No action needed." else "Disable developer options/ADB if you are not actively developing."
        ))
    }
}
