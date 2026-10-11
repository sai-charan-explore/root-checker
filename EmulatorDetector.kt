package app.rootscanner.emulator

import android.content.Context
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Build
import app.rootscanner.domain.*

/** Scores multiple signals; no single fingerprint is treated as conclusive. */
class EmulatorDetector(private val ctx: Context) : Detector {
    data class Signal(val name: String, val hit: Boolean, val weight: Int)

    override suspend fun run(): List<Detection> {
        val fp = Build.FINGERPRINT.lowercase(); val hw = Build.HARDWARE.lowercase()
        val model = Build.MODEL.lowercase(); val prod = Build.PRODUCT.lowercase()
        val sm = ctx.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        val signals = listOf(
            Signal("Fingerprint contains generic/emulator marker: ${Build.FINGERPRINT}", fp.startsWith("generic") || fp.contains("emulator") || fp.contains("sdk_gphone"), 3),
            Signal("Hardware is goldfish/ranchu/vbox: ${Build.HARDWARE}", hw.contains("goldfish") || hw.contains("ranchu") || hw.contains("vbox"), 3),
            Signal("Model matches virtual profile: ${Build.MODEL}", listOf("sdk", "emulator", "android sdk built for", "bluestacks", "memu", "ldplayer", "nox", "mumu", "gameloop").any { model.contains(it) }, 2),
            Signal("Product is sdk/emulator image: ${Build.PRODUCT}", prod.contains("sdk") || prod.contains("emulator") || prod.contains("vbox"), 2),
            Signal("Manufacturer is Genymotion/unknown: ${Build.MANUFACTURER}", Build.MANUFACTURER.contains("Genymotion", true) || Build.MANUFACTURER.equals("unknown", true), 2),
            Signal("No motion sensors exposed", sm.getSensorList(Sensor.TYPE_ACCELEROMETER).isEmpty() && sm.getSensorList(Sensor.TYPE_GYROSCOPE).isEmpty(), 1),
            Signal("x86 ABI primary: ${Build.SUPPORTED_ABIS.firstOrNull()}", Build.SUPPORTED_ABIS.firstOrNull()?.startsWith("x86") == true, 1)
        )
        val hits = signals.filter { it.hit }
        val score = hits.sumOf { it.weight }
        val virtual = score >= 4
        return listOf(Detection(
            id = "emu.multi", category = Category.EMULATOR,
            title = if (virtual) "Emulator / virtual device" else "Physical device",
            severity = if (virtual) Severity.MEDIUM else Severity.INFO,
            confidence = if (score >= 6 || score == 0) Confidence.HIGH else Confidence.MEDIUM,
            status = if (virtual) Status.DETECTED else Status.NOT_DETECTED,
            evidence = hits.map { it.name }.ifEmpty { listOf("0 of ${signals.size} virtualization signals matched") },
            explanation = if (virtual) "Multiple hardware and system characteristics are consistent with a virtualized Android environment (signal score $score)."
                          else "Hardware and build characteristics are consistent with a physical device.",
            falsePositiveNote = "Developer test devices and some Chromebooks/ARM-translation layers can match individual signals.",
            recommendation = if (virtual) "Expected if you are running an emulator. Otherwise investigate." else "No action needed."
        ))
    }
}
