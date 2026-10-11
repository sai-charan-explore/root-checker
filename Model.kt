package app.rootscanner.domain

enum class Severity(val weight: Int) { INFO(0), LOW(1), MEDIUM(2), HIGH(3), CRITICAL(4) }
enum class Confidence { LOW, MEDIUM, HIGH }
enum class Category { ROOT, EMULATOR, DEBUG, TAMPER, APPS, FILES, OVERLAY, CERTIFICATE }
enum class Status { DETECTED, NOT_DETECTED, ACCESS_RESTRICTED }

data class Detection(
    val id: String,
    val category: Category,
    val title: String,
    val severity: Severity,
    val confidence: Confidence,
    val status: Status,
    val evidence: List<String>,
    val explanation: String,
    val falsePositiveNote: String,
    val recommendation: String,
    val timestamp: Long = System.currentTimeMillis()
)

interface Detector { suspend fun run(): List<Detection> }
