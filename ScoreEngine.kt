package app.rootscanner.scanner

import app.rootscanner.domain.*

data class ScoreLine(val label: String, val max: Int, val penalty: Int)
data class Score(val value: Int, val risk: String, val lines: List<ScoreLine>)

/** Transparent scoring: each category loses up to its weight, scaled by severity and confidence. */
object ScoreEngine {
    private val weights = mapOf(
        Category.ROOT to 30, Category.TAMPER to 20, Category.APPS to 15, Category.EMULATOR to 10,
        Category.FILES to 10, Category.DEBUG to 5, Category.OVERLAY to 5, Category.CERTIFICATE to 5
    )

    fun compute(results: List<Detection>): Score {
        val lines = weights.map { (cat, max) ->
            val worst = results.filter { it.category == cat && it.status == Status.DETECTED }
            val penalty = worst.maxOfOrNull { d ->
                val conf = when (d.confidence) { Confidence.HIGH -> 1.0; Confidence.MEDIUM -> 0.7; Confidence.LOW -> 0.4 }
                (max * d.severity.weight / 4.0 * conf).toInt()
            } ?: 0
            ScoreLine(cat.name, max, penalty.coerceAtMost(max))
        }
        val v = (100 - lines.sumOf { it.penalty }).coerceIn(0, 100)
        val risk = when { v >= 80 -> "LOW RISK"; v >= 60 -> "MEDIUM RISK"; v >= 40 -> "HIGH RISK"; else -> "CRITICAL" }
        return Score(v, risk, lines)
    }
}
