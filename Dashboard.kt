package app.rootscanner.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import app.rootscanner.domain.*
import app.rootscanner.scanner.ScanState

private val Bg = Color(0xFF0B0B10); private val CardBg = Color(0x33FFFFFF)
private fun sevColor(s: Severity) = when (s) {
    Severity.CRITICAL -> Color(0xFFFF3B5C); Severity.HIGH -> Color(0xFFFF7A3B); Severity.MEDIUM -> Color(0xFFFFC53B)
    Severity.LOW -> Color(0xFF3BC8FF); Severity.INFO -> Color(0xFF9B6BFF)
}

@Composable
fun Dashboard(state: ScanState, onScan: () -> Unit) {
    val verdict = state.results.maxByOrNull { if (it.status == Status.DETECTED) it.severity.weight else -1 }
        ?.takeIf { it.status == Status.DETECTED }
    Column(Modifier.fillMaxSize().background(Bg).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("DEVICE SECURITY STATUS", style = MaterialTheme.typography.labelLarge, color = Color.White)
        Text(when { state.score == null -> "NOT SCANNED"; verdict == null -> "SECURE"
            else -> verdict.category.name + " " + verdict.severity.name }, style = MaterialTheme.typography.headlineLarge,
            color = verdict?.let { sevColor(it.severity) } ?: Color(0xFF3BFFB0))
        state.score?.let { Text("Security Score ${it.value}/100 · ${it.risk}", color = Color.White) }
        if (state.running) {
            LinearProgressIndicator(progress = { if (state.total == 0) 0f else state.done / state.total.toFloat() })
            Text("Scanning: ${state.stage}", color = Color.LightGray)
        }
        Button(onClick = onScan, enabled = !state.running) { Text("START FULL SECURITY SCAN") }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(state.results) { FindingCard(it) }
            state.score?.let { s -> items(s.lines) { Text("${it.label}: -${it.penalty} / ${it.max}", color = Color.Gray) } }
        }
    }
}

@Composable
fun FindingCard(d: Detection) {
    var open by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth().background(CardBg, RoundedCornerShape(16.dp)).padding(12.dp)) {
        TextButton(onClick = { open = !open }) {
            Text("${d.severity} · ${d.title} · ${d.confidence}", color = sevColor(d.severity))
        }
        if (open) {
            Text("Evidence:\n" + d.evidence.joinToString("\n") { "• $it" }, color = Color.White)
            Text("Why it matters: ${d.explanation}", color = Color.LightGray)
            Text("Possible false positive: ${d.falsePositiveNote}", color = Color.LightGray)
            Text("Recommended action: ${d.recommendation}", color = Color.LightGray)
        }
    }
}
