package app.rootscanner.scanner

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import app.rootscanner.domain.*
import app.rootscanner.applications.ApplicationAnalyzer
import app.rootscanner.emulator.EmulatorDetector
import app.rootscanner.integrity.CertificateAnalyzer
import app.rootscanner.integrity.DebugDetector
import app.rootscanner.root.RootDetector
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

data class ScanState(
    val running: Boolean = false, val stage: String = "", val done: Int = 0, val total: Int = 0,
    val results: List<Detection> = emptyList(), val score: Score? = null
)

class ScanViewModel(app: Application) : AndroidViewModel(app) {
    private val _state = MutableStateFlow(ScanState())
    val state = _state.asStateFlow()
    private var job: Job? = null

    fun start() {
        if (job?.isActive == true) return
        val ctx = getApplication<Application>()
        val stages = listOf("Root indicators" to RootDetector(ctx), "Virtual environment" to EmulatorDetector(ctx), "Debugging state" to DebugDetector(ctx),
            "Installed applications" to ApplicationAnalyzer(ctx), "APK signatures" to CertificateAnalyzer(ctx))
        job = viewModelScope.launch {
            _state.value = ScanState(running = true, total = stages.size)
            val all = mutableListOf<Detection>()
            stages.forEachIndexed { i, (name, det) ->
                _state.update { it.copy(stage = name, done = i) }
                withTimeoutOrNull(30_000) { det.run() }?.let { all.addAll(it) }
            }
            _state.value = ScanState(false, "Complete", stages.size, stages.size, all, ScoreEngine.compute(all))
        }
    }
    fun cancel() { job?.cancel(); _state.update { it.copy(running = false) } }
}
