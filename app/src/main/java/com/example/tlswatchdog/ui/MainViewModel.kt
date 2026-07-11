package com.example.tlswatchdog.ui

import android.app.Application
import android.content.Intent
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.tlswatchdog.data.AppSelection
import com.example.tlswatchdog.data.FlowEntity
import com.example.tlswatchdog.data.FlowRepository
import com.example.tlswatchdog.vpn.VpnController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

data class AppItem(val packageName: String, val label: String)

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val repo = FlowRepository(app)

    val running: StateFlow<Boolean> = VpnController.running

    val selected: StateFlow<Set<String>> =
        AppSelection.observe(app).stateIn(viewModelScope, SharingStarted.Eagerly, emptySet())

    val recordCleartext: StateFlow<Boolean> =
        AppSelection.observeRecord(app).stateIn(viewModelScope, SharingStarted.Eagerly, false)

    private val _apps = MutableStateFlow<List<AppItem>>(emptyList())
    val apps: StateFlow<List<AppItem>> = _apps

    val allFlows: StateFlow<List<FlowEntity>> =
        repo.observeAll().stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())
    val offenderFlows: StateFlow<List<FlowEntity>> =
        repo.observeOffenders().stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    init {
        loadApps()
    }

    private fun loadApps() = viewModelScope.launch(Dispatchers.IO) {
        val pm = getApplication<Application>().packageManager
        val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val resolved = pm.queryIntentActivities(intent, 0)
        val items = resolved
            .map { it.activityInfo.packageName }
            .distinct()
            .filter { it != getApplication<Application>().packageName }
            .map { pkg ->
                val label = try {
                    pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0)).toString()
                } catch (e: Exception) {
                    pkg
                }
                AppItem(pkg, label)
            }
            .sortedBy { it.label.lowercase() }
        _apps.value = items
    }

    fun toggleApp(pkg: String) = viewModelScope.launch {
        val current = selected.value.toMutableSet()
        if (!current.add(pkg)) current.remove(pkg)
        AppSelection.set(getApplication(), current)
    }

    fun setRecordCleartext(enabled: Boolean) = viewModelScope.launch {
        AppSelection.setRecord(getApplication(), enabled)
    }

    fun clearFlows() = viewModelScope.launch { repo.clear() }

    suspend fun exportCsv(uri: Uri) = withContext(Dispatchers.IO) {
        val rows = repo.snapshot()
        val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        val sb = StringBuilder()
        sb.append("time,app,package,uid,src_port,dst_ip,dst_port,proto,verdict,offender,first_bytes_hex,sample_text\n")
        for (r in rows) {
            sb.append(fmt.format(Date(r.timestamp))).append(',')
                .append(csv(r.appLabel)).append(',')
                .append(csv(r.packageName)).append(',')
                .append(r.uid).append(',')
                .append(r.srcPort).append(',')
                .append(csv(r.dstIp)).append(',')
                .append(r.dstPort).append(',')
                .append(r.proto).append(',')
                .append(r.verdict).append(',')
                .append(r.isOffender).append(',')
                .append(r.firstBytesHex).append(',')
                .append(csv(r.sampleText)).append('\n')
        }
        getApplication<Application>().contentResolver.openOutputStream(uri)?.use {
            it.write(sb.toString().toByteArray())
        }
    }

    private fun csv(s: String?): String {
        val v = s ?: ""
        val needsQuote = v.any { it == ',' || it == '"' || it == '\n' || it == '\r' }
        return if (needsQuote) "\"" + v.replace("\"", "\"\"") + "\"" else v
    }
}
