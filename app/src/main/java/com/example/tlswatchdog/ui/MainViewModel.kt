package com.example.tlswatchdog.ui

import android.Manifest
import android.app.Application
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.core.graphics.drawable.toBitmap
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

data class AppItem(
    val packageName: String,
    val label: String,
    val icon: ImageBitmap?,
    val hasInternet: Boolean,
)

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val repo = FlowRepository(app)

    val running: StateFlow<Boolean> = VpnController.running

    val selected: StateFlow<Set<String>> =
        AppSelection.observe(app).stateIn(viewModelScope, SharingStarted.Eagerly, emptySet())

    val recordCleartext: StateFlow<Boolean> =
        AppSelection.observeRecord(app).stateIn(viewModelScope, SharingStarted.Eagerly, false)
    val cap: StateFlow<Int> =
        AppSelection.observeCap(app).stateIn(viewModelScope, SharingStarted.Eagerly, AppSelection.DEFAULT_CAP)
    val flagUdp: StateFlow<Boolean> =
        AppSelection.observeFlagUdp(app).stateIn(viewModelScope, SharingStarted.Eagerly, false)
    val flagOldTls: StateFlow<Boolean> =
        AppSelection.observeFlagOldTls(app).stateIn(viewModelScope, SharingStarted.Eagerly, false)
    val autoStart: StateFlow<Boolean> =
        AppSelection.observeAutoStart(app).stateIn(viewModelScope, SharingStarted.Eagerly, false)

    fun setCap(bytes: Int) = viewModelScope.launch { AppSelection.setCap(getApplication(), bytes) }
    fun setFlagUdp(enabled: Boolean) = viewModelScope.launch { AppSelection.setFlagUdp(getApplication(), enabled) }
    fun setFlagOldTls(enabled: Boolean) = viewModelScope.launch { AppSelection.setFlagOldTls(getApplication(), enabled) }

    /** Decrypt a single row's payload fields for the detail view (cheap; call inside remember). */
    fun decryptDetail(f: FlowEntity): FlowEntity = repo.decryptDetail(f)
    fun setAutoStart(enabled: Boolean) = viewModelScope.launch { AppSelection.setAutoStart(getApplication(), enabled) }

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
        val self = getApplication<Application>().packageName
        val launchable = pm.queryIntentActivities(
            Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0,
        ).map { it.activityInfo.packageName }
        val internet: Set<String> = try {
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
                .filter { it.requestedPermissions?.contains(Manifest.permission.INTERNET) == true }
                .map { it.packageName }
                .toSet()
        } catch (e: Exception) {
            emptySet()
        }
        val items = (launchable + internet).distinct()
            .filter { it != self }
            .mapNotNull { pkg ->
                try {
                    val ai = pm.getApplicationInfo(pkg, 0)
                    val label = pm.getApplicationLabel(ai).toString()
                    val icon = try {
                        pm.getApplicationIcon(ai).toBitmap(96, 96).asImageBitmap()
                    } catch (e: Exception) {
                        null
                    }
                    AppItem(pkg, label, icon, hasInternet = pkg in internet)
                } catch (e: Exception) {
                    null
                }
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
        sb.append(
            "time,app,package,uid,src_port,dst_ip,dst_port,proto,verdict,tls_version,offender," +
                "bytes_out,bytes_in,packets,duration_ms,first_bytes_hex,request_text,response_text\n",
        )
        for (r0 in rows) {
            val r = repo.decryptDetail(r0) // decrypt the sensitive fields for export
            sb.append(fmt.format(Date(r.timestamp))).append(',')
                .append(csv(r.appLabel)).append(',')
                .append(csv(r.packageName)).append(',')
                .append(r.uid).append(',')
                .append(r.srcPort).append(',')
                .append(csv(r.dstIp)).append(',')
                .append(r.dstPort).append(',')
                .append(r.proto).append(',')
                .append(r.verdict).append(',')
                .append(csv(r.tlsVersion)).append(',')
                .append(r.isOffender).append(',')
                .append(r.bytesOut).append(',')
                .append(r.bytesIn).append(',')
                .append(r.packets).append(',')
                .append(r.durationMs).append(',')
                .append(r.firstBytesHex).append(',')
                .append(csv(r.sampleText)).append(',')
                .append(csv(r.responseText)).append('\n')
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
