package com.example.tlswatchdog

import android.Manifest
import android.app.Activity
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.tlswatchdog.data.FlowEntity
import com.example.tlswatchdog.ui.MainViewModel
import com.example.tlswatchdog.vpn.VpnController
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Scaffold { padding ->
                    App(Modifier.padding(padding))
                }
            }
        }
    }
}

@Composable
private fun App(modifier: Modifier = Modifier) {
    val vm: MainViewModel = viewModel()
    val context = LocalContext.current
    var tab by remember { mutableIntStateOf(0) }

    // Ask for notification permission on first launch (Android 13+).
    val notifPerm = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {}
    androidx.compose.runtime.LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33) notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    val vpnConsent = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { res ->
        if (res.resultCode == Activity.RESULT_OK) VpnController.start(context)
    }

    Column(modifier.fillMaxSize()) {
        TabRow(selectedTabIndex = tab) {
            listOf("Monitor", "Apps", "Flows").forEachIndexed { i, title ->
                Tab(selected = tab == i, onClick = { tab = i }, text = { Text(title) })
            }
        }
        when (tab) {
            0 -> MonitorTab(vm) {
                val prep = VpnService.prepare(context)
                if (prep != null) vpnConsent.launch(prep) else VpnController.start(context)
            }
            1 -> AppsTab(vm)
            2 -> FlowsTab(vm)
        }
    }
}

@Composable
private fun MonitorTab(vm: MainViewModel, onStart: () -> Unit) {
    val running by vm.running.collectAsState()
    val selected by vm.selected.collectAsState()
    val record by vm.recordCleartext.collectAsState()
    val context = LocalContext.current

    Column(
        Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            if (running) "Monitoring active" else "Stopped",
            fontSize = 22.sp,
            fontWeight = FontWeight.Bold,
        )
        Spacer(Modifier.height(8.dp))
        Text("${selected.size} app(s) selected")
        Spacer(Modifier.height(24.dp))

        // Second toggle: capture a sample of each cleartext payload.
        Row(
            Modifier.fillMaxWidth().padding(bottom = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center,
        ) {
            Switch(
                checked = record,
                onCheckedChange = { vm.setRecordCleartext(it) },
                enabled = !running,
            )
            Spacer(Modifier.height(0.dp))
            Text("  Record cleartext content", fontWeight = FontWeight.Medium)
        }
        Text(
            "Captures ~2 KB of each non-TLS flow (URLs, headers, maybe secrets). Stored locally.",
            fontSize = 12.sp,
            color = MaterialTheme.colorScheme.outline,
        )
        Spacer(Modifier.height(24.dp))

        if (running) {
            if (record) {
                Text("Recording cleartext", color = MaterialTheme.colorScheme.error, fontSize = 13.sp)
                Spacer(Modifier.height(8.dp))
            }
            Button(onClick = { VpnController.stop(context) }) { Text("Stop") }
        } else {
            Button(onClick = onStart, enabled = selected.isNotEmpty()) { Text("Start monitoring") }
            if (selected.isEmpty()) {
                Spacer(Modifier.height(8.dp))
                Text("Select at least one app in the Apps tab", fontSize = 13.sp)
            }
        }
    }
}

@Composable
private fun AppsTab(vm: MainViewModel) {
    val apps by vm.apps.collectAsState()
    val selected by vm.selected.collectAsState()
    LazyColumn(Modifier.fillMaxSize()) {
        items(apps, key = { it.packageName }) { app ->
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Checkbox(
                    checked = app.packageName in selected,
                    onCheckedChange = { vm.toggleApp(app.packageName) },
                )
                Spacer(Modifier.height(0.dp))
                Column(Modifier.padding(start = 8.dp)) {
                    Text(app.label, fontWeight = FontWeight.Medium)
                    Text(app.packageName, fontSize = 12.sp, color = MaterialTheme.colorScheme.outline)
                }
            }
        }
    }
}

@Composable
private fun FlowsTab(vm: MainViewModel) {
    var offendersOnly by remember { mutableStateOf(false) }
    val all by vm.allFlows.collectAsState()
    val offenders by vm.offenderFlows.collectAsState()
    val flows = if (offendersOnly) offenders else all
    val scope = rememberCoroutineScope()

    val exporter = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/csv"),
    ) { uri -> if (uri != null) scope.launch { vm.exportCsv(uri) } }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FilterChip(
                selected = offendersOnly,
                onClick = { offendersOnly = !offendersOnly },
                label = { Text("Cleartext only") },
            )
            Spacer(Modifier.fillMaxWidth().weight(1f))
            OutlinedButton(onClick = { exporter.launch("tls-watchdog.csv") }) { Text("Export") }
            Spacer(Modifier.height(0.dp))
            OutlinedButton(
                onClick = { vm.clearFlows() },
                modifier = Modifier.padding(start = 8.dp),
            ) { Text("Clear") }
        }
        HorizontalDivider()
        LazyColumn(Modifier.fillMaxSize()) {
            items(flows, key = { it.id }) { FlowRow(it) }
        }
    }
}

private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

private fun humanBytes(b: Long): String = when {
    b < 1024 -> "${b}B"
    b < 1024 * 1024 -> "%.1fKB".format(b / 1024.0)
    b < 1024 * 1024 * 1024 -> "%.1fMB".format(b / (1024.0 * 1024))
    else -> "%.1fGB".format(b / (1024.0 * 1024 * 1024))
}

private fun humanDuration(ms: Long): String = when {
    ms < 1000 -> "${ms}ms"
    ms < 60_000 -> "%.1fs".format(ms / 1000.0)
    else -> "${ms / 60_000}m${(ms % 60_000) / 1000}s"
}

@Composable
private fun FlowRow(f: FlowEntity) {
    val color = if (f.isOffender) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface
    var expanded by remember { mutableStateOf(false) }
    val hasSample = !f.sampleText.isNullOrBlank()
    Column(
        Modifier
            .fillMaxWidth()
            .then(if (hasSample) Modifier.clickable { expanded = !expanded } else Modifier)
            .padding(horizontal = 16.dp, vertical = 6.dp),
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(f.appLabel ?: f.packageName ?: "uid ${f.uid}", fontWeight = FontWeight.Medium)
            Text(f.verdict, color = color, fontWeight = FontWeight.Bold, fontSize = 13.sp)
        }
        Text(
            "${f.dstIp}:${f.dstPort}  ·  ${timeFmt.format(Date(f.timestamp))}" +
                if (hasSample) "  ·  tap to ${if (expanded) "hide" else "view"} payload" else "",
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.outline,
        )
        val stats = if (f.packets > 0) {
            "↑${humanBytes(f.bytesOut)} ↓${humanBytes(f.bytesIn)} · ${f.packets} pkts · ${humanDuration(f.durationMs)}"
        } else {
            "active…"
        }
        Text(
            stats,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.outline,
        )
        if (hasSample) {
            val text = f.sampleText!!
            Text(
                if (expanded) text else text.lineSequence().first().take(80),
                fontSize = 11.sp,
                fontFamily = FontFamily.Monospace,
                maxLines = if (expanded) Int.MAX_VALUE else 1,
                color = color,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
    }
    HorizontalDivider()
}
