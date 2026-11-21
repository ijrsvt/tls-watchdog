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
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.VerticalDivider
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.tlswatchdog.data.FlowEntity
import com.example.tlswatchdog.ui.MainViewModel
import com.example.tlswatchdog.ui.TlsWatchdogTheme
import com.example.tlswatchdog.vpn.VpnController
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            TlsWatchdogTheme {
                Scaffold { padding -> App(Modifier.padding(padding)) }
            }
        }
    }
}

@Composable
private fun App(modifier: Modifier = Modifier) {
    val vm: MainViewModel = viewModel()
    val context = LocalContext.current
    var tab by remember { mutableIntStateOf(0) }

    val notifPerm = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) {}
    androidx.compose.runtime.LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33) notifPerm.launch(Manifest.permission.POST_NOTIFICATIONS)
    }

    val vpnConsent = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { res -> if (res.resultCode == Activity.RESULT_OK) VpnController.start(context) }

    Column(modifier.fillMaxSize()) {
        TabRow(selectedTabIndex = tab) {
            listOf("Monitor", "Apps", "Flows", "Settings").forEachIndexed { i, title ->
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
            3 -> SettingsTab(vm)
        }
    }
}

@Composable
private fun MonitorTab(vm: MainViewModel, onStart: () -> Unit) {
    val running by vm.running.collectAsState()
    val selected by vm.selected.collectAsState()
    val record by vm.recordCleartext.collectAsState()
    val monitorAll by vm.monitorAllApps.collectAsState()
    val context = LocalContext.current

    Column(
        Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(if (running) "Monitoring active" else "Stopped", fontSize = 22.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        Text(if (monitorAll) "All apps" else "${selected.size} app(s) selected")
        Spacer(Modifier.height(24.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = monitorAll, onCheckedChange = { vm.setMonitorAllApps(it) }, enabled = !running)
            Text("  Monitor all apps (full system)", fontWeight = FontWeight.Medium)
        }
        Text(
            "Routes every app's traffic through the watchdog instead of just the Apps tab selection.",
            fontSize = 12.sp, color = MaterialTheme.colorScheme.outline,
        )
        Spacer(Modifier.height(16.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(checked = record, onCheckedChange = { vm.setRecordCleartext(it) }, enabled = !running)
            Text("  Record cleartext content", fontWeight = FontWeight.Medium)
        }
        Text(
            "Captures request + response of non-TLS flows (size in Settings). Stored locally.",
            fontSize = 12.sp, color = MaterialTheme.colorScheme.outline,
        )
        Spacer(Modifier.height(24.dp))

        if (running) {
            if (record) {
                Text("Recording cleartext", color = MaterialTheme.colorScheme.error, fontSize = 13.sp)
                Spacer(Modifier.height(8.dp))
            }
            Button(onClick = { VpnController.stop(context) }) { Text("Stop") }
        } else {
            Button(onClick = onStart, enabled = monitorAll || selected.isNotEmpty()) { Text("Start monitoring") }
            if (!monitorAll && selected.isEmpty()) {
                Spacer(Modifier.height(8.dp))
                Text("Select at least one app in the Apps tab, or enable \"Monitor all apps\"", fontSize = 13.sp)
            }
        }
    }
}

@Composable
private fun AppsTab(vm: MainViewModel) {
    val apps by vm.apps.collectAsState()
    val selected by vm.selected.collectAsState()
    val monitorAll by vm.monitorAllApps.collectAsState()
    var query by remember { mutableStateOf("") }
    var internetOnly by remember { mutableStateOf(true) }
    val shown = apps.filter {
        (!internetOnly || it.hasInternet) &&
            (query.isBlank() || it.label.contains(query, true) || it.packageName.contains(query, true))
    }
    Column(Modifier.fillMaxSize()) {
        if (monitorAll) {
            Text(
                "\"Monitor all apps\" is on (Monitor tab) — this selection is ignored until you turn it off.",
                fontSize = 12.sp, color = MaterialTheme.colorScheme.error,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
            )
        }
        OutlinedTextField(
            value = query, onValueChange = { query = it },
            label = { Text("Search apps") }, singleLine = true,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp),
        )
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FilterChip(
                selected = internetOnly,
                onClick = { internetOnly = !internetOnly },
                label = { Text("Internet only") },
            )
            Spacer(Modifier.width(8.dp))
            Text("${shown.size} app(s)", fontSize = 12.sp, color = MaterialTheme.colorScheme.outline)
        }
        LazyColumn(Modifier.fillMaxSize()) {
            items(shown, key = { it.packageName }) { app ->
                Row(
                    Modifier.fillMaxWidth().clickable { vm.toggleApp(app.packageName) }
                        .padding(horizontal = 16.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(checked = app.packageName in selected, onCheckedChange = { vm.toggleApp(app.packageName) })
                    app.icon?.let { Image(it, null, Modifier.size(32.dp).padding(start = 4.dp)) }
                    Column(Modifier.padding(start = 8.dp)) {
                        Text(app.label, fontWeight = FontWeight.Medium)
                        Text(app.packageName, fontSize = 12.sp, color = MaterialTheme.colorScheme.outline)
                    }
                }
            }
        }
    }
}

@Composable
private fun FlowsTab(vm: MainViewModel) {
    var offendersOnly by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    var appFilter by remember { mutableStateOf<String?>(null) }
    var selectedFlow by remember { mutableStateOf<FlowEntity?>(null) }
    var showExportConfirm by remember { mutableStateOf(false) }
    val all by vm.allFlows.collectAsState()
    val offenders by vm.offenderFlows.collectAsState()
    val scope = rememberCoroutineScope()

    val exporter = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/csv"),
    ) { uri -> if (uri != null) scope.launch { vm.exportCsv(uri) } }

    val base = if (offendersOnly) offenders else all
    val appsInFlows = base.mapNotNull { f -> f.packageName?.let { it to (f.appLabel ?: it) } }.distinct()
    val flows = base.filter { f ->
        (appFilter == null || f.packageName == appFilter) &&
            (query.isBlank() || listOfNotNull(f.host, f.dstIp, f.appLabel, f.packageName, f.verdict)
                .any { it.contains(query, true) })
    }

    Column(Modifier.fillMaxSize()) {
        OutlinedTextField(
            value = query, onValueChange = { query = it },
            label = { Text("Search host / ip / app") }, singleLine = true,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp),
        )
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            FilterChip(selected = offendersOnly, onClick = { offendersOnly = !offendersOnly },
                label = { Text("Cleartext") })
            Spacer(Modifier.width(8.dp))
            AppFilterDropdown(appFilter, appsInFlows) { appFilter = it }
            Spacer(Modifier.weight(1f))
            OutlinedButton(onClick = { showExportConfirm = true }) { Text("Export") }
            OutlinedButton(onClick = { vm.clearFlows() }, modifier = Modifier.padding(start = 8.dp)) { Text("Clear") }
        }
        HorizontalDivider()
        BoxWithConstraintsWide { wide ->
            if (wide) {
                Row(Modifier.fillMaxSize()) {
                    LazyColumn(Modifier.weight(1f)) {
                        items(flows, key = { it.id }) { FlowRow(it, it.id == selectedFlow?.id) { selectedFlow = it } }
                    }
                    VerticalDivider()
                    Box(Modifier.weight(1f).fillMaxSize()) {
                        selectedFlow?.let { FlowDetail(it, vm) }
                            ?: Text("Select a flow", Modifier.padding(16.dp), color = MaterialTheme.colorScheme.outline)
                    }
                }
            } else {
                LazyColumn(Modifier.fillMaxSize()) {
                    items(flows, key = { it.id }) { FlowRow(it, false) { selectedFlow = it } }
                }
                if (selectedFlow != null) {
                    androidx.compose.ui.window.Dialog(onDismissRequest = { selectedFlow = null }) {
                        Box(
                            Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface),
                        ) { FlowDetail(selectedFlow!!, vm) }
                    }
                }
            }
        }
    }

    if (showExportConfirm) {
        androidx.compose.material3.AlertDialog(
            onDismissRequest = { showExportConfirm = false },
            title = { Text("Export flows to CSV") },
            text = { Text("The CSV includes captured cleartext payloads, which may contain secrets (cookies, tokens, credentials). Only share it somewhere you trust.") },
            confirmButton = {
                TextButton(onClick = { showExportConfirm = false; exporter.launch("tls-watchdog.csv") }) { Text("Export") }
            },
            dismissButton = { TextButton(onClick = { showExportConfirm = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun BoxWithConstraintsWide(content: @Composable (wide: Boolean) -> Unit) {
    androidx.compose.foundation.layout.BoxWithConstraints(Modifier.fillMaxSize()) {
        content(maxWidth >= 720.dp)
    }
}

@Composable
private fun AppFilterDropdown(current: String?, apps: List<Pair<String, String>>, onSelect: (String?) -> Unit) {
    var open by remember { mutableStateOf(false) }
    val label = current?.let { pkg -> apps.firstOrNull { it.first == pkg }?.second ?: pkg } ?: "All apps"
    Box {
        TextButton(onClick = { open = true }) { Text(label, maxLines = 1) }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            DropdownMenuItem(text = { Text("All apps") }, onClick = { onSelect(null); open = false })
            apps.forEach { (pkg, lbl) ->
                DropdownMenuItem(text = { Text(lbl) }, onClick = { onSelect(pkg); open = false })
            }
        }
    }
}

private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)
private val fullTimeFmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

@Composable
private fun FlowRow(f: FlowEntity, selected: Boolean, onClick: () -> Unit) {
    val color = if (f.isOffender) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface
    val bg = if (selected) MaterialTheme.colorScheme.surfaceVariant else MaterialTheme.colorScheme.surface
    Column(
        Modifier.fillMaxWidth().background(bg).clickable { onClick() }
            .padding(horizontal = 16.dp, vertical = 6.dp),
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(f.appLabel ?: f.packageName ?: "uid ${f.uid}", fontWeight = FontWeight.Medium)
            val verdictLabel = f.tlsVersion?.let { "${f.verdict} $it" } ?: f.verdict
            Text(verdictLabel, color = color, fontWeight = FontWeight.Bold, fontSize = 13.sp)
        }
        Text(
            f.host ?: "${f.dstIp}:${f.dstPort}",
            fontSize = 13.sp, fontFamily = FontFamily.Monospace,
        )
        val stats = if (f.packets > 0) {
            "↑${humanBytes(f.bytesOut)} ↓${humanBytes(f.bytesIn)} · ${f.packets} pkts · ${humanDuration(f.durationMs)}"
        } else {
            "active…"
        }
        Text(
            "$stats  ·  ${timeFmt.format(Date(f.timestamp))}",
            fontSize = 12.sp, fontFamily = FontFamily.Monospace, color = MaterialTheme.colorScheme.outline,
        )
    }
    HorizontalDivider()
}

@Composable
private fun FlowDetail(f: FlowEntity, vm: MainViewModel) {
    val clip = LocalClipboardManager.current
    // Decrypt the payload fields once per row (metadata below stays cleartext).
    val d = remember(f.id) { vm.decryptDetail(f) }
    Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(16.dp)) {
        Text(f.appLabel ?: f.packageName ?: "uid ${f.uid}", fontWeight = FontWeight.Bold, fontSize = 18.sp)
        val color = if (f.isOffender) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface
        Text(f.verdict, color = color, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        DetailRow("Host", f.host ?: "—")
        f.tlsVersion?.let { DetailRow("TLS version", it) }
        DetailRow("Destination", "${f.dstIp}:${f.dstPort}")
        DetailRow("Protocol", if (f.proto == 6) "TCP" else if (f.proto == 17) "UDP" else "proto ${f.proto}")
        DetailRow("Source port", f.srcPort.toString())
        DetailRow("App package", f.packageName ?: "—")
        DetailRow("UID", f.uid.toString())
        DetailRow("Bytes", "↑${humanBytes(f.bytesOut)}  ↓${humanBytes(f.bytesIn)}")
        DetailRow("Packets", f.packets.toString())
        DetailRow("Duration", humanDuration(f.durationMs))
        DetailRow("Time", fullTimeFmt.format(Date(f.timestamp)))

        f.host?.let { host ->
            OutlinedButton(onClick = { clip.setText(AnnotatedString(host)) }, modifier = Modifier.padding(top = 8.dp)) {
                Text("Copy host")
            }
        }
        PayloadSection("Request", d.sampleText, clip)
        PayloadSection("Response", d.responseText, clip)
    }
}

@Composable
private fun PayloadSection(title: String, body: String?, clip: androidx.compose.ui.platform.ClipboardManager) {
    if (body.isNullOrBlank()) return
    Spacer(Modifier.height(12.dp))
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(title, fontWeight = FontWeight.Bold)
        Spacer(Modifier.width(12.dp))
        OutlinedButton(onClick = { clip.setText(AnnotatedString(body)) }) { Text("Copy") }
    }
    Text(
        body, fontSize = 11.sp, fontFamily = FontFamily.Monospace,
        modifier = Modifier.padding(top = 4.dp),
    )
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text(label, Modifier.width(110.dp), color = MaterialTheme.colorScheme.outline, fontSize = 13.sp)
        Text(value, fontSize = 13.sp, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun SettingsTab(vm: MainViewModel) {
    val cap by vm.cap.collectAsState()
    val flagUdp by vm.flagUdp.collectAsState()
    val flagOldTls by vm.flagOldTls.collectAsState()
    val autoStart by vm.autoStart.collectAsState()
    val running by vm.running.collectAsState()

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp)) {
        Text("Recording", fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Text("Max capture size per direction: ${humanBytes(cap.toLong())}", fontSize = 14.sp)
        // Slider over powers of two from 4KB (12) to 4MB (22).
        val minExp = 12f
        val maxExp = 22f
        var exp by remember(cap) { mutableStateOf((Math.log(cap.toDouble()) / Math.log(2.0)).toFloat().coerceIn(minExp, maxExp)) }
        Slider(
            value = exp, onValueChange = { exp = it },
            onValueChangeFinished = { vm.setCap((1 shl exp.toInt())) },
            valueRange = minExp..maxExp, enabled = !running,
        )
        Text("Applies next time you Start. Larger = more storage per flow.", fontSize = 12.sp, color = MaterialTheme.colorScheme.outline)

        Spacer(Modifier.height(20.dp))
        Text("Classification", fontWeight = FontWeight.Bold, fontSize = 16.sp)
        SettingSwitch("Flag non-QUIC UDP as cleartext", "Treat plaintext UDP (DNS, etc.) as offenders. Noisy.", flagUdp, !running) { vm.setFlagUdp(it) }
        SettingSwitch("Flag outdated TLS (< 1.2)", "Mark flows negotiating SSL 3.0 / TLS 1.0 / 1.1 as offenders.", flagOldTls, !running) { vm.setFlagOldTls(it) }

        Spacer(Modifier.height(20.dp))
        Text("General", fontWeight = FontWeight.Bold, fontSize = 16.sp)
        SettingSwitch("Auto-start on boot", "Best-effort: restart monitoring after reboot (may need always-on VPN).", autoStart, true) { vm.setAutoStart(it) }

        if (running) {
            Spacer(Modifier.height(16.dp))
            Text("Stop monitoring to change size/UDP settings.", fontSize = 12.sp, color = MaterialTheme.colorScheme.error)
        }

        Spacer(Modifier.height(20.dp))
        Text("About", fontWeight = FontWeight.Bold, fontSize = 16.sp)
        val context = LocalContext.current
        val (versionName, versionCode) = remember {
            runCatching {
                val pi = context.packageManager.getPackageInfo(context.packageName, 0)
                (pi.versionName ?: "?") to pi.longVersionCode
            }.getOrDefault("?" to 0L)
        }
        Text("TLS Watchdog", fontWeight = FontWeight.Medium)
        DetailRow("Version", "$versionName (build $versionCode)")
        DetailRow("Commit", BuildConfig.GIT_SHA)
        DetailRow("Commit date", BuildConfig.GIT_COMMIT_TIME)
        DetailRow("Package", context.packageName)
        Text(
            "On-device TLS usage monitor via a local VPN. Flags outbound traffic not using TLS.",
            fontSize = 12.sp, color = MaterialTheme.colorScheme.outline, modifier = Modifier.padding(top = 4.dp),
        )
    }
}

@Composable
private fun SettingSwitch(title: String, subtitle: String, checked: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(title, fontWeight = FontWeight.Medium)
            Text(subtitle, fontSize = 12.sp, color = MaterialTheme.colorScheme.outline)
        }
        Switch(checked = checked, onCheckedChange = onChange, enabled = enabled)
    }
}

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
