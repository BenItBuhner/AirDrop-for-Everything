package tech.airdrop4e

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle

class MainActivity : ComponentActivity() {

    private val vm: MainViewModel by viewModels()

    // Storage Access Framework picker — returns content:// URIs, which the
    // ViewModel copies into a cache-dir outbox for a4e_send_files.
    private val picker =
        registerForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
            if (!uris.isNullOrEmpty()) vm.stage(uris)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                A4eApp(vm, onPickFiles = { picker.launch(arrayOf("*/*")) })
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun A4eApp(vm: MainViewModel, onPickFiles: () -> Unit) {
    val receiverOn by vm.receiverOn.collectAsStateWithLifecycle()
    val peers by vm.peers.collectAsStateWithLifecycle()
    val browsing by vm.browsing.collectAsStateWithLifecycle()
    val staged by vm.staged.collectAsStateWithLifecycle()
    val pendingAsks by vm.pendingAsks.collectAsStateWithLifecycle()
    val log by vm.log.collectAsStateWithLifecycle()

    Scaffold(
        topBar = { TopAppBar(title = { Text("AirDrop for Everything") }) },
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            // ---- receiver -------------------------------------------------
            Card(Modifier.fillMaxWidth()) {
                Row(
                    Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("Receiver", fontWeight = FontWeight.Bold)
                        Text(
                            if (receiverOn) "discoverable — saving to ${vm.destDir.name}/"
                            else "off",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    Switch(checked = receiverOn, onCheckedChange = vm::setReceiver)
                }
            }

            // ---- actions --------------------------------------------------
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { vm.browse() }, enabled = !browsing) {
                    Text(if (browsing) "Browsing…" else "Find peers")
                }
                OutlinedButton(onClick = onPickFiles) { Text("Pick files") }
                if (staged.isNotEmpty()) {
                    TextButton(onClick = vm::clearStaged) { Text("Clear") }
                }
            }
            if (staged.isNotEmpty()) {
                Text(
                    "staged: ${staged.joinToString(", ") { it.name }}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            // ---- peers ----------------------------------------------------
            Text("Peers", fontWeight = FontWeight.Bold)
            LazyColumn(Modifier.weight(1f)) {
                items(peers, key = { it.ident }) { peer ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clickable { vm.sendTo(peer) }
                            .padding(vertical = 8.dp),
                    ) {
                        Column {
                            Text(peer.displayName)
                            Text(
                                "${peer.ident}  ${peer.endpoint}",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                    HorizontalDivider()
                }
                if (peers.isEmpty()) {
                    item {
                        Text(
                            if (browsing) "listening on _airdrop._tcp…"
                            else "no peers — tap “Find peers”",
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(vertical = 8.dp),
                        )
                    }
                }
            }

            // ---- log ------------------------------------------------------
            Text("Log", fontWeight = FontWeight.Bold)
            LazyColumn(Modifier.weight(1f)) {
                items(log) { line ->
                    Text(
                        line,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                    )
                }
            }
        }
    }

    // ---- incoming /Ask dialog --------------------------------------------
    pendingAsks.firstOrNull()?.let { ask ->
        AlertDialog(
            onDismissRequest = { vm.answerAsk(false) },
            title = { Text("Incoming AirDrop") },
            text = {
                Column {
                    Text("${ask.senderName} (${ask.senderModel}) wants to send:")
                    Spacer(Modifier.height(8.dp))
                    ask.files.take(8).forEach {
                        Text("• ${it.name} (${it.size} B)")
                    }
                    if (ask.files.size > 8) Text("…and ${ask.files.size - 8} more")
                }
            },
            confirmButton = {
                TextButton(onClick = { vm.answerAsk(true) }) { Text("Accept") }
            },
            dismissButton = {
                TextButton(onClick = { vm.answerAsk(false) }) { Text("Decline") }
            },
        )
    }
}
