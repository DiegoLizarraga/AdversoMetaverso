package com.adverso.metaverso.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import com.adverso.metaverso.core.model.ShadowEvent
import com.adverso.metaverso.ui.components.Chip
import com.adverso.metaverso.ui.components.SectionTitle
import com.adverso.metaverso.ui.theme.Ink
import com.adverso.metaverso.ui.theme.P5Bone
import com.adverso.metaverso.ui.theme.P5Ink
import com.adverso.metaverso.ui.theme.P5Red
import com.adverso.metaverso.ui.theme.P5White
import com.adverso.metaverso.ui.theme.rememberSkewShape
import com.adverso.metaverso.ui.theme.rememberSlashShape
import com.adverso.metaverso.ui.theme.tint
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Mementos: el flujo en vivo. Cada línea es una consulta real que acaba de salir
 * del teléfono, con quién la pidió y qué decidimos hacer con ella.
 */
@Composable
fun MementosScreen(
    events: List<ShadowEvent>,
    modifier: Modifier = Modifier,
) {
    var onlyBlocked by remember { mutableStateOf(false) }
    val clock = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }
    val visible = remember(events, onlyBlocked) {
        val filtered = if (onlyBlocked) events.filter { it.blocked } else events
        filtered.asReversed()
    }
    val listState = rememberLazyListState()

    // Al llegar algo nuevo volvemos arriba, que es donde está lo más reciente.
    LaunchedEffect(visible.firstOrNull()?.id) {
        if (listState.firstVisibleItemIndex <= 2) listState.animateScrollToItem(0)
    }

    Column(modifier.fillMaxWidth()) {
        Column(Modifier.padding(horizontal = 18.dp, vertical = 14.dp)) {
            SectionTitle("Mementos", "El rastro en vivo de esta red")
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterTab("TODO", !onlyBlocked, Modifier.weight(1f)) { onlyBlocked = false }
                FilterTab("SOLO ROBOS", onlyBlocked, Modifier.weight(1f)) { onlyBlocked = true }
            }
        }

        if (visible.isEmpty()) {
            Column(Modifier.padding(horizontal = 18.dp)) {
                Text("SILENCIO ABSOLUTO", style = Ink.title, color = P5White)
                Spacer(Modifier.height(8.dp))
                Text(
                    "Nada todavía. Activa el Navegador y abre cualquier app: en segundos " +
                        "empezarás a ver los nombres que pide.",
                    style = Ink.body,
                    color = P5Bone,
                )
            }
        } else {
            LazyColumn(
                state = listState,
                contentPadding = PaddingValues(start = 18.dp, end = 18.dp, bottom = 28.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                items(visible, key = { it.id }) { event ->
                    EventRow(event, clock)
                }
            }
        }
    }
}

@Composable
private fun EventRow(event: ShadowEvent, clock: SimpleDateFormat) {
    val color = event.kind.tint()
    Row(
        Modifier
            .fillMaxWidth()
            .clip(rememberSlashShape(topEnd = 10.dp, bottomStart = 10.dp))
            .background(if (event.blocked) P5Red.copy(alpha = 0.16f) else P5Ink)
            .padding(horizontal = 12.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        // Marca de decisión: una barra roja si le robamos el corazón.
        Box(
            Modifier
                .width(4.dp)
                .height(38.dp)
                .background(if (event.blocked) P5Red else color.copy(alpha = 0.5f)),
        )
        Spacer(Modifier.width(10.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(clock.format(Date(event.timestamp)), style = Ink.mono, color = P5Bone)
                Spacer(Modifier.width(8.dp))
                Text(
                    event.appLabel.uppercase(),
                    style = Ink.label,
                    color = P5White,
                    maxLines = 1,
                )
            }
            Spacer(Modifier.height(3.dp))
            Text(event.domain, style = Ink.mono, color = if (event.blocked) P5Red else P5White, maxLines = 1)
            Spacer(Modifier.height(5.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                Chip(event.queryType, P5Bone)
                Chip(event.kind.display, color)
                if (event.latencyMs >= 0) Chip("${event.latencyMs} ms", P5Bone)
            }
        }
        Spacer(Modifier.width(8.dp))
        Column(horizontalAlignment = Alignment.End) {
            Text(
                if (event.blocked) "✕" else "→",
                style = Ink.numeral,
                color = if (event.blocked) P5Red else color,
            )
            Text(event.score.toString(), style = Ink.label, color = P5Bone)
        }
    }
}

@Composable
private fun FilterTab(
    text: String,
    selected: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    Box(
        modifier
            .clip(rememberSkewShape(lean = 6.dp))
            .background(if (selected) P5Red else P5Ink)
            .clickable(onClick = onClick)
            .padding(vertical = 9.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, style = Ink.label, color = if (selected) P5White else P5Bone)
    }
}
