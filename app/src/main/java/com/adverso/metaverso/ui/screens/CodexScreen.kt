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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp
import com.adverso.metaverso.core.model.ShadowAggregate
import com.adverso.metaverso.core.model.ShadowKind
import com.adverso.metaverso.ui.components.SectionTitle
import com.adverso.metaverso.ui.theme.Ink
import com.adverso.metaverso.ui.theme.P5Bone
import com.adverso.metaverso.ui.theme.P5Ink
import com.adverso.metaverso.ui.theme.P5Red
import com.adverso.metaverso.ui.theme.P5White
import com.adverso.metaverso.ui.theme.rememberSkewShape
import com.adverso.metaverso.ui.theme.rememberSlashShape
import com.adverso.metaverso.ui.theme.tint

/**
 * El Códice: todas las Sombras encontradas, con su ficha y su destino. Es la
 * lista de bloqueo editable de la app disfrazada de compendio de personas.
 */
@Composable
fun CodexScreen(
    shadows: Map<String, ShadowAggregate>,
    stolen: Set<String>,
    pacted: Set<String>,
    onSteal: (String) -> Unit,
    onSeal: (String) -> Unit,
    onRelease: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var filter by remember { mutableStateOf<ShadowKind?>(null) }
    val visible = remember(shadows, filter) {
        shadows.values
            .filter { filter == null || it.kind == filter }
            .sortedWith(
                compareByDescending<ShadowAggregate> { it.score }
                    .thenByDescending { it.encounters },
            )
    }
    val tally = remember(shadows) {
        ShadowKind.entries.associateWith { kind -> shadows.values.count { it.kind == kind } }
    }

    LazyColumn(
        modifier = modifier.fillMaxWidth(),
        contentPadding = PaddingValues(start = 18.dp, end = 18.dp, top = 14.dp, bottom = 28.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        item {
            SectionTitle(
                "Códice de sombras",
                "${shadows.size} registradas · ${stolen.size} corazones robados a mano",
            )
        }

        item {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    KindTab("TODAS", filter == null, P5Red, shadows.size, Modifier.weight(1f)) { filter = null }
                }
                ShadowKind.entries
                    .filter { (tally[it] ?: 0) > 0 }
                    .chunked(2)
                    .forEach { pair ->
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            pair.forEach { kind ->
                                KindTab(
                                    text = kind.display.removePrefix("SOMBRA "),
                                    selected = filter == kind,
                                    accent = kind.tint(),
                                    count = tally[kind] ?: 0,
                                    modifier = Modifier.weight(1f),
                                ) { filter = if (filter == kind) null else kind }
                            }
                            if (pair.size == 1) Spacer(Modifier.weight(1f))
                        }
                    }
            }
        }

        if (filter != null) {
            item {
                Text(filter!!.blurb, style = Ink.body, color = P5Bone)
            }
        }

        if (visible.isEmpty()) {
            item {
                Column(
                    Modifier
                        .fillMaxWidth()
                        .clip(rememberSlashShape(topEnd = 16.dp, bottomStart = 16.dp))
                        .background(P5Ink)
                        .padding(20.dp),
                ) {
                    Text("CÓDICE VACÍO", style = Ink.title, color = P5White)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Cada dominio nuevo que aparezca queda fichado aquí para siempre, " +
                            "con el motivo por el que lo clasificamos así.",
                        style = Ink.body,
                        color = P5Bone,
                    )
                }
            }
        }

        items(visible, key = { it.domain }) { shadow ->
            ShadowRow(
                shadow = shadow,
                isStolen = stolen.contains(shadow.domain),
                isPacted = pacted.contains(shadow.domain),
                onSteal = onSteal,
                onSeal = onSeal,
                onRelease = onRelease,
            )
        }
    }
}

@Composable
private fun KindTab(
    text: String,
    selected: Boolean,
    accent: androidx.compose.ui.graphics.Color,
    count: Int,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    val shape = rememberSkewShape(lean = 6.dp)
    Box(
        modifier
            .clip(shape)
            .background(if (selected) accent else P5Ink)
            .clickable(onClick = onClick)
            .padding(horizontal = 10.dp, vertical = 8.dp),
        contentAlignment = Alignment.CenterStart,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text,
                style = Ink.label,
                color = if (selected) P5White else accent,
                maxLines = 1,
                modifier = Modifier.weight(1f, fill = false),
            )
            Spacer(Modifier.width(6.dp))
            Text(
                count.toString(),
                style = Ink.label,
                color = if (selected) P5White else P5Bone,
            )
        }
    }
}
