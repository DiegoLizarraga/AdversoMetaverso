package com.adverso.metaverso.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.unit.dp
import com.adverso.metaverso.core.Metaverse
import com.adverso.metaverso.core.model.PalaceAggregate
import com.adverso.metaverso.ui.components.Chip
import com.adverso.metaverso.ui.components.RankBadge
import com.adverso.metaverso.ui.components.ScoreBar
import com.adverso.metaverso.ui.components.SectionTitle
import com.adverso.metaverso.ui.theme.Ink
import com.adverso.metaverso.ui.theme.P5Bone
import com.adverso.metaverso.ui.theme.P5Ink
import com.adverso.metaverso.ui.theme.P5Red
import com.adverso.metaverso.ui.theme.P5White
import com.adverso.metaverso.ui.theme.rememberSkewShape
import com.adverso.metaverso.ui.theme.rememberSlashShape
import com.adverso.metaverso.ui.theme.tint

private enum class PalaceOrder(val label: String) {
    AMENAZA("Amenaza"),
    SOMBRAS("Sombras"),
    VOLUMEN("Volumen"),
}

/** El mapa de Palacios: una tarjeta por app que ha hablado con la red. */
@Composable
fun PalacesScreen(
    palaces: Map<Int, PalaceAggregate>,
    onOpen: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    var order by remember { mutableStateOf(PalaceOrder.AMENAZA) }
    val visible = remember(palaces, order) {
        palaces.values
            .filter { it.queries > 0 || it.bytesTotal > 0 }
            .sortedWith(
                when (order) {
                    PalaceOrder.AMENAZA -> compareByDescending<PalaceAggregate> { it.threatScore }
                        .thenByDescending { it.domains.size }
                    PalaceOrder.SOMBRAS -> compareByDescending<PalaceAggregate> { it.domains.size }
                        .thenByDescending { it.threatScore }
                    PalaceOrder.VOLUMEN -> compareByDescending<PalaceAggregate> { it.bytesTotal }
                        .thenByDescending { it.threatScore }
                },
            )
    }

    LazyColumn(
        modifier = modifier.fillMaxWidth(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(
            start = 18.dp, end = 18.dp, top = 14.dp, bottom = 28.dp,
        ),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            SectionTitle(
                "Palacios",
                "${visible.size} apps con actividad · ordenadas por ${order.label.lowercase()}",
            )
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                PalaceOrder.entries.forEach { option ->
                    Box(
                        Modifier
                            .weight(1f)
                            .clip(rememberSkewShape(lean = 6.dp))
                            .background(if (order == option) P5Red else P5Ink)
                            .clickable { order = option }
                            .padding(vertical = 9.dp),
                        contentAlignment = Alignment.Center,
                    ) {
                        Text(
                            option.label.uppercase(),
                            style = Ink.label,
                            color = if (order == option) P5White else P5Bone,
                        )
                    }
                }
            }
        }

        if (visible.isEmpty()) {
            item { EmptyPalaces() }
        }

        items(visible, key = { it.uid }) { palace ->
            PalaceCard(palace, onOpen)
        }
    }
}

@Composable
private fun PalaceCard(palace: PalaceAggregate, onOpen: (Int) -> Unit) {
    val color = palace.tier.tint()
    val shape = rememberSlashShape(topEnd = 20.dp, bottomStart = 20.dp)
    Row(
        Modifier
            .fillMaxWidth()
            .rotate(-0.6f)
            .clip(shape)
            .background(P5Ink)
            .clickable { onOpen(palace.uid) }
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        RankBadge(palace.rank.letter, color)
        Spacer(Modifier.width(18.dp))
        Column(Modifier.weight(1f)) {
            Text(
                palace.label.uppercase(),
                style = Ink.title,
                color = P5White,
                maxLines = 1,
            )
            Text(
                palace.packageName,
                style = Ink.mono,
                color = P5Bone,
                maxLines = 1,
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Chip(palace.rank.label, color)
                Chip("${palace.domains.size} sombras", P5Bone)
                if (palace.blocked > 0) Chip("${palace.blocked} robos", P5Red, filled = true)
            }
            if (palace.bytesTotal > 0) {
                Spacer(Modifier.height(6.dp))
                Text(
                    "↑ ${Metaverse.formatBytes(palace.bytesTx)}   ↓ ${Metaverse.formatBytes(palace.bytesRx)}",
                    style = Ink.caption,
                    color = P5Bone,
                )
            }
            Spacer(Modifier.height(8.dp))
            ScoreBar(palace.threatScore, color, Modifier.fillMaxWidth())
        }
        Spacer(Modifier.width(12.dp))
        Column(horizontalAlignment = Alignment.End) {
            Text(palace.threatScore.toString(), style = Ink.numeral, color = color)
            Text(palace.dominantKind.distortion, style = Ink.label, color = P5Bone)
        }
    }
}

@Composable
private fun EmptyPalaces() {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(rememberSlashShape(topEnd = 16.dp, bottomStart = 16.dp))
            .background(P5Ink)
            .padding(20.dp),
    ) {
        Text("NINGÚN PALACIO ABIERTO", style = Ink.title, color = P5White)
        Spacer(Modifier.height(8.dp))
        Text(
            "Entra al Metaverso desde el Nav y deja el teléfono trabajar un rato. " +
                "En cuanto una app pida un nombre de dominio, su Palacio aparecerá aquí.",
            style = Ink.body,
            color = P5Bone,
        )
    }
}
