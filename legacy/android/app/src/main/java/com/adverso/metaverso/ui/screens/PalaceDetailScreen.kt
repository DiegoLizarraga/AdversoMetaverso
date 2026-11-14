package com.adverso.metaverso.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.unit.dp
import com.adverso.metaverso.core.Metaverse
import com.adverso.metaverso.core.model.PalaceAggregate
import com.adverso.metaverso.core.model.ShadowAggregate
import com.adverso.metaverso.ui.components.Chip
import com.adverso.metaverso.ui.components.RankBadge
import com.adverso.metaverso.ui.components.ScoreBar
import com.adverso.metaverso.ui.theme.Ink
import com.adverso.metaverso.ui.theme.P5Black
import com.adverso.metaverso.ui.theme.P5Bone
import com.adverso.metaverso.ui.theme.P5Coal
import com.adverso.metaverso.ui.theme.P5Ink
import com.adverso.metaverso.ui.theme.P5Red
import com.adverso.metaverso.ui.theme.P5White
import com.adverso.metaverso.ui.theme.P5Yellow
import com.adverso.metaverso.ui.theme.rememberSkewShape
import com.adverso.metaverso.ui.theme.rememberSlashShape
import com.adverso.metaverso.ui.theme.tint

/**
 * El interior de un Palacio: la tarjeta de presentación y la lista completa de
 * cómplices con los que habla la app.
 */
@Composable
fun PalaceDetailScreen(
    palace: PalaceAggregate?,
    shadows: List<ShadowAggregate>,
    stolen: Set<String>,
    pacted: Set<String>,
    onBack: () -> Unit,
    onSteal: (String) -> Unit,
    onSeal: (String) -> Unit,
    onRelease: (String) -> Unit,
    onShareCard: (String) -> Unit,
    onStealAll: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    if (palace == null) {
        Column(modifier.padding(18.dp)) {
            BackRow(onBack)
            Spacer(Modifier.height(20.dp))
            Text("ESTE PALACIO SE DESVANECIÓ", style = Ink.title, color = P5White)
        }
        return
    }

    val color = palace.tier.tint()
    val sorted = remember(shadows) { shadows.sortedByDescending { it.score } }
    val card = remember(palace, shadows) { Metaverse.callingCard(palace.uid) }

    LazyColumn(
        modifier = modifier.fillMaxWidth(),
        contentPadding = PaddingValues(start = 18.dp, end = 18.dp, top = 14.dp, bottom = 30.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { BackRow(onBack) }

        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                RankBadge(palace.rank.letter, color)
                Spacer(Modifier.width(18.dp))
                Column {
                    Text(palace.label.uppercase(), style = Ink.display, color = P5White)
                    Text(palace.packageName, style = Ink.mono, color = P5Bone)
                }
            }
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Chip(palace.rank.label, color, filled = true)
                Chip(palace.dominantKind.distortion, P5Yellow)
                if (Metaverse.isSystemApp(palace.packageName)) Chip("Sistema", P5Bone)
            }
        }

        // La carta de los Ladrones Fantasma: el informe legible del Palacio.
        item {
            Column(
                Modifier
                    .fillMaxWidth()
                    .rotate(-1f)
                    .clip(rememberSlashShape(topEnd = 22.dp, bottomStart = 22.dp))
                    .background(P5White)
                    .padding(18.dp),
            ) {
                Text(card, style = Ink.mono, color = P5Black)
                Spacer(Modifier.height(14.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Box(
                        Modifier
                            .clip(rememberSkewShape(lean = 6.dp))
                            .background(P5Red)
                            .clickable { onShareCard(card) }
                            .padding(horizontal = 14.dp, vertical = 8.dp),
                    ) {
                        Text("ENVIAR LA CARTA", style = Ink.label, color = P5White)
                    }
                    Box(
                        Modifier
                            .clip(rememberSkewShape(lean = 6.dp))
                            .border(2.dp, P5Black, rememberSkewShape(lean = 6.dp))
                            .clickable { onStealAll(palace.uid) }
                            .padding(horizontal = 14.dp, vertical = 8.dp),
                    ) {
                        Text("ROBAR TODO EL TESORO", style = Ink.label, color = P5Black)
                    }
                }
            }
        }

        item {
            Text(
                "CÓMPLICES · ${sorted.size}",
                style = Ink.label,
                color = P5Bone,
                modifier = Modifier.padding(top = 6.dp),
            )
        }

        items(sorted, key = { it.domain }) { shadow ->
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
private fun BackRow(onBack: () -> Unit) {
    Box(
        Modifier
            .clip(rememberSkewShape(lean = 8.dp, toRight = false))
            .background(P5Coal)
            .clickable(onClick = onBack)
            .padding(horizontal = 16.dp, vertical = 8.dp),
    ) {
        Text("‹ VOLVER AL MAPA", style = Ink.label, color = P5White)
    }
}

/**
 * Una Sombra en la lista, con sus tres destinos posibles: robarle el corazón,
 * sellar un pacto o dejarla al criterio del motor.
 */
@Composable
fun ShadowRow(
    shadow: ShadowAggregate,
    isStolen: Boolean,
    isPacted: Boolean,
    onSteal: (String) -> Unit,
    onSeal: (String) -> Unit,
    onRelease: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val color = shadow.kind.tint()
    Column(
        modifier
            .fillMaxWidth()
            .clip(rememberSlashShape(topEnd = 14.dp, bottomStart = 14.dp))
            .background(P5Ink)
            .padding(14.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(shadow.codename, style = Ink.label, color = color)
                Text(shadow.domain, style = Ink.mono, color = P5White)
            }
            Spacer(Modifier.width(10.dp))
            Text(shadow.score.toString(), style = Ink.numeral, color = color)
        }
        Spacer(Modifier.height(8.dp))
        ScoreBar(shadow.score, color, Modifier.fillMaxWidth())
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Chip(shadow.kind.display, color)
            Chip("×${shadow.encounters}", P5Bone)
            if (shadow.blockedCount > 0) Chip("${shadow.blockedCount} cortadas", P5Red, filled = true)
        }
        if (shadow.category != "Sin clasificar") {
            Spacer(Modifier.height(6.dp))
            Text(shadow.category, style = Ink.caption, color = P5Bone)
        }
        Spacer(Modifier.height(8.dp))
        shadow.reasons.take(3).forEach { reason ->
            Text("· $reason", style = Ink.caption, color = P5Bone)
        }
        if (shadow.addresses.isNotEmpty()) {
            Spacer(Modifier.height(6.dp))
            Text("→ ${shadow.addresses.joinToString(", ")}", style = Ink.mono, color = P5Bone)
        }

        Spacer(Modifier.height(12.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            VerdictButton(
                text = if (isStolen) "CORAZÓN ROBADO" else "ROBAR",
                selected = isStolen,
                accent = P5Red,
                modifier = Modifier.weight(1f),
            ) { if (isStolen) onRelease(shadow.domain) else onSteal(shadow.domain) }
            VerdictButton(
                text = if (isPacted) "PACTO SELLADO" else "PACTAR",
                selected = isPacted,
                accent = P5Yellow,
                modifier = Modifier.weight(1f),
            ) { if (isPacted) onRelease(shadow.domain) else onSeal(shadow.domain) }
        }
    }
}

@Composable
private fun VerdictButton(
    text: String,
    selected: Boolean,
    accent: androidx.compose.ui.graphics.Color,
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
) {
    val shape = rememberSkewShape(lean = 6.dp)
    Box(
        modifier
            .clip(shape)
            .background(if (selected) accent else androidx.compose.ui.graphics.Color.Transparent)
            .border(1.5.dp, accent, shape)
            .clickable(onClick = onClick)
            .padding(vertical = 9.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, style = Ink.label, color = if (selected) P5Black else accent, maxLines = 1)
    }
}
