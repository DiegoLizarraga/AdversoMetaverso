package com.adverso.metaverso.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.adverso.metaverso.core.model.ThreatTier
import com.adverso.metaverso.ui.theme.Ink
import com.adverso.metaverso.ui.theme.P5Black
import com.adverso.metaverso.ui.theme.P5Bone
import com.adverso.metaverso.ui.theme.P5Coal
import com.adverso.metaverso.ui.theme.P5Ink
import com.adverso.metaverso.ui.theme.P5Red
import com.adverso.metaverso.ui.theme.P5White
import com.adverso.metaverso.ui.theme.rememberSkewShape
import com.adverso.metaverso.ui.theme.rememberSlashShape
import com.adverso.metaverso.ui.theme.rememberTornShape
import com.adverso.metaverso.ui.theme.tint

/** Título de sección: bloque rojo inclinado con el texto en cursiva pesada. */
@Composable
fun SectionTitle(
    title: String,
    subtitle: String? = null,
    modifier: Modifier = Modifier,
    accent: Color = P5Red,
) {
    Column(modifier) {
        Box(
            Modifier
                .rotate(-1.2f)
                .clip(rememberSkewShape(lean = 12.dp))
                .background(accent)
                .padding(horizontal = 18.dp, vertical = 7.dp),
        ) {
            Text(title.uppercase(), style = Ink.title, color = P5White)
        }
        if (subtitle != null) {
            Spacer(Modifier.height(6.dp))
            Text(
                subtitle,
                style = Ink.caption,
                color = P5Bone,
                modifier = Modifier.padding(start = 4.dp),
            )
        }
    }
}

/** Panel de papel rasgado sobre el que se apoya el contenido. */
@Composable
fun TornPanel(
    seed: Int,
    modifier: Modifier = Modifier,
    background: Color = P5Ink,
    lean: Float = 0f,
    content: @Composable ColumnScope.() -> Unit,
) {
    Box(
        modifier
            .rotate(lean)
            .clip(rememberTornShape(seed))
            .background(background),
    ) {
        Column(
            Modifier.padding(horizontal = 16.dp, vertical = 20.dp),
            content = content,
        )
    }
}

/** El botón grande de "INFILTRAR / SALIR". */
@Composable
fun PhantomButton(
    label: String,
    caption: String,
    active: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val background by animateColorAsState(
        targetValue = if (active) P5Black else P5Red,
        animationSpec = tween(280),
        label = "buttonBg",
    )
    val border by animateColorAsState(
        targetValue = if (active) P5Red else P5White,
        animationSpec = tween(280),
        label = "buttonBorder",
    )
    Box(
        modifier
            .rotate(-1.4f)
            .clip(rememberSlashShape(topEnd = 26.dp, bottomStart = 26.dp))
            .background(background)
            .border(3.dp, border, rememberSlashShape(topEnd = 26.dp, bottomStart = 26.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 26.dp, vertical = 20.dp),
        contentAlignment = Alignment.Center,
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Text(label.uppercase(), style = Ink.display, color = P5White, textAlign = TextAlign.Center)
            Spacer(Modifier.height(4.dp))
            Text(caption.uppercase(), style = Ink.label, color = if (active) P5Red else P5White)
        }
    }
}

/** El medidor de seguridad del Palacio, calcado del HUD del juego. */
@Composable
fun AlertGauge(
    value: Int,
    tier: ThreatTier,
    modifier: Modifier = Modifier,
) {
    val fraction by animateFloatAsState(
        targetValue = (value / 100f).coerceIn(0f, 1f),
        animationSpec = tween(600),
        label = "gauge",
    )
    val color = tier.tint()
    Column(modifier) {
        Row(verticalAlignment = Alignment.Bottom) {
            Text("NIVEL DE ALERTA", style = Ink.label, color = P5Bone)
            Spacer(Modifier.width(10.dp))
            Text("$value%", style = Ink.numeral, color = color)
        }
        Spacer(Modifier.height(8.dp))
        Box(
            Modifier
                .fillMaxWidth()
                .height(16.dp)
                .clip(rememberSkewShape(lean = 8.dp))
                .background(P5Coal),
        ) {
            Box(
                Modifier
                    .fillMaxWidth(fraction)
                    .fillMaxHeight()
                    .background(color),
            )
        }
        Spacer(Modifier.height(6.dp))
        Text(tier.label, style = Ink.label, color = color)
    }
}

/** Cifra grande con etiqueta: la unidad del panel de estado. */
@Composable
fun StatTile(
    value: String,
    label: String,
    modifier: Modifier = Modifier,
    accent: Color = P5White,
) {
    Column(
        modifier
            .clip(rememberSlashShape(topEnd = 12.dp, bottomStart = 12.dp))
            .background(P5Ink)
            .padding(horizontal = 12.dp, vertical = 10.dp),
    ) {
        Text(value, style = Ink.numeral, color = accent, maxLines = 1)
        Spacer(Modifier.height(2.dp))
        Text(
            label.uppercase(),
            style = Ink.label,
            color = P5Bone,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

/** Etiqueta pequeña inclinada para categorías y tipos de Sombra. */
@Composable
fun Chip(
    text: String,
    color: Color,
    modifier: Modifier = Modifier,
    filled: Boolean = false,
) {
    Box(
        modifier
            .clip(rememberSkewShape(lean = 5.dp))
            .background(if (filled) color else Color.Transparent)
            .border(1.5.dp, color, rememberSkewShape(lean = 5.dp))
            .padding(horizontal = 9.dp, vertical = 3.dp),
    ) {
        Text(
            text.uppercase(),
            style = Ink.label,
            color = if (filled) P5Black else color,
            maxLines = 1,
        )
    }
}

/** Insignia de rango: la letra dentro de un rombo, como los resultados de combate. */
@Composable
fun RankBadge(letter: Char, color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier
            .size(44.dp)
            .rotate(45f)
            .background(color)
            .padding(1.dp),
        contentAlignment = Alignment.Center,
    ) {
        Box(Modifier.rotate(-45f)) {
            Text(letter.toString(), style = Ink.title, color = P5Black)
        }
    }
}

/** Barrita de puntuación fina, para las filas de listado. */
@Composable
fun ScoreBar(score: Int, color: Color, modifier: Modifier = Modifier) {
    Box(
        modifier
            .height(5.dp)
            .clip(RoundedCornerShape(1.dp))
            .background(P5Coal),
    ) {
        Box(
            Modifier
                .fillMaxWidth((score / 100f).coerceIn(0f, 1f))
                .fillMaxHeight()
                .background(color),
        )
    }
}

/** Aviso de una sola línea, en rojo, para lo que el usuario debe saber ya. */
@Composable
fun NoticeStrip(message: String, onDismiss: () -> Unit, modifier: Modifier = Modifier) {
    Row(
        modifier
            .fillMaxWidth()
            .clip(rememberSkewShape(lean = 10.dp))
            .background(P5Red)
            .clickable(onClick = onDismiss)
            .padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(message, style = Ink.caption, color = P5White, modifier = Modifier.weight(1f))
        Spacer(Modifier.width(10.dp))
        Text("✕", style = Ink.label, color = P5White)
    }
}
