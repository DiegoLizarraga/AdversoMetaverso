package com.adverso.metaverso.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.adverso.metaverso.core.Metaverse
import com.adverso.metaverso.core.model.MetaversePulse
import com.adverso.metaverso.core.model.PalaceAggregate
import com.adverso.metaverso.ui.MetaversoActions
import com.adverso.metaverso.ui.components.AlertGauge
import com.adverso.metaverso.ui.components.Chip
import com.adverso.metaverso.ui.components.PhantomButton
import com.adverso.metaverso.ui.components.SectionTitle
import com.adverso.metaverso.ui.components.StatTile
import com.adverso.metaverso.ui.components.TornPanel
import com.adverso.metaverso.ui.theme.Ink
import com.adverso.metaverso.ui.theme.P5Bone
import com.adverso.metaverso.ui.theme.P5Coal
import com.adverso.metaverso.ui.theme.P5Cyan
import com.adverso.metaverso.ui.theme.P5Ink
import com.adverso.metaverso.ui.theme.P5Red
import com.adverso.metaverso.ui.theme.P5White
import com.adverso.metaverso.ui.theme.P5Yellow
import com.adverso.metaverso.ui.theme.rememberSkewShape
import com.adverso.metaverso.ui.theme.rememberSlashShape

/**
 * El Nav: la pantalla desde la que se entra y se sale del Metaverso, con el
 * pulso de la sesión en curso.
 */
@Composable
fun NavScreen(
    pulse: MetaversePulse,
    active: Boolean,
    blocking: Boolean,
    hijack: Boolean,
    threshold: Int,
    hasTrafficAccess: Boolean,
    palaces: Map<Int, PalaceAggregate>,
    actions: MetaversoActions,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 18.dp)
            .padding(bottom = 28.dp),
    ) {
        Spacer(Modifier.height(14.dp))

        Text(
            if (active) "ESTÁS DENTRO" else "MUNDO REAL",
            style = Ink.hero,
            color = if (active) P5Red else P5White,
        )
        Text(
            if (active) {
                "El Navegador ve cada nombre que pide este teléfono."
            } else {
                "Nadie está mirando. Las Sombras se mueven libres."
            },
            style = Ink.body,
            color = P5Bone,
        )

        Spacer(Modifier.height(20.dp))

        PhantomButton(
            label = if (active) "Salir del Metaverso" else "Infiltrar",
            caption = if (active) "Cerrar el túnel" else "Activar el Navegador",
            active = active,
            onClick = actions.toggleNavigator,
            modifier = Modifier.fillMaxWidth(),
        )

        Spacer(Modifier.height(22.dp))

        AlertGauge(pulse.alert, pulse.tier, Modifier.fillMaxWidth())

        Spacer(Modifier.height(20.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            StatTile(
                value = pulse.queries.toString(),
                label = "Sombras\navistadas",
                accent = P5White,
                modifier = Modifier.weight(1f),
            )
            StatTile(
                value = pulse.blocked.toString(),
                label = "Tesoros\nconfiscados",
                accent = P5Red,
                modifier = Modifier.weight(1f),
            )
            StatTile(
                value = pulse.shadows.toString(),
                label = "Sombras\núnicas",
                accent = P5Yellow,
                modifier = Modifier.weight(1f),
            )
        }

        Spacer(Modifier.height(10.dp))

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            StatTile(
                value = pulse.palaces.toString(),
                label = "Palacios\nabiertos",
                accent = P5Cyan,
                modifier = Modifier.weight(1f),
            )
            StatTile(
                value = pulse.corrupted.toString(),
                label = "Sombras\ncorruptas",
                accent = if (pulse.corrupted > 0) P5Red else P5Bone,
                modifier = Modifier.weight(1f),
            )
            StatTile(
                value = "${(pulse.blockRate * 100).toInt()}%",
                label = "Ratio de\nconfiscación",
                accent = P5Yellow,
                modifier = Modifier.weight(1f),
            )
        }

        if (pulse.lastDomain != null) {
            Spacer(Modifier.height(14.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Chip("Último rastro", P5Red, filled = true)
                Spacer(Modifier.width(8.dp))
                Text(pulse.lastDomain, style = Ink.mono, color = P5White, maxLines = 1)
            }
        }

        Spacer(Modifier.height(28.dp))

        SectionTitle("Los ladrones fantasma", "Cómo se comporta el Navegador")
        Spacer(Modifier.height(14.dp))

        TornPanel(seed = 41, lean = -0.5f, modifier = Modifier.fillMaxWidth()) {
            ToggleRow(
                title = "Robar corazones",
                description = "Devuelve una dirección nula a las Sombras que superan el umbral. " +
                    "Apagado, el Navegador solo observa.",
                checked = blocking,
                onToggle = actions.toggleBlocking,
            )
            Spacer(Modifier.height(16.dp))
            ThresholdRow(threshold, actions)
            Spacer(Modifier.height(16.dp))
            ToggleRow(
                title = "Modo agresivo",
                description = "Desvía también los resolutores públicos (8.8.8.8, 1.1.1.1…) para " +
                    "pillar apps con DNS propio. Puede romper el DNS privado si apunta ahí.",
                checked = hijack,
                onToggle = actions.toggleHijack,
                accent = P5Yellow,
            )
        }

        Spacer(Modifier.height(24.dp))

        SectionTitle("El día a día", "Bytes que este teléfono movió hoy", accent = P5Coal)
        Spacer(Modifier.height(14.dp))

        if (hasTrafficAccess) {
            val tx = palaces.values.sumOf { it.bytesTx }
            val rx = palaces.values.sumOf { it.bytesRx }
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                StatTile(
                    value = Metaverse.formatBytes(tx),
                    label = "Enviado\nhoy",
                    accent = P5Red,
                    modifier = Modifier.weight(1f),
                )
                StatTile(
                    value = Metaverse.formatBytes(rx),
                    label = "Recibido\nhoy",
                    accent = P5Cyan,
                    modifier = Modifier.weight(1f),
                )
            }
        } else {
            Box(
                Modifier
                    .fillMaxWidth()
                    .clip(rememberSlashShape(topEnd = 14.dp, bottomStart = 14.dp))
                    .background(P5Ink)
                    .border(2.dp, P5Yellow, rememberSlashShape(topEnd = 14.dp, bottomStart = 14.dp))
                    .clickable(onClick = actions.openTrafficAccess)
                    .padding(16.dp),
            ) {
                Column {
                    Text("FALTA UNA LLAVE", style = Ink.title, color = P5Yellow)
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Android guarda los bytes por app detrás del permiso de “Acceso al uso”. " +
                            "Toca aquí para concederlo y ver cuánto habla cada Palacio.",
                        style = Ink.body,
                        color = P5Bone,
                    )
                }
            }
        }

        if (pulse.droppedTcp > 0) {
            Spacer(Modifier.height(14.dp))
            Text(
                "${pulse.droppedTcp} intentos de DNS por TCP/DoT descartados. " +
                    "Si una app se queda sin red, apaga el modo agresivo.",
                style = Ink.caption,
                color = P5Bone,
            )
        }

        Spacer(Modifier.height(24.dp))

        Box(
            Modifier
                .clip(rememberSkewShape(lean = 8.dp))
                .border(2.dp, P5Coal, rememberSkewShape(lean = 8.dp))
                .clickable(onClick = actions.resetRun)
                .padding(horizontal = 18.dp, vertical = 10.dp),
        ) {
            Text("BORRAR ESTA INFILTRACIÓN", style = Ink.label, color = P5Bone)
        }
    }
}

@Composable
private fun ToggleRow(
    title: String,
    description: String,
    checked: Boolean,
    onToggle: () -> Unit,
    accent: Color = P5Red,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onToggle),
        verticalAlignment = Alignment.Top,
    ) {
        Column(Modifier.weight(1f)) {
            Text(title.uppercase(), style = Ink.title, color = if (checked) accent else P5White)
            Spacer(Modifier.height(4.dp))
            Text(description, style = Ink.body, color = P5Bone)
        }
        Spacer(Modifier.width(14.dp))
        // Interruptor con la estética del juego: rombo lleno o vacío.
        Box(
            Modifier
                .rotate(45f)
                .background(if (checked) accent else Color.Transparent)
                .border(2.dp, if (checked) accent else P5Coal)
                .padding(11.dp),
        )
    }
}

@Composable
private fun ThresholdRow(threshold: Int, actions: MetaversoActions) {
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("UMBRAL DE ROBO", style = Ink.label, color = P5Bone)
            Spacer(Modifier.width(10.dp))
            Text(threshold.toString(), style = Ink.numeral, color = P5Red)
        }
        Spacer(Modifier.height(4.dp))
        Text(
            "Se confisca todo lo que puntúe $threshold o más. Bajarlo bloquea más; " +
                "subirlo deja pasar analítica ligera.",
            style = Ink.body,
            color = P5Bone,
        )
        Spacer(Modifier.height(10.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            listOf(35 to "IMPLACABLE", 55 to "EQUILIBRADO", 75 to "PRUDENTE").forEach { (value, name) ->
                Box(
                    Modifier
                        .weight(1f)
                        .clip(rememberSkewShape(lean = 6.dp))
                        .background(if (threshold == value) P5Red else Color.Transparent)
                        .border(1.5.dp, if (threshold == value) P5Red else P5Coal, rememberSkewShape(lean = 6.dp))
                        .clickable { actions.setThreshold(value) }
                        .padding(vertical = 8.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(name, style = Ink.label, color = if (threshold == value) P5White else P5Bone)
                }
            }
        }
    }
}
