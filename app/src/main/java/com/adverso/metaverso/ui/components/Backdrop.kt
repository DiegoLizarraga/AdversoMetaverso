package com.adverso.metaverso.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.graphicsLayer
import com.adverso.metaverso.ui.theme.P5Black
import com.adverso.metaverso.ui.theme.P5Red
import com.adverso.metaverso.ui.theme.P5RedDeep
import com.adverso.metaverso.ui.theme.P5White

/** Separación horizontal entre franjas, en píxeles. */
private const val STRIPE_PERIOD = 64f

/** Cada tercera franja es gruesa, así que la trama se repite cada tres. */
private const val STRIPE_CYCLE = 3

/** Desplazamiento horizontal por píxel de altura: la inclinación del patrón. */
private const val STRIPE_SKEW = 0.42f

/**
 * El fondo del Metaverso: franjas rojas inclinadas que se arrastran despacio y
 * se aceleran con el nivel de alerta.
 *
 * **Sobre el rendimiento.** La versión obvia —dibujar las franjas una a una en
 * cada fotograma— hacía que el primer frame tardase segundos y Android acabase
 * declarando ANR: son decenas de líneas de pantalla completa con alfa, o sea
 * varias capas de sobredibujado por fotograma. En su lugar la trama se dibuja
 * **una sola vez** como un único [Path] y la animación es solo un
 * `translationX` sobre la capa ya rasterizada. Como el patrón es periódico,
 * desplazarlo un ciclo entero lo deja exactamente igual y el bucle es continuo.
 *
 * [intensity] va de 0 (calma) a 1 (emergencia): controla velocidad, opacidad y
 * si aparecen las esquirlas de choque.
 */
@Composable
fun MetaverseBackdrop(
    intensity: Float,
    modifier: Modifier = Modifier,
) {
    val clamped = intensity.coerceIn(0f, 1f)
    val transition = rememberInfiniteTransition(label = "backdrop")

    val drift by transition.animateFloat(
        initialValue = 0f,
        targetValue = 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = (16_000 - 9_000 * clamped).toInt(), easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "drift",
    )
    val breathe by transition.animateFloat(
        initialValue = 0.9f,
        targetValue = 1.12f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = (2_800 - 1_500 * clamped).toInt(), easing = LinearEasing),
            repeatMode = RepeatMode.Reverse,
        ),
        label = "breathe",
    )

    Box(modifier.background(P5Black)) {
        Canvas(
            Modifier
                .fillMaxSize()
                .graphicsLayer {
                    // Solo propiedades de capa: no obliga a redibujar la trama.
                    translationX = drift * STRIPE_PERIOD * STRIPE_CYCLE
                    alpha = 0.42f + 0.38f * clamped
                    clip = false
                },
        ) {
            val skew = size.height * STRIPE_SKEW
            val thick = Path()
            val thin = Path()
            // El patrón se extiende más allá de la pantalla para que el
            // desplazamiento no deje huecos por los bordes.
            var x = -skew - STRIPE_PERIOD * STRIPE_CYCLE * 2
            var index = 0
            while (x < size.width + STRIPE_PERIOD * STRIPE_CYCLE) {
                val heavy = index % STRIPE_CYCLE == 0
                val width = if (heavy) STRIPE_PERIOD * 0.40f else STRIPE_PERIOD * 0.12f
                val target = if (heavy) thick else thin
                target.moveTo(x + skew, 0f)
                target.lineTo(x + skew + width, 0f)
                target.lineTo(x + width, size.height)
                target.lineTo(x, size.height)
                target.close()
                x += STRIPE_PERIOD
                index++
            }
            drawPath(thick, P5RedDeep)
            drawPath(thin, P5Red)
        }

        // Esquirla de choque: aparece cuando el Palacio ya está nervioso.
        if (clamped > 0.35f) {
            Canvas(
                Modifier
                    .fillMaxSize()
                    .graphicsLayer {
                        alpha = 0.22f * clamped
                        scaleX = breathe
                        scaleY = breathe
                    },
            ) {
                val scale = size.minDimension * 0.18f
                val cx = size.width * 0.82f
                val cy = size.height * 0.15f
                val shard = Path().apply {
                    moveTo(cx, cy - scale)
                    lineTo(cx + scale * 0.34f, cy - scale * 0.2f)
                    lineTo(cx + scale, cy)
                    lineTo(cx + scale * 0.28f, cy + scale * 0.3f)
                    lineTo(cx, cy + scale)
                    lineTo(cx - scale * 0.3f, cy + scale * 0.24f)
                    lineTo(cx - scale, cy)
                    lineTo(cx - scale * 0.32f, cy - scale * 0.26f)
                    close()
                }
                drawPath(shard, P5Red)
                drawPath(shard, P5White.copy(alpha = 0.35f), style = androidx.compose.ui.graphics.drawscope.Stroke(width = 2f))
            }
        }
    }
}
