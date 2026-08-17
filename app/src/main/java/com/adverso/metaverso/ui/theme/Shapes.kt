package com.adverso.metaverso.ui.theme

import androidx.compose.foundation.shape.GenericShape
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import kotlin.random.Random

/**
 * Las siluetas de Persona 5: nada es un rectángulo. Todo está cortado en
 * diagonal, rasgado como papel o inclinado como si alguien lo hubiera pegado
 * a la carrera.
 */

/** Rectángulo con esquinas cortadas en diagonal, la forma base del juego. */
@Composable
fun rememberSlashShape(
    topStart: Dp = 0.dp,
    topEnd: Dp = 18.dp,
    bottomEnd: Dp = 0.dp,
    bottomStart: Dp = 18.dp,
): Shape {
    val density = LocalDensity.current
    return remember(topStart, topEnd, bottomEnd, bottomStart, density) {
        val ts = with(density) { topStart.toPx() }
        val te = with(density) { topEnd.toPx() }
        val be = with(density) { bottomEnd.toPx() }
        val bs = with(density) { bottomStart.toPx() }
        GenericShape { size, _ ->
            moveTo(ts, 0f)
            lineTo(size.width - te, 0f)
            lineTo(size.width, te)
            lineTo(size.width, size.height - be)
            lineTo(size.width - be, size.height)
            lineTo(bs, size.height)
            lineTo(0f, size.height - bs)
            lineTo(0f, ts)
            close()
        }
    }
}

/**
 * Papel rasgado. El borde se genera con un [Random] sembrado, así que la misma
 * tarjeta siempre se rasga igual y no "tiembla" al recomponer.
 */
@Composable
fun rememberTornShape(seed: Int, bite: Dp = 7.dp, teeth: Int = 9): Shape {
    val density = LocalDensity.current
    return remember(seed, bite, teeth, density) {
        val amplitude = with(density) { bite.toPx() }
        GenericShape { size, _ ->
            val random = Random(seed)
            fun jitter() = (random.nextFloat() - 0.35f) * amplitude

            moveTo(0f, amplitude)
            for (i in 1..teeth) {
                val x = size.width * i / teeth
                lineTo(x, amplitude + jitter())
            }
            lineTo(size.width, size.height - amplitude)
            for (i in teeth - 1 downTo 0) {
                val x = size.width * i / teeth
                lineTo(x, size.height - amplitude + jitter())
            }
            lineTo(0f, amplitude)
            close()
        }
    }
}

/** Paralelogramo inclinado: pestañas, insignias, etiquetas. */
@Composable
fun rememberSkewShape(lean: Dp = 10.dp, toRight: Boolean = true): Shape {
    val density = LocalDensity.current
    return remember(lean, toRight, density) {
        val offset = with(density) { lean.toPx() }
        GenericShape { size, _ ->
            if (toRight) {
                moveTo(offset, 0f)
                lineTo(size.width, 0f)
                lineTo(size.width - offset, size.height)
                lineTo(0f, size.height)
            } else {
                moveTo(0f, 0f)
                lineTo(size.width - offset, 0f)
                lineTo(size.width, size.height)
                lineTo(offset, size.height)
            }
            close()
        }
    }
}

/** Estrella de choque para los momentos de "¡ALERTA!". */
@Composable
fun rememberBurstShape(points: Int = 14, innerRatio: Float = 0.74f): Shape {
    return remember(points, innerRatio) {
        GenericShape { size, _ ->
            val cx = size.width / 2f
            val cy = size.height / 2f
            val outerX = size.width / 2f
            val outerY = size.height / 2f
            val total = points * 2
            for (i in 0 until total) {
                val angle = Math.PI * 2 * i / total - Math.PI / 2
                val ratio = if (i % 2 == 0) 1f else innerRatio
                val x = cx + (outerX * ratio * kotlin.math.cos(angle)).toFloat()
                val y = cy + (outerY * ratio * kotlin.math.sin(angle)).toFloat()
                if (i == 0) moveTo(x, y) else lineTo(x, y)
            }
            close()
        }
    }
}
