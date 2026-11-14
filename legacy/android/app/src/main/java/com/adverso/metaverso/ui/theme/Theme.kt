package com.adverso.metaverso.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.adverso.metaverso.core.model.ShadowKind
import com.adverso.metaverso.core.model.ThreatTier

// La paleta de Persona 5: rojo sangre, negro tinta, papel crema. Nada más.
val P5Red = Color(0xFFE60012)
val P5RedDeep = Color(0xFFA3000C)
val P5RedGlow = Color(0xFFFF2D3F)
val P5Black = Color(0xFF080808)
val P5Ink = Color(0xFF151515)
val P5Coal = Color(0xFF232323)
val P5White = Color(0xFFF6F2E9)
val P5Bone = Color(0xFFCFC8B8)
val P5Yellow = Color(0xFFFFD400)
val P5Cyan = Color(0xFF25E0D8)

/**
 * Tipografía del Metaverso: negrita extrema, cursiva y versalitas.
 *
 * Persona 5 usa fuentes condensadas propias; aquí van las de sistema con el peso
 * al máximo. Cambiar [FontFamily.SansSerif] por una fuente condensada real en
 * `res/font` es la mejora visual más grande y más barata que le queda a la app.
 */
object Ink {
    private val family = FontFamily.SansSerif

    val hero = TextStyle(
        fontFamily = family,
        fontWeight = FontWeight.Black,
        fontStyle = FontStyle.Italic,
        fontSize = 46.sp,
        lineHeight = 46.sp,
        letterSpacing = (-1.5).sp,
    )
    val display = TextStyle(
        fontFamily = family,
        fontWeight = FontWeight.Black,
        fontStyle = FontStyle.Italic,
        fontSize = 30.sp,
        lineHeight = 32.sp,
        letterSpacing = (-0.8).sp,
    )
    val title = TextStyle(
        fontFamily = family,
        fontWeight = FontWeight.Black,
        fontStyle = FontStyle.Italic,
        fontSize = 19.sp,
        lineHeight = 22.sp,
        letterSpacing = (-0.3).sp,
    )
    val label = TextStyle(
        fontFamily = family,
        fontWeight = FontWeight.Black,
        fontSize = 11.sp,
        lineHeight = 13.sp,
        letterSpacing = 1.4.sp,
    )
    val body = TextStyle(
        fontFamily = family,
        fontWeight = FontWeight.Medium,
        fontSize = 13.sp,
        lineHeight = 18.sp,
    )
    val caption = TextStyle(
        fontFamily = family,
        fontWeight = FontWeight.SemiBold,
        fontSize = 11.sp,
        lineHeight = 14.sp,
        letterSpacing = 0.4.sp,
    )
    val mono = TextStyle(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Medium,
        fontSize = 12.sp,
        lineHeight = 16.sp,
    )
    val numeral = TextStyle(
        fontFamily = family,
        fontWeight = FontWeight.Black,
        fontStyle = FontStyle.Italic,
        fontSize = 26.sp,
        lineHeight = 26.sp,
        letterSpacing = (-1).sp,
    )
}

fun ShadowKind.tint(): Color = when (this) {
    ShadowKind.WANDERER -> P5Bone
    ShadowKind.ANONYMOUS -> P5Cyan
    ShadowKind.SEDUCER -> Color(0xFFFF7BC1)
    ShadowKind.GREEDY -> P5Yellow
    ShadowKind.WATCHER -> Color(0xFFFF8A2B)
    ShadowKind.CORRUPT -> P5Red
    ShadowKind.DEVOURER -> P5RedGlow
}

fun ThreatTier.tint(): Color = when (this) {
    ThreatTier.CALMA -> P5Cyan
    ThreatTier.SOSPECHA -> P5Bone
    ThreatTier.ALERTA -> P5Yellow
    ThreatTier.CAUTELA -> Color(0xFFFF8A2B)
    ThreatTier.EMERGENCIA -> P5Red
}

@Composable
fun MetaversoTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = P5Red,
            onPrimary = P5White,
            secondary = P5Yellow,
            onSecondary = P5Black,
            background = P5Black,
            onBackground = P5White,
            surface = P5Ink,
            onSurface = P5White,
            surfaceVariant = P5Coal,
            onSurfaceVariant = P5Bone,
            error = P5RedGlow,
        ),
        content = content,
    )
}
