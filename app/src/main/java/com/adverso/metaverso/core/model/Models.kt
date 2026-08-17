package com.adverso.metaverso.core.model

/**
 * El vocabulario del Metaverso.
 *
 * Cada dominio con el que habla el teléfono es una **Sombra**; cada app que las
 * invoca es un **Palacio** gobernado por un deseo distorsionado.
 */
enum class ShadowKind(
    val display: String,
    val distortion: String,
    val blurb: String,
) {
    /** Ruido de infraestructura: CDNs, NTP, resolutores. Casi siempre inofensivo. */
    WANDERER("SOMBRA ERRANTE", "PEREZA", "Deambula sin intención. Infraestructura."),

    /** No la reconocemos. Ni buena ni mala: desconocida. */
    ANONYMOUS("SOMBRA ANÓNIMA", "DUDA", "Sin antecedentes en el registro."),

    /** Redes sociales y perfilado social. */
    SEDUCER("SOMBRA SEDUCTORA", "VANIDAD", "Se alimenta de tu imagen pública."),

    /** Publicidad y subastas de tu atención. */
    GREEDY("SOMBRA CODICIOSA", "AVARICIA", "Subasta tu atención al mejor postor."),

    /** Analítica, telemetría, huellas digitales. */
    WATCHER("SOMBRA VIGILANTE", "VIGILANCIA", "Registra cada cosa que haces."),

    /** Patrones de dominio generado, phishing, C2. */
    CORRUPT("SOMBRA CORRUPTA", "IRA", "Su nombre no fue hecho por humanos."),

    /** Volumen anómalo o fuga de datos a través del propio DNS. */
    DEVOURER("SOMBRA DEVORADORA", "GULA", "Usa el DNS como tubería para sacar datos."),
    ;

    val severity: Int
        get() = when (this) {
            WANDERER -> 8
            ANONYMOUS -> 26
            SEDUCER -> 42
            GREEDY -> 58
            WATCHER -> 64
            CORRUPT -> 86
            DEVOURER -> 92
        }
}

/** Nivel de alerta del Palacio, calcado del medidor de seguridad de Persona 5. */
enum class ThreatTier(val label: String, val threshold: Int) {
    CALMA("CALMA", 0),
    SOSPECHA("SOSPECHA", 25),
    ALERTA("ALERTA", 45),
    CAUTELA("CAUTELA", 65),
    EMERGENCIA("EMERGENCIA", 85),
    ;

    companion object {
        fun of(score: Int): ThreatTier = entries.last { score >= it.threshold }
    }
}

/**
 * Los Palacios de Persona 5, usados como rango del "tamaño" de lo que una app
 * esconde: cuanto más sucia su huella, más imponente su Palacio.
 */
enum class PalaceRank(val label: String, val threshold: Int, val letter: Char) {
    GUARIDA("GUARIDA", 0, 'E'),
    CASTILLO("CASTILLO", 20, 'D'),
    MUSEO("MUSEO", 38, 'C'),
    BANCO("BANCO", 52, 'B'),
    PIRAMIDE("PIRÁMIDE", 66, 'A'),
    CASINO("CASINO", 78, 'A'),
    CRUCERO("CRUCERO", 88, 'S'),
    ;

    companion object {
        fun of(score: Int): PalaceRank = entries.last { score >= it.threshold }
    }
}

/** Una consulta DNS observada: la unidad atómica de todo lo que ves en la app. */
data class ShadowEvent(
    val id: Long,
    val timestamp: Long,
    val domain: String,
    val queryType: String,
    val uid: Int,
    val packageName: String,
    val appLabel: String,
    val kind: ShadowKind,
    val score: Int,
    val codename: String,
    val category: String,
    val blocked: Boolean,
    val verdictReason: String,
    val resolvedIps: List<String> = emptyList(),
    val latencyMs: Int = -1,
)

/** Todo lo que sabemos acumulado sobre un dominio. */
data class ShadowAggregate(
    val domain: String,
    val kind: ShadowKind,
    val score: Int,
    val codename: String,
    val category: String,
    val reasons: List<String>,
    val encounters: Int,
    val blockedCount: Int,
    val firstSeen: Long,
    val lastSeen: Long,
    val uids: Set<Int>,
    val addresses: List<String>,
) {
    val tier: ThreatTier get() = ThreatTier.of(score)
}

/** Todo lo que sabemos acumulado sobre una app. */
data class PalaceAggregate(
    val uid: Int,
    val packageName: String,
    val label: String,
    val queries: Int,
    val blocked: Int,
    val domains: Set<String>,
    val dominantKind: ShadowKind,
    val worstScore: Int,
    val threatScore: Int,
    val lastSeen: Long,
    val bytesTx: Long = 0L,
    val bytesRx: Long = 0L,
) {
    val rank: PalaceRank get() = PalaceRank.of(threatScore)
    val tier: ThreatTier get() = ThreatTier.of(threatScore)
    val bytesTotal: Long get() = bytesTx + bytesRx
}

/** Estado global de la infiltración, lo que muestra el panel principal. */
data class MetaversePulse(
    val queries: Int = 0,
    val blocked: Int = 0,
    val shadows: Int = 0,
    val palaces: Int = 0,
    val corrupted: Int = 0,
    val alert: Int = 0,
    val lastDomain: String? = null,
    val droppedTcp: Int = 0,
) {
    val tier: ThreatTier get() = ThreatTier.of(alert)
    val blockRate: Float get() = if (queries == 0) 0f else blocked.toFloat() / queries
}
