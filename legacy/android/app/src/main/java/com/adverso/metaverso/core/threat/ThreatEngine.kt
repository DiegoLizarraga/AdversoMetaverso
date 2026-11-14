package com.adverso.metaverso.core.threat

import com.adverso.metaverso.core.model.ShadowKind
import kotlin.math.ln

/**
 * El Códice de Sombras: decide *qué* es un dominio y *cuánto* debe preocuparte.
 *
 * Dos capas. Primero el registro conocido (coincidencia por sufijo), que cubre
 * las redes de publicidad y analítica reales. Después la heurística, que es lo
 * que atrapa lo que ningún registro conoce todavía: nombres generados por
 * máquina, etiquetas gigantes que huelen a fuga por DNS, TLDs quemados.
 */
object ThreatEngine {

    class Verdict(
        val domain: String,
        val kind: ShadowKind,
        val score: Int,
        val category: String,
        val reasons: List<String>,
        val codename: String,
    )

    private class Rule(val suffix: String, val kind: ShadowKind, val category: String)

    private val registry: List<Rule> = listOf(
        // --- Publicidad y subastas de atención -------------------------------
        Rule("doubleclick.net", ShadowKind.GREEDY, "Publicidad"),
        Rule("googlesyndication.com", ShadowKind.GREEDY, "Publicidad"),
        Rule("googleadservices.com", ShadowKind.GREEDY, "Publicidad"),
        Rule("googletagservices.com", ShadowKind.GREEDY, "Publicidad"),
        Rule("adservice.google.com", ShadowKind.GREEDY, "Publicidad"),
        Rule("admob.com", ShadowKind.GREEDY, "Publicidad móvil"),
        Rule("applovin.com", ShadowKind.GREEDY, "Publicidad móvil"),
        Rule("unityads.unity3d.com", ShadowKind.GREEDY, "Publicidad en juegos"),
        Rule("ironsrc.com", ShadowKind.GREEDY, "Publicidad en juegos"),
        Rule("ironsource.com", ShadowKind.GREEDY, "Publicidad en juegos"),
        Rule("vungle.com", ShadowKind.GREEDY, "Publicidad en juegos"),
        Rule("chartboost.com", ShadowKind.GREEDY, "Publicidad en juegos"),
        Rule("adcolony.com", ShadowKind.GREEDY, "Publicidad en juegos"),
        Rule("tapjoy.com", ShadowKind.GREEDY, "Publicidad en juegos"),
        Rule("mopub.com", ShadowKind.GREEDY, "Publicidad móvil"),
        Rule("inmobi.com", ShadowKind.GREEDY, "Publicidad móvil"),
        Rule("smaato.net", ShadowKind.GREEDY, "Publicidad móvil"),
        Rule("startappservice.com", ShadowKind.GREEDY, "Publicidad móvil"),
        Rule("pubmatic.com", ShadowKind.GREEDY, "Subasta en tiempo real"),
        Rule("rubiconproject.com", ShadowKind.GREEDY, "Subasta en tiempo real"),
        Rule("openx.net", ShadowKind.GREEDY, "Subasta en tiempo real"),
        Rule("adsrvr.org", ShadowKind.GREEDY, "Subasta en tiempo real"),
        Rule("casalemedia.com", ShadowKind.GREEDY, "Subasta en tiempo real"),
        Rule("criteo.com", ShadowKind.GREEDY, "Retargeting"),
        Rule("criteo.net", ShadowKind.GREEDY, "Retargeting"),
        Rule("taboola.com", ShadowKind.GREEDY, "Contenido patrocinado"),
        Rule("outbrain.com", ShadowKind.GREEDY, "Contenido patrocinado"),
        Rule("moatads.com", ShadowKind.GREEDY, "Medición publicitaria"),
        Rule("adsafeprotected.com", ShadowKind.GREEDY, "Medición publicitaria"),

        // --- Analítica, telemetría, huella digital ---------------------------
        Rule("google-analytics.com", ShadowKind.WATCHER, "Analítica"),
        Rule("googletagmanager.com", ShadowKind.WATCHER, "Analítica"),
        Rule("app-measurement.com", ShadowKind.WATCHER, "Analítica Firebase"),
        Rule("firebase-settings.crashlytics.com", ShadowKind.WATCHER, "Telemetría de fallos"),
        Rule("crashlytics.com", ShadowKind.WATCHER, "Telemetría de fallos"),
        Rule("appsflyer.com", ShadowKind.WATCHER, "Atribución de instalaciones"),
        Rule("adjust.com", ShadowKind.WATCHER, "Atribución de instalaciones"),
        Rule("adjust.io", ShadowKind.WATCHER, "Atribución de instalaciones"),
        Rule("branch.io", ShadowKind.WATCHER, "Atribución de instalaciones"),
        Rule("kochava.com", ShadowKind.WATCHER, "Atribución de instalaciones"),
        Rule("singular.net", ShadowKind.WATCHER, "Atribución de instalaciones"),
        Rule("amplitude.com", ShadowKind.WATCHER, "Producto/analítica"),
        Rule("mixpanel.com", ShadowKind.WATCHER, "Producto/analítica"),
        Rule("segment.io", ShadowKind.WATCHER, "Producto/analítica"),
        Rule("segment.com", ShadowKind.WATCHER, "Producto/analítica"),
        Rule("heapanalytics.com", ShadowKind.WATCHER, "Producto/analítica"),
        Rule("braze.com", ShadowKind.WATCHER, "Marketing"),
        Rule("clevertap.com", ShadowKind.WATCHER, "Marketing"),
        Rule("onesignal.com", ShadowKind.WATCHER, "Notificaciones"),
        Rule("bugsnag.com", ShadowKind.WATCHER, "Telemetría de fallos"),
        Rule("sentry.io", ShadowKind.WATCHER, "Telemetría de fallos"),
        Rule("newrelic.com", ShadowKind.WATCHER, "Monitorización"),
        Rule("datadoghq.com", ShadowKind.WATCHER, "Monitorización"),
        Rule("hotjar.com", ShadowKind.WATCHER, "Grabación de sesión"),
        Rule("fullstory.com", ShadowKind.WATCHER, "Grabación de sesión"),
        Rule("clarity.ms", ShadowKind.WATCHER, "Grabación de sesión"),
        Rule("scorecardresearch.com", ShadowKind.WATCHER, "Panel de medición"),
        Rule("quantserve.com", ShadowKind.WATCHER, "Panel de medición"),
        Rule("demdex.net", ShadowKind.WATCHER, "Perfilado Adobe"),
        Rule("omtrdc.net", ShadowKind.WATCHER, "Perfilado Adobe"),
        Rule("bluekai.com", ShadowKind.WATCHER, "Broker de datos"),
        Rule("adobedtm.com", ShadowKind.WATCHER, "Etiquetado Adobe"),
        Rule("mc.yandex.ru", ShadowKind.WATCHER, "Analítica Yandex"),
        Rule("appmetrica.yandex.net", ShadowKind.WATCHER, "Analítica Yandex"),
        Rule("analytics.tiktok.com", ShadowKind.WATCHER, "Analítica TikTok"),
        Rule("log.byteoversea.com", ShadowKind.WATCHER, "Telemetría ByteDance"),
        Rule("pangle.io", ShadowKind.WATCHER, "Publicidad ByteDance"),
        Rule("umeng.com", ShadowKind.WATCHER, "Analítica"),
        Rule("flurry.com", ShadowKind.WATCHER, "Analítica"),

        // --- Perfilado social ------------------------------------------------
        Rule("graph.facebook.com", ShadowKind.SEDUCER, "Grafo social"),
        Rule("connect.facebook.net", ShadowKind.SEDUCER, "Grafo social"),
        Rule("an.facebook.com", ShadowKind.GREEDY, "Audience Network"),
        Rule("facebook.com", ShadowKind.SEDUCER, "Red social"),
        Rule("instagram.com", ShadowKind.SEDUCER, "Red social"),
        Rule("tiktokv.com", ShadowKind.SEDUCER, "Red social"),
        Rule("x.com", ShadowKind.SEDUCER, "Red social"),
        Rule("twitter.com", ShadowKind.SEDUCER, "Red social"),
        Rule("linkedin.com", ShadowKind.SEDUCER, "Red social"),
        Rule("snapchat.com", ShadowKind.SEDUCER, "Red social"),

        // --- Infraestructura: ruido, no amenaza ------------------------------
        Rule("gstatic.com", ShadowKind.WANDERER, "CDN"),
        Rule("googleapis.com", ShadowKind.WANDERER, "API de plataforma"),
        Rule("akamaiedge.net", ShadowKind.WANDERER, "CDN"),
        Rule("akamaized.net", ShadowKind.WANDERER, "CDN"),
        Rule("cloudfront.net", ShadowKind.WANDERER, "CDN"),
        Rule("fastly.net", ShadowKind.WANDERER, "CDN"),
        Rule("cloudflare.com", ShadowKind.WANDERER, "CDN"),
        Rule("cloudflare-dns.com", ShadowKind.WANDERER, "Resolutor DNS"),
        Rule("amazonaws.com", ShadowKind.WANDERER, "Nube"),
        Rule("windows.net", ShadowKind.WANDERER, "Nube"),
        Rule("azureedge.net", ShadowKind.WANDERER, "CDN"),
        Rule("ntp.org", ShadowKind.WANDERER, "Hora de red"),
        Rule("in-addr.arpa", ShadowKind.WANDERER, "DNS inverso"),
        Rule("ip6.arpa", ShadowKind.WANDERER, "DNS inverso"),
        Rule("local", ShadowKind.WANDERER, "Red local"),
        Rule("localdomain", ShadowKind.WANDERER, "Red local"),
    )

    /** Palabras que delatan la intención cuando el registro no conoce el dominio. */
    private val hints: List<Triple<String, ShadowKind, String>> = listOf(
        Triple("telemetry", ShadowKind.WATCHER, "Telemetría"),
        Triple("analytics", ShadowKind.WATCHER, "Analítica"),
        Triple("analytic", ShadowKind.WATCHER, "Analítica"),
        Triple("metrics", ShadowKind.WATCHER, "Métricas"),
        Triple("metric", ShadowKind.WATCHER, "Métricas"),
        Triple("tracking", ShadowKind.WATCHER, "Rastreo"),
        Triple("tracker", ShadowKind.WATCHER, "Rastreo"),
        Triple("beacon", ShadowKind.WATCHER, "Baliza"),
        Triple("pixel", ShadowKind.WATCHER, "Píxel de rastreo"),
        Triple("collect", ShadowKind.WATCHER, "Recolección"),
        Triple("logging", ShadowKind.WATCHER, "Registro remoto"),
        Triple("crashreport", ShadowKind.WATCHER, "Telemetría de fallos"),
        Triple("adserv", ShadowKind.GREEDY, "Publicidad"),
        Triple("adsdk", ShadowKind.GREEDY, "Publicidad"),
        Triple("banner", ShadowKind.GREEDY, "Publicidad"),
        Triple("popads", ShadowKind.GREEDY, "Publicidad"),
        Triple("clickserv", ShadowKind.GREEDY, "Publicidad"),
    )

    private val riskyTlds = setOf(
        "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "work", "rest",
        "zip", "mov", "surf", "monster", "cyou", "quest", "sbs",
    )

    /** Nombres de Sombra para que cada dominio tenga su propia identidad. */
    private val codenames = listOf(
        "PIXIE", "JACK FROST", "SILKY", "INCUBUS", "BERITH", "ELIGOR", "ANZU",
        "MOKOI", "ONMORAKI", "HUA PO", "SANDMAN", "KELPIE", "REGENT", "ANDRAS",
        "NAGA", "RAKSHASA", "BICORN", "KING FROST", "BELPHEGOR", "ARSENE",
        "SUCCUBUS", "OBERON", "TITANIA", "SETANTA", "MAKAMI", "NEKOMATA",
        "SHIISAA", "ORTHRUS", "MITHRAS", "YAKSINI", "LAMIA", "MOTHMAN",
        "QUEEN MAB", "KUSHI MITAMA", "APSARAS", "AGATHION", "KODAMA",
        "MATADOR", "ARCHANGEL", "PRINCIPALITY", "VALKYRIE", "LEANAN SIDHE",
    )

    fun evaluate(rawDomain: String): Verdict {
        val domain = rawDomain.trim().trimEnd('.').lowercase()
        if (domain.isEmpty()) {
            return Verdict("(vacío)", ShadowKind.ANONYMOUS, 20, "Consulta vacía", listOf("Consulta sin nombre"), "NIEBLA")
        }

        val reasons = ArrayList<String>(4)
        var kind = ShadowKind.ANONYMOUS
        var category = "Sin clasificar"
        var score: Int
        var escalated = false

        fun escalate(candidate: ShadowKind) {
            if (candidate.severity > kind.severity) {
                kind = candidate
                escalated = true
            }
        }

        val rule = registry.firstOrNull { domain == it.suffix || domain.endsWith(".${it.suffix}") }
        if (rule != null) {
            kind = rule.kind
            category = rule.category
            score = kind.severity
            reasons += "Registrada en el códice: ${rule.suffix} · ${rule.category}"
        } else {
            val hint = hints.firstOrNull { domain.contains(it.first) }
            if (hint != null) {
                kind = hint.second
                category = hint.third
                // Sospecha por nombre, no certeza: pesa algo menos que el registro.
                score = kind.severity - 8
                reasons += "Nombre delator: “${hint.first}”"
            } else {
                score = kind.severity
            }
        }

        val labels = domain.split('.')
        val longest = labels.maxByOrNull { it.length }.orEmpty()

        // Los CDN y las nubes generan nombres de host aleatorios por diseño
        // (`d2k7x9.cloudfront.net`). Si el registro ya identificó el dominio como
        // infraestructura, las señales de "nombre raro" se anotan pero no
        // castigan: si no, medio internet saldría como Sombra Corrupta.
        val knownInfrastructure = rule != null && rule.kind == ShadowKind.WANDERER

        if (labels.size >= 6) {
            score += 6
            reasons += "Cadena de ${labels.size} subdominios"
        }

        val entropy = entropyOf(longest)
        if (longest.length >= 12 && entropy > 3.55) {
            if (knownInfrastructure) {
                reasons += "Etiqueta aleatoria, esperable en un CDN"
            } else {
                score += 18
                escalate(ShadowKind.CORRUPT)
                reasons += "Entropía ${format(entropy)} en “$longest”: nombre generado por máquina"
                if (category == "Sin clasificar") category = "Dominio generado (DGA)"
            }
        }

        if (longest.length >= 34) {
            if (knownInfrastructure) {
                score += 4
                reasons += "Etiqueta de ${longest.length} caracteres en infraestructura conocida"
            } else {
                score += 24
                escalate(ShadowKind.DEVOURER)
                reasons += "Etiqueta de ${longest.length} caracteres: patrón de fuga de datos por DNS"
                category = "Túnel DNS"
            }
        }

        val tld = labels.lastOrNull().orEmpty()
        if (tld in riskyTlds) {
            score += 16
            reasons += "TLD de alto riesgo: .$tld"
        }

        if (domain.contains("xn--")) {
            score += 12
            reasons += "Punycode: posible dominio homógrafo"
        }

        // La puntuación es lo que decide si se bloquea, así que tiene que seguir
        // a la reclasificación: no sirve etiquetar algo de Sombra Corrupta y
        // dejarlo pasar porque arrancó como anónimo.
        if (escalated) score = maxOf(score, kind.severity - 14)

        if (reasons.isEmpty()) reasons += "Sin antecedentes. Sombra anónima."

        return Verdict(
            domain = domain,
            kind = kind,
            score = score.coerceIn(0, 100),
            category = category,
            reasons = reasons,
            codename = codenameFor(domain),
        )
    }

    /** Nombre estable por dominio: la misma Sombra siempre se llama igual. */
    private fun codenameFor(domain: String): String {
        var hash = 0
        for (c in domain) hash = hash * 31 + c.code
        val index = ((hash % codenames.size) + codenames.size) % codenames.size
        return codenames[index]
    }

    /** Entropía de Shannon: alta en cadenas aleatorias, baja en palabras reales. */
    private fun entropyOf(value: String): Double {
        if (value.isEmpty()) return 0.0
        val counts = HashMap<Char, Int>(value.length)
        for (c in value) counts[c] = (counts[c] ?: 0) + 1
        var entropy = 0.0
        for (count in counts.values) {
            val p = count.toDouble() / value.length
            entropy -= p * (ln(p) / LN2)
        }
        return entropy
    }

    private const val LN2 = 0.6931471805599453

    private fun format(value: Double): String {
        val rounded = (value * 100).toInt()
        return "${rounded / 100}.${(rounded % 100).toString().padStart(2, '0')}"
    }
}
