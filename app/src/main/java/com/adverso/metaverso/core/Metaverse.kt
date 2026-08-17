package com.adverso.metaverso.core

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Process
import com.adverso.metaverso.core.model.MetaversePulse
import com.adverso.metaverso.core.model.PalaceAggregate
import com.adverso.metaverso.core.model.ShadowAggregate
import com.adverso.metaverso.core.model.ShadowEvent
import com.adverso.metaverso.core.model.ShadowKind
import com.adverso.metaverso.core.threat.ThreatEngine
import java.util.Calendar
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * El estado del Metaverso, compartido entre el servicio de VPN y la interfaz.
 *
 * El túnel escribe aquí desde su propio hilo a mucha velocidad, así que los
 * agregados viven en mapas mutables bajo cerrojo y se publican como instantáneas
 * inmutables cada [FLUSH_MS]. Así la UI recompone a un ritmo humano por muchas
 * consultas DNS que pasen por debajo.
 */
object Metaverse {

    private const val MAX_EVENTS = 400
    private const val FLUSH_MS = 250L

    private lateinit var appContext: Context
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val sequence = AtomicLong(0)

    lateinit var settings: NavSettings
        private set

    private val lock = Any()
    private val shadowStore = HashMap<String, ShadowAggregate>()
    private val palaceStore = HashMap<Int, PalaceAggregate>()
    private val eventRing = ArrayDeque<ShadowEvent>()
    private val verdictCache = ConcurrentHashMap<String, ThreatEngine.Verdict>()
    private val identityCache = ConcurrentHashMap<Int, Identity>()

    @Volatile private var dirty = false
    @Volatile private var totalQueries = 0
    @Volatile private var totalBlocked = 0
    @Volatile private var droppedTcp = 0

    private val _navigatorActive = MutableStateFlow(false)
    val navigatorActive: StateFlow<Boolean> = _navigatorActive.asStateFlow()

    private val _events = MutableStateFlow<List<ShadowEvent>>(emptyList())
    val events: StateFlow<List<ShadowEvent>> = _events.asStateFlow()

    private val _shadows = MutableStateFlow<Map<String, ShadowAggregate>>(emptyMap())
    val shadows: StateFlow<Map<String, ShadowAggregate>> = _shadows.asStateFlow()

    private val _palaces = MutableStateFlow<Map<Int, PalaceAggregate>>(emptyMap())
    val palaces: StateFlow<Map<Int, PalaceAggregate>> = _palaces.asStateFlow()

    private val _pulse = MutableStateFlow(MetaversePulse())
    val pulse: StateFlow<MetaversePulse> = _pulse.asStateFlow()

    private val _notice = MutableStateFlow<String?>(null)
    /** Mensaje efímero para la UI (fallos del túnel, avisos de configuración). */
    val notice: StateFlow<String?> = _notice.asStateFlow()

    private val _sessionStart = MutableStateFlow(0L)
    val sessionStart: StateFlow<Long> = _sessionStart.asStateFlow()

    class Identity(val packageName: String, val label: String)

    class Decision(val block: Boolean, val reason: String)

    fun install(context: Context) {
        appContext = context.applicationContext
        settings = NavSettings.from(appContext)
        scope.launch {
            while (true) {
                delay(FLUSH_MS)
                if (dirty) flush()
            }
        }
    }

    // ---------------------------------------------------------------- captura

    /** Veredicto memorizado: el mismo dominio se consulta cientos de veces. */
    fun evaluate(domain: String): ThreatEngine.Verdict =
        verdictCache.getOrPut(domain.lowercase()) { ThreatEngine.evaluate(domain) }

    fun decide(verdict: ThreatEngine.Verdict): Decision {
        if (settings.isPacted(verdict.domain)) return Decision(false, "Pacto sellado")
        if (settings.isStolen(verdict.domain)) return Decision(true, "Corazón robado a mano")
        if (!settings.blockingEnabled) return Decision(false, "Solo reconocimiento")
        val block = verdict.kind != ShadowKind.WANDERER && verdict.score >= settings.threshold
        return Decision(block, if (block) "Tesoro confiscado" else "Bajo vigilancia")
    }

    fun record(
        domain: String,
        queryType: String,
        uid: Int,
        verdict: ThreatEngine.Verdict,
        blocked: Boolean,
        reason: String,
        addresses: List<String> = emptyList(),
        latencyMs: Int = -1,
    ) {
        val identity = identify(uid)
        val now = System.currentTimeMillis()
        val event = ShadowEvent(
            id = sequence.incrementAndGet(),
            timestamp = now,
            domain = verdict.domain,
            queryType = queryType,
            uid = uid,
            packageName = identity.packageName,
            appLabel = identity.label,
            kind = verdict.kind,
            score = verdict.score,
            codename = verdict.codename,
            category = verdict.category,
            blocked = blocked,
            verdictReason = reason,
            resolvedIps = addresses,
            latencyMs = latencyMs,
        )

        synchronized(lock) {
            eventRing.addLast(event)
            while (eventRing.size > MAX_EVENTS) eventRing.removeFirst()

            val shadow = shadowStore[verdict.domain]
            shadowStore[verdict.domain] = if (shadow == null) {
                ShadowAggregate(
                    domain = verdict.domain,
                    kind = verdict.kind,
                    score = verdict.score,
                    codename = verdict.codename,
                    category = verdict.category,
                    reasons = verdict.reasons,
                    encounters = 1,
                    blockedCount = if (blocked) 1 else 0,
                    firstSeen = now,
                    lastSeen = now,
                    uids = setOf(uid),
                    addresses = addresses.take(6),
                )
            } else {
                shadow.copy(
                    encounters = shadow.encounters + 1,
                    blockedCount = shadow.blockedCount + if (blocked) 1 else 0,
                    lastSeen = now,
                    uids = shadow.uids + uid,
                    addresses = (shadow.addresses + addresses).distinct().take(6),
                )
            }

            val palace = palaceStore[uid]
            val domains = (palace?.domains ?: emptySet()) + verdict.domain
            val worst = maxOf(palace?.worstScore ?: 0, verdict.score)
            val dominant = when {
                palace == null -> verdict.kind
                verdict.kind.severity > palace.dominantKind.severity -> verdict.kind
                else -> palace.dominantKind
            }
            palaceStore[uid] = PalaceAggregate(
                uid = uid,
                packageName = identity.packageName,
                label = identity.label,
                queries = (palace?.queries ?: 0) + 1,
                blocked = (palace?.blocked ?: 0) + if (blocked) 1 else 0,
                domains = domains,
                dominantKind = dominant,
                worstScore = worst,
                threatScore = palaceScore(worst, domains.size),
                lastSeen = now,
                bytesTx = palace?.bytesTx ?: 0L,
                bytesRx = palace?.bytesRx ?: 0L,
            )

            totalQueries++
            if (blocked) totalBlocked++
        }
        dirty = true
    }

    /**
     * Cuánto vale el Palacio de una app: lo peor que hace pesa más que el
     * promedio, pero la cantidad de Sombras distintas también cuenta — una app
     * que habla con treinta rastreadores tiene un problema estructural.
     */
    private fun palaceScore(worst: Int, domainCount: Int): Int {
        val breadth = when {
            domainCount >= 30 -> 18
            domainCount >= 15 -> 12
            domainCount >= 7 -> 7
            domainCount >= 3 -> 3
            else -> 0
        }
        return (worst * 0.82 + breadth).toInt().coerceIn(0, 100)
    }

    fun onTcpDropped() {
        droppedTcp++
        dirty = true
    }

    fun onNavigatorActive(active: Boolean) {
        _navigatorActive.value = active
        if (active && _sessionStart.value == 0L) _sessionStart.value = System.currentTimeMillis()
    }

    fun notice(message: String?) {
        _notice.value = message
    }

    fun clearRun() {
        synchronized(lock) {
            shadowStore.clear()
            palaceStore.clear()
            eventRing.clear()
            totalQueries = 0
            totalBlocked = 0
            droppedTcp = 0
        }
        _sessionStart.value = if (_navigatorActive.value) System.currentTimeMillis() else 0L
        flush()
    }

    /** Fusiona el consumo real de bytes por app medido por el sistema. */
    fun mergeTraffic(traffic: Map<Int, LongArray>) {
        if (traffic.isEmpty()) return
        synchronized(lock) {
            for ((uid, bytes) in traffic) {
                val identity = identify(uid)
                val existing = palaceStore[uid]
                palaceStore[uid] = existing?.copy(bytesTx = bytes[0], bytesRx = bytes[1])
                    ?: PalaceAggregate(
                        uid = uid,
                        packageName = identity.packageName,
                        label = identity.label,
                        queries = 0,
                        blocked = 0,
                        domains = emptySet(),
                        dominantKind = ShadowKind.ANONYMOUS,
                        worstScore = 0,
                        threatScore = 0,
                        lastSeen = 0L,
                        bytesTx = bytes[0],
                        bytesRx = bytes[1],
                    )
            }
        }
        flush()
    }

    private fun flush() {
        val shadowSnapshot: Map<String, ShadowAggregate>
        val palaceSnapshot: Map<Int, PalaceAggregate>
        val eventSnapshot: List<ShadowEvent>
        synchronized(lock) {
            dirty = false
            shadowSnapshot = HashMap(shadowStore)
            palaceSnapshot = HashMap(palaceStore)
            eventSnapshot = eventRing.toList()
        }
        _shadows.value = shadowSnapshot
        _palaces.value = palaceSnapshot
        _events.value = eventSnapshot

        // El nivel de alerta mezcla lo reciente con lo estructural: un pico de
        // consultas sucias lo sube rápido, y las Sombras corruptas lo sostienen.
        val recent = eventSnapshot.takeLast(60)
        val average = if (recent.isEmpty()) 0.0 else recent.sumOf { it.score }.toDouble() / recent.size
        val corrupted = shadowSnapshot.values.count {
            it.kind == ShadowKind.CORRUPT || it.kind == ShadowKind.DEVOURER
        }
        val alert = (average * 0.72 + (corrupted * 9).coerceAtMost(28)).toInt().coerceIn(0, 100)

        _pulse.value = MetaversePulse(
            queries = totalQueries,
            blocked = totalBlocked,
            shadows = shadowSnapshot.size,
            palaces = palaceSnapshot.count { it.value.queries > 0 },
            corrupted = corrupted,
            alert = alert,
            lastDomain = eventSnapshot.lastOrNull()?.domain,
            droppedTcp = droppedTcp,
        )
    }

    // ------------------------------------------------------------- identidad

    fun identify(uid: Int): Identity = identityCache.getOrPut(uid) { resolveIdentity(uid) }

    private fun resolveIdentity(uid: Int): Identity {
        if (uid < 0) return Identity("?", "SOMBRA SIN DUEÑO")
        if (uid == 0) return Identity("android:root", "NÚCLEO DEL SISTEMA")
        if (uid == Process.myUid()) return Identity(appContext.packageName, "NAVEGADOR")
        val pm = appContext.packageManager
        val packages = runCatching { pm.getPackagesForUid(uid) }.getOrNull()
        if (packages.isNullOrEmpty()) {
            return Identity("uid:$uid", if (uid == 1000) "SISTEMA ANDROID" else "PROCESO $uid")
        }
        val primary = packages.first()
        val label = runCatching {
            val info: ApplicationInfo = pm.getApplicationInfo(primary, 0)
            pm.getApplicationLabel(info).toString()
        }.getOrNull() ?: primary
        return Identity(primary, label)
    }

    fun isSystemApp(packageName: String): Boolean = runCatching {
        val info = appContext.packageManager.getApplicationInfo(packageName, 0)
        (info.flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0
    }.getOrDefault(false)

    fun applicationIcon(packageName: String) = runCatching {
        appContext.packageManager.getApplicationIcon(packageName)
    }.getOrNull()

    @Suppress("unused")
    fun packageManagerOrNull(): PackageManager? = if (::appContext.isInitialized) appContext.packageManager else null

    // ------------------------------------------------- tarjeta de presentación

    /**
     * Genera la carta que los Ladrones Fantasma dejan antes de robar un tesoro.
     * Es el informe legible del Palacio: qué hace la app y a quién le habla.
     */
    fun callingCard(uid: Int): String {
        val palace = _palaces.value[uid] ?: return "Sin datos de este Palacio."
        val theirShadows = _shadows.value.values
            .filter { it.uids.contains(uid) }
            .sortedByDescending { it.score }
        val worst = theirShadows.take(5)
        val line = "─".repeat(34)

        return buildString {
            appendLine("TARJETA DE PRESENTACIÓN")
            appendLine(line)
            appendLine("A: ${palace.label.uppercase()}")
            appendLine("(${palace.packageName})")
            appendLine()
            appendLine("Hemos visto tu Palacio: ${palace.rank.label}.")
            appendLine("Tu deseo distorsionado es la ${palace.dominantKind.distortion}.")
            appendLine()
            appendLine("Cargos:")
            appendLine("· ${palace.queries} consultas de nombre observadas")
            appendLine("· ${palace.domains.size} Sombras distintas contactadas")
            appendLine("· ${palace.blocked} tesoros ya confiscados")
            if (palace.bytesTotal > 0) {
                appendLine("· ${formatBytes(palace.bytesTx)} enviados / ${formatBytes(palace.bytesRx)} recibidos hoy")
            }
            if (worst.isNotEmpty()) {
                appendLine()
                appendLine("Cómplices principales:")
                worst.forEach { appendLine("· ${it.domain} — ${it.kind.display} (${it.score})") }
            }
            appendLine()
            appendLine("Tomaremos tus datos distorsionados sin dejar rastro.")
            appendLine("— Los Ladrones Fantasma del Metaverso")
            append(line)
        }
    }

    fun formatBytes(value: Long): String = when {
        value <= 0L -> "0 B"
        value < 1024L -> "$value B"
        value < 1024L * 1024 -> "${value / 1024} KB"
        value < 1024L * 1024 * 1024 -> "${"%.1f".format(value / 1024.0 / 1024.0)} MB"
        else -> "${"%.2f".format(value / 1024.0 / 1024.0 / 1024.0)} GB"
    }

    fun startOfToday(): Long {
        val calendar = Calendar.getInstance()
        calendar.set(Calendar.HOUR_OF_DAY, 0)
        calendar.set(Calendar.MINUTE, 0)
        calendar.set(Calendar.SECOND, 0)
        calendar.set(Calendar.MILLISECOND, 0)
        return calendar.timeInMillis
    }
}
