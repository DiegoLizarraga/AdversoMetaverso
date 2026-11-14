package com.adverso.metaverso.core

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Ajustes del Navegador. Se leen desde el hilo del túnel en caliente, así que
 * cada valor vive en un [StateFlow] y se persiste al escribir.
 */
class NavSettings(private val prefs: SharedPreferences) {

    private val _blockingEnabled = MutableStateFlow(prefs.getBoolean(KEY_BLOCKING, true))
    val blockingEnabledFlow: StateFlow<Boolean> = _blockingEnabled.asStateFlow()

    private val _hijackResolvers = MutableStateFlow(prefs.getBoolean(KEY_HIJACK, false))
    val hijackResolversFlow: StateFlow<Boolean> = _hijackResolvers.asStateFlow()

    private val _threshold = MutableStateFlow(prefs.getInt(KEY_THRESHOLD, 55))
    val thresholdFlow: StateFlow<Int> = _threshold.asStateFlow()

    private val _pacts = MutableStateFlow(prefs.getStringSet(KEY_PACTS, emptySet()).orEmpty())
    /** Dominios que el usuario perdonó explícitamente: nunca se bloquean. */
    val pactsFlow: StateFlow<Set<String>> = _pacts.asStateFlow()

    private val _stolen = MutableStateFlow(prefs.getStringSet(KEY_STOLEN, emptySet()).orEmpty())
    /** Dominios cuyo corazón el usuario robó a mano: siempre se bloquean. */
    val stolenFlow: StateFlow<Set<String>> = _stolen.asStateFlow()

    private val _upstream = MutableStateFlow(prefs.getString(KEY_UPSTREAM, DEFAULT_UPSTREAM) ?: DEFAULT_UPSTREAM)
    val upstreamFlow: StateFlow<String> = _upstream.asStateFlow()

    var blockingEnabled: Boolean
        get() = _blockingEnabled.value
        set(value) {
            prefs.edit().putBoolean(KEY_BLOCKING, value).apply()
            _blockingEnabled.value = value
        }

    /**
     * Modo agresivo: además del DNS del túnel, desvía los resolutores públicos
     * más comunes (8.8.8.8, 1.1.1.1…) para pillar apps que traen su DNS a mano.
     * Desactivado por defecto porque rompe DNS-over-TLS hacia esas mismas IPs.
     */
    var hijackResolvers: Boolean
        get() = _hijackResolvers.value
        set(value) {
            prefs.edit().putBoolean(KEY_HIJACK, value).apply()
            _hijackResolvers.value = value
        }

    var threshold: Int
        get() = _threshold.value
        set(value) {
            val clamped = value.coerceIn(20, 100)
            prefs.edit().putInt(KEY_THRESHOLD, clamped).apply()
            _threshold.value = clamped
        }

    var upstream: String
        get() = _upstream.value
        set(value) {
            prefs.edit().putString(KEY_UPSTREAM, value).apply()
            _upstream.value = value
        }

    fun isPacted(domain: String): Boolean = _pacts.value.contains(domain)

    fun isStolen(domain: String): Boolean = _stolen.value.contains(domain)

    /** Sellar un pacto: la Sombra queda libre y no se vuelve a bloquear. */
    fun seal(domain: String) {
        mutate(_stolen, KEY_STOLEN, domain, add = false)
        mutate(_pacts, KEY_PACTS, domain, add = true)
    }

    /** Robar el corazón: la Sombra queda bloqueada aunque parezca inofensiva. */
    fun steal(domain: String) {
        mutate(_pacts, KEY_PACTS, domain, add = false)
        mutate(_stolen, KEY_STOLEN, domain, add = true)
    }

    fun release(domain: String) {
        mutate(_pacts, KEY_PACTS, domain, add = false)
        mutate(_stolen, KEY_STOLEN, domain, add = false)
    }

    private fun mutate(flow: MutableStateFlow<Set<String>>, key: String, domain: String, add: Boolean) {
        val current = flow.value
        val next = if (add) current + domain else current - domain
        if (next == current) return
        prefs.edit().putStringSet(key, next).apply()
        flow.value = next
    }

    companion object {
        const val DEFAULT_UPSTREAM = "1.1.1.1"

        private const val KEY_BLOCKING = "blocking_enabled"
        private const val KEY_HIJACK = "hijack_resolvers"
        private const val KEY_THRESHOLD = "block_threshold"
        private const val KEY_PACTS = "pacted_domains"
        private const val KEY_STOLEN = "stolen_domains"
        private const val KEY_UPSTREAM = "upstream_dns"

        fun from(context: Context): NavSettings =
            NavSettings(context.getSharedPreferences("metaverso_nav", Context.MODE_PRIVATE))
    }
}
