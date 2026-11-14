package com.adverso.metaverso.core.stats

import android.app.AppOpsManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.provider.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Cuántos bytes de verdad salieron y entraron por cada app.
 *
 * Esto no viene del túnel: lo lleva el propio Android en [NetworkStatsManager] y
 * requiere el permiso especial de "Acceso al uso". Es el complemento perfecto de
 * la vista DNS — el DNS dice *con quién* habla una app, esto dice *cuánto* le
 * cuenta.
 */
object TrafficLedger {

    /**
     * El sistema solo concede este dato tras un permiso especial de Ajustes.
     *
     * No hay forma no obsoleta de preguntarlo: `AppOpsManager` es la única vía
     * pública para saber si "Acceso al uso" está concedido sin provocar una
     * excepción, y todas sus variantes están marcadas como deprecadas.
     */
    @Suppress("DEPRECATION")
    fun hasAccess(context: Context): Boolean {
        val manager = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager ?: return false
        val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            manager.unsafeCheckOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                context.packageName,
            )
        } else {
            manager.checkOpNoThrow(
                AppOpsManager.OPSTR_GET_USAGE_STATS,
                Process.myUid(),
                context.packageName,
            )
        }
        return mode == AppOpsManager.MODE_ALLOWED
    }

    fun accessSettingsIntent(): Intent =
        Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    /**
     * Bytes por UID desde [since] hasta ahora, como `[tx, rx]`.
     * Devuelve un mapa vacío si falta el permiso o el sistema se niega.
     */
    suspend fun since(context: Context, since: Long): Map<Int, LongArray> = withContext(Dispatchers.IO) {
        if (!hasAccess(context)) return@withContext emptyMap()
        val manager = context.getSystemService(NetworkStatsManager::class.java)
            ?: return@withContext emptyMap()

        val now = System.currentTimeMillis()
        val totals = HashMap<Int, LongArray>()
        val bucket = NetworkStats.Bucket()

        @Suppress("DEPRECATION")
        val transports = intArrayOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)
        for (transport in transports) {
            val stats = try {
                manager.querySummary(transport, null, since, now)
            } catch (_: Throwable) {
                continue // sin SIM, sin permiso de teléfono, o el OEM lo bloquea
            }
            try {
                while (stats.hasNextBucket()) {
                    stats.getNextBucket(bucket)
                    val entry = totals.getOrPut(bucket.uid) { LongArray(2) }
                    entry[0] += bucket.txBytes
                    entry[1] += bucket.rxBytes
                }
            } catch (_: Throwable) {
                // seguimos con el siguiente transporte
            } finally {
                runCatching { stats.close() }
            }
        }
        totals
    }
}
