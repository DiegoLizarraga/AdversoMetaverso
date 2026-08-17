package com.adverso.metaverso.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.lifecycleScope
import com.adverso.metaverso.core.Metaverse
import com.adverso.metaverso.core.stats.TrafficLedger
import com.adverso.metaverso.core.vpn.NavigatorVpnService
import com.adverso.metaverso.ui.theme.MetaversoTheme
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    private var trafficAccess by mutableStateOf(false)

    /**
     * Android exige que el usuario acepte el túnel en un diálogo del sistema.
     * `VpnService.prepare` devuelve el intent que lo muestra, o null si ya hay
     * consentimiento vigente.
     */
    private val vpnConsent = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            NavigatorVpnService.enter(this)
        } else {
            Metaverse.notice("Sin permiso de VPN no se puede entrar al Metaverso.")
        }
    }

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* opcional */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notificationPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }

        val actions = MetaversoActions(
            toggleNavigator = ::toggleNavigator,
            toggleBlocking = { Metaverse.settings.blockingEnabled = !Metaverse.settings.blockingEnabled },
            toggleHijack = ::toggleHijack,
            setThreshold = { Metaverse.settings.threshold = it },
            openTrafficAccess = ::openTrafficAccess,
            shareCard = ::shareCard,
            resetRun = { Metaverse.clearRun() },
        )

        setContent {
            MetaversoTheme {
                MetaversoApp(actions = actions, hasTrafficAccess = trafficAccess)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshTraffic()
    }

    private fun toggleNavigator() {
        if (Metaverse.navigatorActive.value) {
            NavigatorVpnService.exit(this)
            return
        }
        val consent = VpnService.prepare(this)
        if (consent == null) {
            NavigatorVpnService.enter(this)
        } else {
            vpnConsent.launch(consent)
        }
    }

    /**
     * El modo agresivo cambia las rutas del túnel, así que si ya estamos dentro
     * hay que reconstruirlo para que el cambio surta efecto.
     */
    private fun toggleHijack() {
        Metaverse.settings.hijackResolvers = !Metaverse.settings.hijackResolvers
        if (Metaverse.navigatorActive.value) {
            NavigatorVpnService.exit(this)
            Metaverse.notice("Rutas cambiadas: vuelve a infiltrarte para aplicarlas.")
        }
    }

    private fun openTrafficAccess() {
        runCatching { startActivity(TrafficLedger.accessSettingsIntent()) }
            .onFailure { Metaverse.notice("No se pudo abrir Ajustes de acceso al uso.") }
    }

    private fun refreshTraffic() {
        trafficAccess = TrafficLedger.hasAccess(this)
        if (!trafficAccess) return
        lifecycleScope.launch {
            val ledger = TrafficLedger.since(this@MainActivity, Metaverse.startOfToday())
            Metaverse.mergeTraffic(ledger)
        }
    }

    private fun shareCard(card: String) {
        val intent = Intent(Intent.ACTION_SEND)
            .setType("text/plain")
            .putExtra(Intent.EXTRA_TEXT, card)
        runCatching { startActivity(Intent.createChooser(intent, "Enviar la tarjeta")) }
    }
}
