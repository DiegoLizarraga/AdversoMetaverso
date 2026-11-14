package com.adverso.metaverso.core.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.content.ContextCompat
import com.adverso.metaverso.R
import com.adverso.metaverso.core.Metaverse
import com.adverso.metaverso.core.net.Dns
import com.adverso.metaverso.core.net.Packets
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext

/**
 * El Navegador del Metaverso: el túnel que convierte el tráfico del teléfono en
 * algo que se puede mirar.
 *
 * **Por qué solo DNS.** Capturar *todo* el tráfico obliga a reimplementar TCP en
 * espacio de usuario; si ese código falla, el teléfono se queda sin internet.
 * En su lugar el túnel anuncia un resolutor propio ([STUB_DNS]) y enruta
 * únicamente esa dirección: el resto del tráfico sale por la red normal, intacto.
 * A cambio vemos cada nombre que resuelve cada app — que es donde está casi toda
 * la información interesante sobre con quién habla el dispositivo — y podemos
 * cortar de raíz devolviendo una respuesta nula.
 */
class NavigatorVpnService : VpnService() {

    private var tunnel: ParcelFileDescriptor? = null
    private var output: FileOutputStream? = null
    private var worker: Thread? = null
    private val writeLock = Any()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val inFlight = Semaphore(48)

    @Volatile private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        establish()
        return START_STICKY
    }

    override fun onRevoke() {
        // El usuario (u otra VPN) nos echó del Metaverso.
        Metaverse.notice("El sistema revocó el túnel. Otra VPN tomó el control.")
        shutdown()
        stopSelf()
    }

    override fun onDestroy() {
        shutdown()
        scope.cancel()
        super.onDestroy()
    }

    // ------------------------------------------------------------- ciclo de vida

    private fun establish() {
        if (running) return

        val builder = Builder()
            .setSession(getString(R.string.nav_session))
            .setMtu(MTU)
            .addAddress(TUN_ADDRESS, 32)
            .addDnsServer(STUB_DNS)
            .addRoute(STUB_DNS, 32)

        if (Metaverse.settings.hijackResolvers) {
            PUBLIC_RESOLVERS.forEach { resolver ->
                runCatching { builder.addRoute(resolver, 32) }
            }
        }
        // Nunca nos capturamos a nosotros mismos: el reenvío usa protect(), pero
        // excluir la app entera evita cualquier lazo.
        runCatching { builder.addDisallowedApplication(packageName) }
        builder.setBlocking(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        builder.setConfigureIntent(configureIntent())

        val descriptor = runCatching { builder.establish() }.getOrNull()
        if (descriptor == null) {
            Metaverse.notice("No se pudo abrir el túnel. Revisa el permiso de VPN.")
            Metaverse.onNavigatorActive(false)
            stopSelf()
            return
        }

        tunnel = descriptor
        output = FileOutputStream(descriptor.fileDescriptor)
        running = true

        startForegroundNotification()
        Metaverse.onNavigatorActive(true)
        warnAboutPrivateDns()

        worker = Thread({ pump(descriptor) }, "metaverso-tun").apply {
            isDaemon = true
            priority = Thread.NORM_PRIORITY + 1
            start()
        }
    }

    private fun shutdown() {
        if (!running && tunnel == null) return
        running = false
        worker?.interrupt()
        worker = null
        runCatching { output?.close() }
        output = null
        runCatching { tunnel?.close() }
        tunnel = null
        Metaverse.onNavigatorActive(false)
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    // ------------------------------------------------------------------- bucle

    private fun pump(descriptor: ParcelFileDescriptor) {
        val input = FileInputStream(descriptor.fileDescriptor)
        val buffer = ByteArray(MTU + 64)
        while (running) {
            val read = try {
                input.read(buffer)
            } catch (_: Throwable) {
                break // el descriptor se cerró: fin de la infiltración
            }
            if (read <= 0) continue
            runCatching { handle(buffer, read) }
        }
        runCatching { input.close() }
    }

    private fun handle(buffer: ByteArray, length: Int) {
        val ip = Packets.parseIpv4(buffer, length) ?: return

        if (ip.protocol != Packets.PROTO_UDP) {
            // Solo enrutamos direcciones de resolutores, así que lo único que
            // puede llegar por TCP es DNS-over-TCP o DoT. Lo dejamos caer y lo
            // contamos para poder avisar al usuario.
            if (ip.protocol == Packets.PROTO_TCP) Metaverse.onTcpDropped()
            return
        }

        val udp = Packets.parseUdp(buffer, ip) ?: return
        if (udp.destinationPort != DNS_PORT || udp.payloadLength < 12) return

        // El búfer se reutiliza en la siguiente lectura del túnel, así que nos
        // quedamos con nuestra propia copia del mensaje antes de tocar nada.
        val payload = buffer.copyOfRange(udp.payloadOffset, udp.payloadOffset + udp.payloadLength)
        val message = Dns.parse(payload, 0, payload.size) ?: return
        if (!message.isQuery) return
        val question = message.questions.firstOrNull() ?: return

        val uid = resolveOwnerUid(ip, udp)
        val verdict = Metaverse.evaluate(question.name)
        val decision = Metaverse.decide(verdict)
        val queryType = Dns.typeName(question.type)

        val clientIp = ip.source
        val clientPort = udp.sourcePort
        val serverIp = ip.destination

        if (decision.block) {
            val sinkhole = Dns.buildSinkhole(payload, message, 0)
            writeToTunnel(Packets.buildUdpIpv4(serverIp, DNS_PORT, clientIp, clientPort, sinkhole))
            Metaverse.record(
                domain = verdict.domain,
                queryType = queryType,
                uid = uid,
                verdict = verdict,
                blocked = true,
                reason = decision.reason,
            )
            return
        }

        scope.launch {
            inFlight.withPermit {
                val started = System.nanoTime()
                val answer = forward(payload)
                val elapsed = ((System.nanoTime() - started) / 1_000_000).toInt()
                if (answer != null) {
                    writeToTunnel(Packets.buildUdpIpv4(serverIp, DNS_PORT, clientIp, clientPort, answer))
                }
                val addresses = answer
                    ?.let { Dns.parse(it, 0, it.size) }
                    ?.addresses
                    .orEmpty()
                Metaverse.record(
                    domain = verdict.domain,
                    queryType = queryType,
                    uid = uid,
                    verdict = verdict,
                    blocked = false,
                    reason = if (answer == null) "Sin respuesta del resolutor" else decision.reason,
                    addresses = addresses,
                    latencyMs = elapsed,
                )
            }
        }
    }

    private suspend fun forward(query: ByteArray): ByteArray? = withContext(Dispatchers.IO) {
        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket()
            // protect() saca este socket del propio túnel; sin esto, bucle infinito.
            if (!protect(socket)) return@withContext null
            socket.soTimeout = UPSTREAM_TIMEOUT_MS
            val upstream = InetAddress.getByName(Metaverse.settings.upstream)
            socket.send(DatagramPacket(query, query.size, upstream, DNS_PORT))
            val buffer = ByteArray(4096)
            val response = DatagramPacket(buffer, buffer.size)
            socket.receive(response)
            buffer.copyOf(response.length)
        } catch (_: Throwable) {
            null
        } finally {
            runCatching { socket?.close() }
        }
    }

    private fun writeToTunnel(packet: ByteArray) {
        val stream = output ?: return
        synchronized(writeLock) {
            runCatching { stream.write(packet) }
        }
    }

    /**
     * Quién es el dueño del socket que hizo la consulta. Disponible desde
     * Android 10; en versiones anteriores todo queda como "Sombra sin dueño".
     */
    private fun resolveOwnerUid(ip: Packets.Ipv4Header, udp: Packets.UdpHeader): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return -1
        val manager = getSystemService(ConnectivityManager::class.java) ?: return -1
        return runCatching {
            manager.getConnectionOwnerUid(
                OsConstants.IPPROTO_UDP,
                InetSocketAddress(InetAddress.getByAddress(ip.source), udp.sourcePort),
                InetSocketAddress(InetAddress.getByAddress(ip.destination), udp.destinationPort),
            )
        }.getOrDefault(-1)
    }

    /**
     * Si el sistema tiene DNS privado (DoT/DoH) activo, las consultas no pasan
     * por nuestro resolutor y el Navegador se queda ciego. Hay que decirlo.
     */
    private fun warnAboutPrivateDns() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P) return
        val manager = getSystemService(ConnectivityManager::class.java) ?: return
        val active = manager.activeNetwork ?: return
        val properties = manager.getLinkProperties(active) ?: return
        if (properties.isPrivateDnsActive) {
            Metaverse.notice(
                "DNS privado activo (${properties.privateDnsServerName ?: "automático"}). " +
                    "Desactívalo en Ajustes › Red › DNS privado para que el Navegador vea las consultas.",
            )
        }
    }

    // ---------------------------------------------------------- notificación

    private fun configureIntent(): PendingIntent {
        val intent = Intent().setClassName(packageName, "com.adverso.metaverso.ui.MainActivity")
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        return PendingIntent.getActivity(this, 0, intent, flags)
    }

    private fun startForegroundNotification() {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager != null && manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, getString(R.string.nav_channel_name), NotificationManager.IMPORTANCE_LOW).apply {
                    description = getString(R.string.nav_channel_description)
                    setShowBadge(false)
                },
            )
        }

        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, NavigatorVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Estás en el Metaverso")
            .setContentText("Vigilando las Sombras de esta red")
            .setSmallIcon(R.drawable.ic_nav_status)
            .setOngoing(true)
            .setContentIntent(configureIntent())
            .addAction(Notification.Action.Builder(null, "SALIR", stopIntent).build())
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    companion object {
        const val ACTION_START = "com.adverso.metaverso.action.ENTER"
        const val ACTION_STOP = "com.adverso.metaverso.action.EXIT"

        private const val CHANNEL_ID = "metaverso.navigator"
        private const val NOTIFICATION_ID = 0x5150
        private const val MTU = 1500
        private const val DNS_PORT = 53
        private const val UPSTREAM_TIMEOUT_MS = 5_000

        /** Dirección del extremo local del túnel. */
        private const val TUN_ADDRESS = "10.111.222.1"

        /** Resolutor ficticio que anunciamos y que es lo único que enrutamos. */
        private const val STUB_DNS = "10.111.222.2"

        /** Resolutores públicos que se desvían en modo agresivo. */
        private val PUBLIC_RESOLVERS = listOf(
            "8.8.8.8", "8.8.4.4",       // Google
            "1.1.1.1", "1.0.0.1",       // Cloudflare
            "9.9.9.9", "149.112.112.112", // Quad9
            "208.67.222.222",           // OpenDNS
            "94.140.14.14",             // AdGuard
        )

        fun enter(context: Context) {
            val intent = Intent(context, NavigatorVpnService::class.java).setAction(ACTION_START)
            ContextCompat.startForegroundService(context, intent)
        }

        fun exit(context: Context) {
            val intent = Intent(context, NavigatorVpnService::class.java).setAction(ACTION_STOP)
            runCatching { context.startService(intent) }
        }
    }
}
