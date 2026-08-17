package com.adverso.metaverso.core.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class PacketsTest {

    /**
     * El paquete que construimos para responder por el túnel tiene que ser
     * válido byte a byte: si el checksum IP está mal, Android lo descarta y la
     * app que preguntó se queda esperando para siempre.
     */
    @Test
    fun `el datagrama construido se vuelve a parsear igual`() {
        val payload = ByteArray(24) { (it * 7).toByte() }
        val source = byteArrayOf(10, 111, 222.toByte(), 2)
        val destination = byteArrayOf(10, 111, 222.toByte(), 1)

        val packet = Packets.buildUdpIpv4(source, 53, destination, 41234, payload)
        assertEquals(20 + 8 + payload.size, packet.size)

        val ip = Packets.parseIpv4(packet, packet.size)
        assertNotNull(ip)
        ip!!
        assertEquals(Packets.PROTO_UDP, ip.protocol)
        assertEquals(20, ip.headerLength)
        assertEquals(packet.size, ip.totalLength)
        assertEquals("10.111.222.2", ip.sourceText)
        assertEquals("10.111.222.1", ip.destinationText)

        val udp = Packets.parseUdp(packet, ip)
        assertNotNull(udp)
        udp!!
        assertEquals(53, udp.sourcePort)
        assertEquals(41234, udp.destinationPort)
        assertEquals(28, udp.payloadOffset)
        assertEquals(payload.size, udp.payloadLength)
        assertEquals(
            payload.toList(),
            packet.copyOfRange(udp.payloadOffset, udp.payloadOffset + udp.payloadLength).toList(),
        )
    }

    @Test
    fun `el checksum de la cabecera IP es correcto`() {
        val packet = Packets.buildUdpIpv4(
            byteArrayOf(1, 2, 3, 4),
            1053,
            byteArrayOf(5, 6, 7, 8),
            2053,
            ByteArray(10),
        )
        // La suma en complemento a uno de una cabecera válida, checksum incluido,
        // siempre da 0xFFFF.
        var sum = 0
        var i = 0
        while (i < 20) {
            sum += ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            i += 2
        }
        while ((sum shr 16) != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        assertEquals(0xFFFF, sum)
    }

    @Test
    fun `rechaza lo que no es IPv4`() {
        assertNull(Packets.parseIpv4(ByteArray(10), 10))
        val ipv6 = ByteArray(40).also { it[0] = 0x60 }
        assertNull(Packets.parseIpv4(ipv6, ipv6.size))
    }

    @Test
    fun `no lee mas payload del que realmente llego`() {
        // Cabecera que declara 200 bytes de UDP pero solo trae 8 de datos.
        val packet = Packets.buildUdpIpv4(
            byteArrayOf(10, 0, 0, 1),
            53,
            byteArrayOf(10, 0, 0, 2),
            5353,
            ByteArray(8),
        )
        packet[24] = 0x00
        packet[25] = 0xC8.toByte() // longitud UDP = 200

        val ip = Packets.parseIpv4(packet, packet.size)!!
        val udp = Packets.parseUdp(packet, ip)!!
        assertEquals(8, udp.payloadLength)
    }
}
