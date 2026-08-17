package com.adverso.metaverso.core.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * El parseo de DNS es la pieza que más fácil se rompe en silencio: un offset mal
 * puesto y la app enseña dominios basura, o peor, el túnel devuelve respuestas
 * corruptas y las apps se quedan sin red. Aquí se fija su comportamiento.
 */
class DnsTest {

    private fun query(name: String, type: Int = Dns.TYPE_A, id: Int = 0x1234): ByteArray {
        val labels = name.split('.')
        val size = 12 + labels.sumOf { it.length + 1 } + 1 + 4
        val out = ByteArray(size)
        var p = 0
        fun put16(v: Int) {
            out[p++] = ((v shr 8) and 0xFF).toByte()
            out[p++] = (v and 0xFF).toByte()
        }
        put16(id)
        put16(0x0100) // consulta recursiva
        put16(1); put16(0); put16(0); put16(0)
        labels.forEach { label ->
            out[p++] = label.length.toByte()
            label.forEach { out[p++] = it.code.toByte() }
        }
        out[p++] = 0
        put16(type)
        put16(1) // clase IN
        return out
    }

    @Test
    fun `lee el nombre y el tipo de una consulta`() {
        val packet = query("graph.facebook.com")
        val message = Dns.parse(packet, 0, packet.size)
        assertNotNull(message)
        message!!
        assertEquals(0x1234, message.id)
        assertTrue(message.isQuery)
        assertEquals(1, message.questions.size)
        assertEquals("graph.facebook.com", message.questions[0].name)
        assertEquals(Dns.TYPE_A, message.questions[0].type)
        assertEquals(packet.size, message.questionSectionEnd)
    }

    @Test
    fun `descarta mensajes truncados en vez de inventar datos`() {
        val packet = query("example.com")
        assertNull(Dns.parse(packet, 0, 8))
        // Cortar en medio de la última etiqueta debe fallar, no leer basura.
        assertNull(Dns.parse(packet, 0, packet.size - 6))
    }

    @Test
    fun `resuelve punteros de compresion en las respuestas`() {
        // Cabecera + pregunta "cdn.test" + una respuesta A que apunta al nombre
        // de la pregunta con el puntero 0xC00C.
        val q = query("cdn.test")
        val answer = byteArrayOf(
            0xC0.toByte(), 0x0C,                    // puntero al offset 12
            0x00, 0x01,                             // tipo A
            0x00, 0x01,                             // clase IN
            0x00, 0x00, 0x00, 0x3C,                 // TTL 60
            0x00, 0x04,                             // rdlength
            93, 184.toByte(), 216.toByte(), 34,     // 93.184.216.34
        )
        val packet = q + answer
        // Marcamos la respuesta: QR=1 y ANCOUNT=1.
        packet[2] = 0x81.toByte(); packet[3] = 0x80.toByte()
        packet[6] = 0x00; packet[7] = 0x01

        val message = Dns.parse(packet, 0, packet.size)
        assertNotNull(message)
        message!!
        assertFalse(message.isQuery)
        assertEquals(1, message.answers.size)
        assertEquals("cdn.test", message.answers[0].name)
        assertEquals(listOf("93.184.216.34"), message.addresses)
    }

    @Test
    fun `el sinkhole devuelve la direccion nula para consultas A`() {
        val packet = query("doubleclick.net", Dns.TYPE_A, id = 0xBEEF)
        val message = Dns.parse(packet, 0, packet.size)!!
        val response = Dns.buildSinkhole(packet, message, 0)

        val parsed = Dns.parse(response, 0, response.size)
        assertNotNull(parsed)
        parsed!!
        assertEquals(0xBEEF, parsed.id)
        assertFalse(parsed.isQuery)
        assertEquals(0, parsed.responseCode)
        assertEquals("doubleclick.net", parsed.questions[0].name)
        assertEquals(listOf("0.0.0.0"), parsed.addresses)
    }

    @Test
    fun `el sinkhole responde NXDOMAIN a tipos sin direccion`() {
        val packet = query("tracker.test", Dns.TYPE_HTTPS)
        val message = Dns.parse(packet, 0, packet.size)!!
        val response = Dns.buildSinkhole(packet, message, 0)

        val parsed = Dns.parse(response, 0, response.size)!!
        assertEquals(3, parsed.responseCode) // NXDOMAIN
        assertTrue(parsed.answers.isEmpty())
    }

    @Test
    fun `el sinkhole de AAAA usa la direccion nula de IPv6`() {
        val packet = query("ads.test", Dns.TYPE_AAAA)
        val message = Dns.parse(packet, 0, packet.size)!!
        val response = Dns.buildSinkhole(packet, message, 0)

        val parsed = Dns.parse(response, 0, response.size)!!
        assertEquals(0, parsed.responseCode)
        assertEquals(1, parsed.answers.size)
        assertEquals("0:0:0:0:0:0:0:0", parsed.answers[0].address)
    }

    @Test
    fun `parsea con un offset distinto de cero`() {
        // Así llega en la vida real: precedido por las cabeceras IP y UDP.
        val prefix = ByteArray(28) { 0x7F }
        val packet = prefix + query("offset.test")
        val message = Dns.parse(packet, 28, packet.size - 28)
        assertNotNull(message)
        assertEquals("offset.test", message!!.questions[0].name)
    }
}
