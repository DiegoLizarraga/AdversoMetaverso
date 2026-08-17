package com.adverso.metaverso.core.net

/**
 * Lectura y escritura de paquetes IPv4/UDP en crudo.
 *
 * Lo que sale del descriptor del túnel son bytes de capa 3 sin cabecera de
 * enlace, así que aquí no hay Ethernet: el byte 0 ya es el primer byte IP.
 */
object Packets {

    const val PROTO_ICMP = 1
    const val PROTO_TCP = 6
    const val PROTO_UDP = 17

    class Ipv4Header(
        val headerLength: Int,
        val totalLength: Int,
        val protocol: Int,
        val source: ByteArray,
        val destination: ByteArray,
    ) {
        val sourceText: String get() = textOf(source)
        val destinationText: String get() = textOf(destination)
    }

    class UdpHeader(
        val sourcePort: Int,
        val destinationPort: Int,
        val payloadOffset: Int,
        val payloadLength: Int,
    )

    fun parseIpv4(data: ByteArray, length: Int): Ipv4Header? {
        if (length < 20) return null
        val versionAndIhl = data[0].toInt() and 0xFF
        if ((versionAndIhl shr 4) != 4) return null
        val headerLength = (versionAndIhl and 0x0F) * 4
        if (headerLength < 20 || headerLength > length) return null
        val declared = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
        // Algunos drivers de tun rellenan; nos quedamos con lo que de verdad leímos.
        val total = if (declared in headerLength..length) declared else length
        return Ipv4Header(
            headerLength = headerLength,
            totalLength = total,
            protocol = data[9].toInt() and 0xFF,
            source = data.copyOfRange(12, 16),
            destination = data.copyOfRange(16, 20),
        )
    }

    fun parseUdp(data: ByteArray, ip: Ipv4Header): UdpHeader? {
        val offset = ip.headerLength
        if (offset + 8 > ip.totalLength) return null
        val sourcePort = u16(data, offset)
        val destinationPort = u16(data, offset + 2)
        val udpLength = u16(data, offset + 4)
        val payloadOffset = offset + 8
        val declared = (udpLength - 8).coerceAtLeast(0)
        val available = (ip.totalLength - payloadOffset).coerceAtLeast(0)
        return UdpHeader(sourcePort, destinationPort, payloadOffset, minOf(declared, available))
    }

    /**
     * Construye un datagrama IPv4/UDP completo listo para escribirse en el túnel.
     * El checksum UDP se deja en cero: es opcional en IPv4 y ahorra una pasada.
     */
    fun buildUdpIpv4(
        source: ByteArray,
        sourcePort: Int,
        destination: ByteArray,
        destinationPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val total = 20 + 8 + payload.size
        val out = ByteArray(total)

        out[0] = 0x45                                   // IPv4, IHL = 5
        out[2] = ((total shr 8) and 0xFF).toByte()
        out[3] = (total and 0xFF).toByte()
        out[6] = 0x40                                   // Don't Fragment
        out[8] = 64                                     // TTL
        out[9] = PROTO_UDP.toByte()
        System.arraycopy(source, 0, out, 12, 4)
        System.arraycopy(destination, 0, out, 16, 4)
        val checksum = onesComplement(out, 0, 20)
        out[10] = ((checksum shr 8) and 0xFF).toByte()
        out[11] = (checksum and 0xFF).toByte()

        val udpLength = 8 + payload.size
        out[20] = ((sourcePort shr 8) and 0xFF).toByte()
        out[21] = (sourcePort and 0xFF).toByte()
        out[22] = ((destinationPort shr 8) and 0xFF).toByte()
        out[23] = (destinationPort and 0xFF).toByte()
        out[24] = ((udpLength shr 8) and 0xFF).toByte()
        out[25] = (udpLength and 0xFF).toByte()
        System.arraycopy(payload, 0, out, 28, payload.size)
        return out
    }

    fun textOf(raw: ByteArray): String = when (raw.size) {
        4 -> "${raw[0].toInt() and 0xFF}.${raw[1].toInt() and 0xFF}." +
            "${raw[2].toInt() and 0xFF}.${raw[3].toInt() and 0xFF}"
        else -> raw.joinToString(":") { (it.toInt() and 0xFF).toString(16) }
    }

    internal fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)

    private fun onesComplement(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += u16(data, i)
            i += 2
        }
        if (i < end) sum += (data[i].toInt() and 0xFF) shl 8
        while ((sum shr 16) != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }
}
