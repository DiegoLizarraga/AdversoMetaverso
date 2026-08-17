package com.adverso.metaverso.core.net

/**
 * Un lector de mensajes DNS (RFC 1035) del tamaño mínimo necesario.
 *
 * Nos interesan tres cosas: qué nombre se pregunta, qué direcciones responde el
 * resolutor de verdad, y cómo fabricar una respuesta falsa cuando decidimos
 * confiscarle el tesoro a una Sombra.
 */
object Dns {

    const val TYPE_A = 1
    const val TYPE_CNAME = 5
    const val TYPE_AAAA = 28
    const val TYPE_HTTPS = 65

    private const val RCODE_NXDOMAIN = 3
    private const val FLAGS_RESPONSE = 0x8180 // QR=1, RD=1, RA=1

    class Question(val name: String, val type: Int, val cls: Int)

    class Record(val name: String, val type: Int, val address: String?)

    class Message(
        val id: Int,
        val flags: Int,
        val questions: List<Question>,
        val answers: List<Record>,
        /** Offset absoluto justo después de la sección de preguntas. */
        val questionSectionEnd: Int,
    ) {
        val isQuery: Boolean get() = (flags and 0x8000) == 0
        val responseCode: Int get() = flags and 0x0F
        val addresses: List<String> get() = answers.mapNotNull { it.address }
    }

    fun typeName(type: Int): String = when (type) {
        TYPE_A -> "A"
        TYPE_CNAME -> "CNAME"
        12 -> "PTR"
        15 -> "MX"
        16 -> "TXT"
        TYPE_AAAA -> "AAAA"
        33 -> "SRV"
        64 -> "SVCB"
        TYPE_HTTPS -> "HTTPS"
        else -> "TYPE$type"
    }

    fun parse(data: ByteArray, offset: Int, length: Int): Message? {
        if (length < 12 || offset + length > data.size) return null
        val end = offset + length
        val id = Packets.u16(data, offset)
        val flags = Packets.u16(data, offset + 2)
        val questionCount = Packets.u16(data, offset + 4)
        val answerCount = Packets.u16(data, offset + 6)
        if (questionCount == 0 || questionCount > 8) return null

        var cursor = offset + 12
        val questions = ArrayList<Question>(questionCount)
        repeat(questionCount) {
            val name = readName(data, cursor, offset, end) ?: return null
            if (name.next + 4 > end) return null
            questions.add(Question(name.value, Packets.u16(data, name.next), Packets.u16(data, name.next + 2)))
            cursor = name.next + 4
        }
        val questionSectionEnd = cursor

        val answers = ArrayList<Record>(answerCount.coerceAtMost(16))
        var seen = 0
        while (seen < answerCount) {
            val name = readName(data, cursor, offset, end) ?: break
            if (name.next + 10 > end) break
            val type = Packets.u16(data, name.next)
            val dataLength = Packets.u16(data, name.next + 8)
            val dataOffset = name.next + 10
            if (dataOffset + dataLength > end) break
            val address = when {
                type == TYPE_A && dataLength == 4 -> Packets.textOf(data.copyOfRange(dataOffset, dataOffset + 4))
                type == TYPE_AAAA && dataLength == 16 -> ipv6Text(data, dataOffset)
                else -> null
            }
            answers.add(Record(name.value, type, address))
            cursor = dataOffset + dataLength
            seen++
        }
        return Message(id, flags, questions, answers, questionSectionEnd)
    }

    /**
     * Fabrica la respuesta con la que se le roba el corazón a una Sombra.
     *
     * Para A/AAAA devolvemos la dirección nula (0.0.0.0 / ::) en lugar de
     * NXDOMAIN: las apps fallan de inmediato en vez de reintentar con otro
     * resolutor, y así el bloqueo no se convierte en una fuga.
     */
    fun buildSinkhole(query: ByteArray, message: Message, queryOffset: Int): ByteArray {
        val question = message.questions.first()
        val questionBytes = query.copyOfRange(queryOffset + 12, message.questionSectionEnd)
        val nullAddress = when (question.type) {
            TYPE_A -> ByteArray(4)
            TYPE_AAAA -> ByteArray(16)
            else -> null
        }
        val answerSize = if (nullAddress != null) 12 + nullAddress.size else 0
        val out = ByteArray(12 + questionBytes.size + answerSize)
        var p = 0
        fun put16(value: Int) {
            out[p++] = ((value shr 8) and 0xFF).toByte()
            out[p++] = (value and 0xFF).toByte()
        }

        put16(message.id)
        put16(if (nullAddress != null) FLAGS_RESPONSE else (FLAGS_RESPONSE or RCODE_NXDOMAIN))
        put16(message.questions.size)
        put16(if (nullAddress != null) 1 else 0)
        put16(0)
        put16(0)
        System.arraycopy(questionBytes, 0, out, p, questionBytes.size)
        p += questionBytes.size

        if (nullAddress != null) {
            put16(0xC00C)               // puntero comprimido al nombre de la pregunta
            put16(question.type)
            put16(question.cls)
            put16(0); put16(60)         // TTL de 60 s: reevaluamos pronto
            put16(nullAddress.size)
            System.arraycopy(nullAddress, 0, out, p, nullAddress.size)
        }
        return out
    }

    private class Name(val value: String, val next: Int)

    /**
     * Lee un nombre con soporte de punteros de compresión. [next] es siempre el
     * offset en el flujo original, no en el destino del salto.
     */
    private fun readName(data: ByteArray, start: Int, base: Int, end: Int): Name? {
        val builder = StringBuilder()
        var cursor = start
        var next = -1
        var hops = 0
        while (cursor < end) {
            val length = data[cursor].toInt() and 0xFF
            when {
                length == 0 -> {
                    cursor++
                    if (next < 0) next = cursor
                    return Name(builder.toString(), next)
                }
                (length and 0xC0) == 0xC0 -> {
                    if (cursor + 1 >= end) return null
                    val pointer = base + (((length and 0x3F) shl 8) or (data[cursor + 1].toInt() and 0xFF))
                    if (next < 0) next = cursor + 2
                    if (++hops > 16 || pointer < base || pointer >= end) return null
                    cursor = pointer
                }
                else -> {
                    if (cursor + 1 + length > end) return null
                    if (builder.isNotEmpty()) builder.append('.')
                    builder.append(String(data, cursor + 1, length, Charsets.ISO_8859_1))
                    cursor += 1 + length
                }
            }
        }
        return null
    }

    private fun ipv6Text(data: ByteArray, offset: Int): String {
        val parts = ArrayList<String>(8)
        for (i in 0 until 8) {
            parts.add(Integer.toHexString(Packets.u16(data, offset + i * 2)))
        }
        return parts.joinToString(":")
    }
}
