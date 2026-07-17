package com.example.tlswatchdog.detect

/** Result of inspecting the first payload of a flow. */
enum class Verdict(val label: String) {
    TLS("TLS"),
    QUIC("QUIC"),
    CLEARTEXT_HTTP("Cleartext HTTP"),
    CLEARTEXT_OTHER("Cleartext"),
    CLEARTEXT_UDP("Cleartext UDP"),
    DNS("DNS"),
    UNKNOWN("Unknown");

    /** Whether this verdict should be treated as an offender (alert + filter). */
    fun isOffender(flagNonQuicUdp: Boolean): Boolean = when (this) {
        CLEARTEXT_HTTP, CLEARTEXT_OTHER -> true
        CLEARTEXT_UDP, DNS -> flagNonQuicUdp
        TLS, QUIC, UNKNOWN -> false
    }
}

/**
 * Classifies a flow from the first bytes of its payload, and (best effort) extracts
 * the destination hostname. Judged by content, never by port number — the port is
 * only a hint for labelling (e.g. DNS).
 */
object FlowClassifier {
    private const val IPPROTO_TCP = 6
    private const val IPPROTO_UDP = 17

    private val httpPrefixes = listOf(
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ",
        "PATCH ", "CONNECT ", "TRACE ", "HTTP/",
    )

    fun classify(proto: Int, dstPort: Int, p: ByteArray): Verdict = when (proto) {
        IPPROTO_TCP -> classifyTcp(p)
        IPPROTO_UDP -> classifyUdp(dstPort, p)
        else -> Verdict.UNKNOWN
    }

    private fun classifyTcp(p: ByteArray): Verdict {
        if (p.size < 3) return Verdict.UNKNOWN
        // TLS handshake record: content type 0x16, version major 0x03.
        if (u(p, 0) == 0x16 && u(p, 1) == 0x03) return Verdict.TLS

        val n = minOf(p.size, 16)
        val ascii = String(p, 0, n, Charsets.US_ASCII)
        if (httpPrefixes.any { ascii.startsWith(it) }) return Verdict.CLEARTEXT_HTTP

        val printable = (0 until n).count { u(p, it) in 0x09..0x7e }
        if (printable >= (n * 3) / 4) return Verdict.CLEARTEXT_OTHER
        return Verdict.UNKNOWN
    }

    private fun classifyUdp(dstPort: Int, p: ByteArray): Verdict {
        if (isQuic(dstPort, p)) return Verdict.QUIC
        if (dstPort == 53 || looksLikeDns(p)) return Verdict.DNS
        return Verdict.CLEARTEXT_UDP
    }

    /**
     * QUIC always implies TLS 1.3. The first datagram is a long-header Initial:
     * high bit (0x80) set + fixed bit (0x40) set, followed by a 4-byte version.
     * Also accept a short-header packet to :443 as an established QUIC flow.
     */
    private fun isQuic(dstPort: Int, p: ByteArray): Boolean {
        if (p.size < 5) return false
        val b0 = u(p, 0)
        if (b0 and 0xc0 == 0xc0) {
            val version = (u(p, 1) shl 24) or (u(p, 2) shl 16) or (u(p, 3) shl 8) or u(p, 4)
            // v1 (0x00000001), v2 (0x6b3343cf), drafts (0xff0000xx), version negotiation (0).
            return version == 0x00000001 ||
                version == 0x6b3343cf ||
                (version ushr 8) == 0xff0000 ||
                version == 0
        }
        // Short header (established connection) — only trust it on the QUIC port.
        return dstPort == 443 && (b0 and 0xc0) == 0x40
    }

    private fun looksLikeDns(p: ByteArray): Boolean {
        // 12-byte header; QR=0 (query), opcode 0, QDCOUNT>=1. Heuristic only.
        if (p.size < 12) return false
        val flags = u(p, 2)
        val qdcount = (u(p, 4) shl 8) or u(p, 5)
        return (flags and 0x78) == 0 && qdcount in 1..16
    }

    /** Best-effort destination hostname: TLS SNI or HTTP Host header. */
    fun extractHost(proto: Int, p: ByteArray): String? {
        if (proto != IPPROTO_TCP || p.size < 6) return null
        return if (u(p, 0) == 0x16 && u(p, 1) == 0x03) parseSni(p) else parseHttpHost(p)
    }

    private fun parseHttpHost(p: ByteArray): String? {
        val text = String(p, 0, minOf(p.size, p.size), Charsets.ISO_8859_1)
        val idx = text.indexOf("\r\nHost:", ignoreCase = true).let {
            if (it >= 0) it + 7 else if (text.startsWith("Host:", ignoreCase = true)) 5 else -1
        }
        if (idx < 0) return null
        val end = text.indexOf("\r\n", idx).let { if (it >= 0) it else text.length }
        val host = text.substring(idx, end).trim()
        return host.ifEmpty { null }?.substringBefore(':')
    }

    /** Parse the SNI (server_name) extension out of a TLS ClientHello. */
    private fun parseSni(p: ByteArray): String? {
        try {
            var o = 5 // skip record header
            if (u(p, o) != 0x01) return null // ClientHello
            o += 4 // handshake type(1) + length(3)
            o += 2 // client_version
            o += 32 // random
            if (o >= p.size) return null
            o += 1 + u(p, o) // session_id
            if (o + 2 > p.size) return null
            o += 2 + ((u(p, o) shl 8) or u(p, o + 1)) // cipher_suites
            if (o >= p.size) return null
            o += 1 + u(p, o) // compression_methods
            if (o + 2 > p.size) return null
            var extEnd = o + 2 + ((u(p, o) shl 8) or u(p, o + 1))
            o += 2
            extEnd = minOf(extEnd, p.size)
            while (o + 4 <= extEnd) {
                val type = (u(p, o) shl 8) or u(p, o + 1)
                val len = (u(p, o + 2) shl 8) or u(p, o + 3)
                o += 4
                if (type == 0x0000) { // server_name
                    // server_name_list(2) + name_type(1) + name_len(2) + name
                    if (o + 5 > p.size) return null
                    val nameLen = (u(p, o + 3) shl 8) or u(p, o + 4)
                    val start = o + 5
                    if (start + nameLen > p.size) return null
                    return String(p, start, nameLen, Charsets.US_ASCII)
                }
                o += len
            }
        } catch (e: Exception) {
            return null
        }
        return null
    }

    private fun u(p: ByteArray, i: Int): Int = p[i].toInt() and 0xff
}
