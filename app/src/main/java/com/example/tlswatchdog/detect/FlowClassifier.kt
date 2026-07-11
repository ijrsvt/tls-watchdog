package com.example.tlswatchdog.detect

/** Result of inspecting the first client->server payload of a flow. */
enum class Verdict(val label: String, val isOffender: Boolean) {
    TLS("TLS", false),
    CLEARTEXT_HTTP("Cleartext HTTP", true),
    CLEARTEXT_OTHER("Cleartext", true),
    UNKNOWN("Unknown", false),
}

/**
 * Classifies a flow from the first bytes the client sends to the server.
 * Judged by content, never by port number.
 */
object FlowClassifier {
    private const val IPPROTO_TCP = 6

    private val httpPrefixes = listOf(
        "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ",
        "PATCH ", "CONNECT ", "TRACE ", "HTTP/",
    )

    fun classify(proto: Int, p: ByteArray): Verdict {
        if (proto != IPPROTO_TCP) return Verdict.UNKNOWN
        if (p.size < 3) return Verdict.UNKNOWN

        // TLS handshake record: content type 0x16 (Handshake), version major 0x03.
        // The ClientHello handshake type (0x01) sits at offset 5 after the record header.
        if ((p[0].toInt() and 0xff) == 0x16 && (p[1].toInt() and 0xff) == 0x03) {
            if (p.size < 6) return Verdict.TLS // record header alone is a strong TLS signal
            if ((p[5].toInt() and 0xff) == 0x01) return Verdict.TLS
            return Verdict.TLS
        }

        val n = minOf(p.size, 16)
        val ascii = String(p, 0, n, Charsets.US_ASCII)
        if (httpPrefixes.any { ascii.startsWith(it) }) return Verdict.CLEARTEXT_HTTP

        // Mostly-printable ASCII with no TLS marker -> some other cleartext protocol.
        val printable = (0 until n).count { p[it].toInt() and 0xff in 0x09..0x7e }
        if (printable >= (n * 3) / 4) return Verdict.CLEARTEXT_OTHER

        return Verdict.UNKNOWN
    }
}
