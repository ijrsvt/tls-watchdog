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
        // Structurally-validated TLS handshake record (not just the first two bytes).
        if (looksLikeTlsHandshake(p)) return Verdict.TLS

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
        return if (looksLikeTlsHandshake(p)) parseSni(p) else parseHttpHost(p)
    }

    /**
     * Detected TLS version of a captured handshake payload, or null if not a TLS handshake.
     * A ClientHello yields the highest **offered** version ("1.3 (offered)"); a ServerHello
     * yields the single **negotiated** version ("1.3"). See [tlsVersion]/[negotiatedTlsVersion].
     */
    fun tlsVersion(proto: Int, p: ByteArray): String? =
        if (proto == IPPROTO_TCP) parseTlsVersion(p) else null

    /** Negotiated version from a ServerHello payload (unqualified, e.g. "1.3"), or null. */
    fun negotiatedTlsVersion(p: ByteArray): String? = parseTlsVersion(p)

    /** True for TLS older than 1.2 (SSL3.0 / TLS 1.0 / TLS 1.1), offered or negotiated. */
    fun isOutdatedTls(v: String?): Boolean =
        v != null && (v.startsWith("1.0") || v.startsWith("1.1") || v.startsWith("SSL3"))

    /**
     * Cheap structural validation of a TLS *handshake record header* — robust to a
     * ClientHello split across TCP segments (the body may be truncated). This is the
     * hardened replacement for the old two-byte check.
     */
    private fun looksLikeTlsHandshake(p: ByteArray): Boolean {
        if (p.size < 6) return false
        if (u(p, 0) != 0x16 || u(p, 1) != 0x03 || u(p, 2) > 0x04) return false // content-type + record version
        val recLen = (u(p, 3) shl 8) or u(p, 4)
        if (recLen < 1 || recLen > 0x4000) return false                        // TLS records are <= 2^14
        val ht = u(p, 5)
        return ht == 0x01 || ht == 0x02                                        // ClientHello or ServerHello
    }

    /** Parsed shape of a TLS ClientHello/ServerHello handshake. */
    private data class TlsHello(
        val handshakeType: Int, // 0x01 ClientHello, 0x02 ServerHello
        val legacyVersion: Int, // e.g. 0x0303
        val extensions: Map<Int, IntRange>, // ext type -> byte range within p
    )

    /**
     * Walk a TLS handshake record and index its extensions; null if not a structurally
     * valid ClientHello/ServerHello. Shared by SNI and version detection. A ServerHello
     * differs only in that cipher_suite / compression are single values, not lists.
     */
    private fun parseHello(p: ByteArray): TlsHello? {
        try {
            if (!looksLikeTlsHandshake(p)) return null
            val ht = u(p, 5)
            var o = 5 + 4 // skip handshake type(1) + length(3)
            if (o + 2 > p.size) return null
            val legacyVersion = (u(p, o) shl 8) or u(p, o + 1)
            o += 2 // client/server version
            o += 32 // random
            if (o >= p.size) return null
            o += 1 + u(p, o) // session_id
            if (ht == 0x01) { // ClientHello: cipher_suites list + compression list
                if (o + 2 > p.size) return null
                o += 2 + ((u(p, o) shl 8) or u(p, o + 1))
                if (o >= p.size) return null
                o += 1 + u(p, o)
            } else { // ServerHello: single cipher_suite(2) + single compression(1)
                o += 3
            }
            if (o + 2 > p.size) return null
            val extEnd = minOf(o + 2 + ((u(p, o) shl 8) or u(p, o + 1)), p.size)
            o += 2
            val exts = HashMap<Int, IntRange>()
            while (o + 4 <= extEnd) {
                val type = (u(p, o) shl 8) or u(p, o + 1)
                val len = (u(p, o + 2) shl 8) or u(p, o + 3)
                o += 4
                if (o + len <= p.size) exts[type] = o until (o + len)
                o += len
            }
            return TlsHello(ht, legacyVersion, exts)
        } catch (e: Exception) {
            return null
        }
    }

    // GREASE values (RFC 8701) are 0x0a0a, 0x1a1a, … 0xfafa: both bytes equal, low nibble 0xa.
    private fun isGrease(v: Int): Boolean =
        (v and 0x0f0f) == 0x0a0a && (v ushr 8) == (v and 0xff)

    /**
     * Version string from a ClientHello (highest offered, suffixed " (offered)") or a
     * ServerHello (the single selected version, unqualified). The real version lives in the
     * supported_versions extension (0x002b); legacy_version is a decoy 0x0303 in TLS 1.3.
     */
    private fun parseTlsVersion(p: ByteArray): String? {
        val hello = parseHello(p) ?: return null
        val ext = hello.extensions[0x002b]
        val server = hello.handshakeType == 0x02
        val chosen: Int = when {
            ext != null && !server -> { // ClientHello: 1-byte list length, then 2-byte versions
                var best = 0
                var i = ext.first + 1
                while (i + 1 <= ext.last) {
                    val v = (u(p, i) shl 8) or u(p, i + 1)
                    if (!isGrease(v) && v > best) best = v
                    i += 2
                }
                if (best != 0) best else hello.legacyVersion
            }
            ext != null && server -> { // ServerHello: single 2-byte selected version
                if (ext.last - ext.first + 1 < 2) hello.legacyVersion
                else (u(p, ext.first) shl 8) or u(p, ext.first + 1)
            }
            else -> hello.legacyVersion
        }
        val name = when (chosen) {
            0x0304 -> "1.3"
            0x0303 -> "1.2"
            0x0302 -> "1.1"
            0x0301 -> "1.0"
            0x0300 -> "SSL3.0"
            else -> return null
        }
        return if (server) name else "$name (offered)"
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
        val hello = parseHello(p) ?: return null
        if (hello.handshakeType != 0x01) return null
        val ext = hello.extensions[0x0000] ?: return null // server_name
        // server_name_list(2) + name_type(1) + name_len(2) + name
        val o = ext.first
        if (o + 5 > p.size) return null
        val nameLen = (u(p, o + 3) shl 8) or u(p, o + 4)
        val start = o + 5
        if (start + nameLen > p.size) return null
        return String(p, start, nameLen, Charsets.US_ASCII)
    }

    private fun u(p: ByteArray, i: Int): Int = p[i].toInt() and 0xff
}
