package com.example.tlswatchdog

import com.example.tlswatchdog.detect.FlowClassifier
import com.example.tlswatchdog.detect.Verdict
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FlowClassifierTest {
    private val TCP = 6
    private val UDP = 17

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
    private fun classify(proto: Int, port: Int, p: ByteArray) = FlowClassifier.classify(proto, port, p)

    @Test fun tlsClientHello_isTls() {
        val p = bytes(0x16, 0x03, 0x01, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x28)
        assertEquals(Verdict.TLS, classify(TCP, 443, p))
    }

    @Test fun httpGet_isCleartext() {
        val p = "GET / HTTP/1.1\r\n".toByteArray(Charsets.US_ASCII)
        assertEquals(Verdict.CLEARTEXT_HTTP, classify(TCP, 80, p))
    }

    @Test fun httpOnPort443_stillCleartext() {
        val p = "POST /login HTTP/1.1\r\n".toByteArray(Charsets.US_ASCII)
        assertEquals(Verdict.CLEARTEXT_HTTP, classify(TCP, 443, p))
    }

    @Test fun binaryNonTls_isUnknown() {
        val p = bytes(0x00, 0x01, 0xff, 0xfe, 0x80, 0x7f, 0x00, 0x00)
        assertEquals(Verdict.UNKNOWN, classify(TCP, 1234, p))
    }

    @Test fun quicInitial_isQuic() {
        // long header (0xc0) + version 0x00000001
        val p = bytes(0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x11, 0x22)
        assertEquals(Verdict.QUIC, classify(UDP, 443, p))
    }

    @Test fun dnsQuery_isDns() {
        // txn id, flags=0x0100 (standard query), qdcount=1
        val p = bytes(0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03)
        assertEquals(Verdict.DNS, classify(UDP, 53, p))
    }

    @Test fun plainUdp_isCleartextUdp() {
        val p = "hello udp world payload".toByteArray(Charsets.US_ASCII)
        assertEquals(Verdict.CLEARTEXT_UDP, classify(UDP, 9999, p))
    }

    @Test fun offenderRules() {
        assertTrue(Verdict.CLEARTEXT_HTTP.isOffender(false))
        assertTrue(!Verdict.TLS.isOffender(true))
        assertTrue(!Verdict.QUIC.isOffender(true))
        // non-QUIC UDP only offends when the flag is on
        assertTrue(!Verdict.CLEARTEXT_UDP.isOffender(false))
        assertTrue(Verdict.CLEARTEXT_UDP.isOffender(true))
        assertTrue(!Verdict.DNS.isOffender(false))
        assertTrue(Verdict.DNS.isOffender(true))
    }

    @Test fun extractHost_httpHostHeader() {
        val p = "GET /x HTTP/1.1\r\nHost: bank.example.com\r\n\r\n".toByteArray(Charsets.US_ASCII)
        assertEquals("bank.example.com", FlowClassifier.extractHost(TCP, p))
    }

    @Test fun extractHost_tlsSni() {
        val p = buildClientHelloWithSni("secure.example.org")
        assertEquals("secure.example.org", FlowClassifier.extractHost(TCP, p))
    }

    @Test fun extractHost_noneForBinary() {
        assertNull(FlowClassifier.extractHost(TCP, bytes(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06)))
    }

    // Builds a minimal but structurally valid TLS ClientHello carrying an SNI.
    private fun buildClientHelloWithSni(host: String): ByteArray {
        val hostBytes = host.toByteArray(Charsets.US_ASCII)
        val body = ArrayList<Int>()
        fun add(vararg v: Int) = v.forEach { body.add(it and 0xff) }
        add(0x03, 0x03) // client_version
        repeat(32) { add(0x00) } // random
        add(0x00) // session_id len
        add(0x00, 0x02, 0x13, 0x01) // cipher_suites len=2 + one suite
        add(0x01, 0x00) // compression: len=1, null
        // extensions
        val ext = ArrayList<Int>()
        val nameLen = hostBytes.size
        val serverNameList = 3 + nameLen // name_type(1)+name_len(2)+name
        ext.add(0x00); ext.add(0x00) // ext type server_name
        ext.add(((serverNameList + 2) ushr 8) and 0xff); ext.add((serverNameList + 2) and 0xff) // ext len
        ext.add((serverNameList ushr 8) and 0xff); ext.add(serverNameList and 0xff) // list len
        ext.add(0x00) // name_type host_name
        ext.add((nameLen ushr 8) and 0xff); ext.add(nameLen and 0xff)
        hostBytes.forEach { ext.add(it.toInt() and 0xff) }
        body.add((ext.size ushr 8) and 0xff); body.add(ext.size and 0xff)
        body.addAll(ext)

        val hs = ArrayList<Int>()
        hs.add(0x01) // ClientHello
        hs.add((body.size ushr 16) and 0xff); hs.add((body.size ushr 8) and 0xff); hs.add(body.size and 0xff)
        hs.addAll(body)

        val rec = ArrayList<Int>()
        rec.add(0x16); rec.add(0x03); rec.add(0x01)
        rec.add((hs.size ushr 8) and 0xff); rec.add(hs.size and 0xff)
        rec.addAll(hs)
        return ByteArray(rec.size) { rec[it].toByte() }
    }

    // --- M-4: hardened detection + TLS version ---

    @Test fun tls12ClientHello_offeredVersion() {
        val p = buildClientHello(0x0303, supportedVersions = null)
        assertEquals(Verdict.TLS, classify(TCP, 443, p))
        assertEquals("1.2 (offered)", FlowClassifier.tlsVersion(TCP, p))
    }

    @Test fun tls13ClientHello_offeredVersionFromExtNotDecoyLegacy() {
        // legacy_version is the 0x0303 decoy; real version is in supported_versions.
        val p = buildClientHello(0x0303, supportedVersions = listOf(0x0304, 0x0303))
        assertEquals(Verdict.TLS, classify(TCP, 443, p))
        assertEquals("1.3 (offered)", FlowClassifier.tlsVersion(TCP, p))
    }

    @Test fun tls13ClientHello_greaseIgnored() {
        val p = buildClientHello(0x0303, supportedVersions = listOf(0x0a0a, 0x0304, 0x0303))
        assertEquals("1.3 (offered)", FlowClassifier.tlsVersion(TCP, p))
    }

    @Test fun tls13ServerHello_negotiatedUnqualified() {
        val p = buildServerHello(0x0303, selectedVersion = 0x0304)
        assertEquals(Verdict.TLS, classify(TCP, 443, p))
        assertEquals("1.3", FlowClassifier.negotiatedTlsVersion(p))
        assertTrue(!FlowClassifier.isOutdatedTls("1.3"))
    }

    @Test fun tls10ServerHello_negotiatedOutdated() {
        val p = buildServerHello(0x0301, selectedVersion = null)
        assertEquals("1.0", FlowClassifier.negotiatedTlsVersion(p))
        assertTrue(FlowClassifier.isOutdatedTls("1.0"))
    }

    @Test fun nonTlsStartingWith1603_isNotTls() {
        // bad record minor (0x7f) — old two-byte check would have said TLS
        assertEquals(Verdict.UNKNOWN, classify(TCP, 1234, bytes(0x16, 0x03, 0x7f, 0xff, 0xff, 0x99, 0x00)))
        // valid record header but handshake type 0x99 (not ClientHello/ServerHello)
        assertEquals(Verdict.UNKNOWN, classify(TCP, 1234, bytes(0x16, 0x03, 0x01, 0x00, 0x05, 0x99, 0x00, 0x00)))
    }

    @Test fun truncatedClientHello_isTlsButNoVersion() {
        val full = buildClientHello(0x0303, supportedVersions = listOf(0x0304))
        val cut = full.copyOfRange(0, 8) // record header + handshake type, body truncated
        assertEquals(Verdict.TLS, classify(TCP, 443, cut))
        assertNull(FlowClassifier.tlsVersion(TCP, cut))
    }

    @Test fun isOutdatedTls_matrix() {
        assertTrue(FlowClassifier.isOutdatedTls("SSL3.0"))
        assertTrue(FlowClassifier.isOutdatedTls("1.1"))
        assertTrue(FlowClassifier.isOutdatedTls("1.0 (offered)"))
        assertTrue(!FlowClassifier.isOutdatedTls("1.2"))
        assertTrue(!FlowClassifier.isOutdatedTls("1.3 (offered)"))
        assertTrue(!FlowClassifier.isOutdatedTls(null))
    }

    // ClientHello with optional supported_versions (0x002b) extension.
    private fun buildClientHello(legacyVersion: Int, supportedVersions: List<Int>?): ByteArray {
        val body = ArrayList<Int>()
        fun add(vararg v: Int) = v.forEach { body.add(it and 0xff) }
        add((legacyVersion ushr 8), legacyVersion) // client_version
        repeat(32) { add(0x00) } // random
        add(0x00) // session_id len
        add(0x00, 0x02, 0x13, 0x01) // cipher_suites len=2 + one suite
        add(0x01, 0x00) // compression: len=1, null
        val ext = ArrayList<Int>()
        if (supportedVersions != null) {
            val listLen = supportedVersions.size * 2 // bytes of the version list
            val extLen = 1 + listLen // 1-byte list length + versions
            ext.add(0x00); ext.add(0x2b) // ext type = supported_versions
            ext.add((extLen ushr 8) and 0xff); ext.add(extLen and 0xff) // ext length
            ext.add(listLen and 0xff) // supported_versions list length (1 byte)
            supportedVersions.forEach { ext.add((it ushr 8) and 0xff); ext.add(it and 0xff) }
        }
        body.add((ext.size ushr 8) and 0xff); body.add(ext.size and 0xff)
        body.addAll(ext)
        return wrapHandshake(0x01, body)
    }

    // ServerHello with optional supported_versions (0x002b) carrying the selected version.
    private fun buildServerHello(legacyVersion: Int, selectedVersion: Int?): ByteArray {
        val body = ArrayList<Int>()
        fun add(vararg v: Int) = v.forEach { body.add(it and 0xff) }
        add((legacyVersion ushr 8), legacyVersion) // server_version
        repeat(32) { add(0x00) } // random
        add(0x00) // session_id len
        add(0x13, 0x01) // selected cipher_suite (single)
        add(0x00) // selected compression (single)
        val ext = ArrayList<Int>()
        if (selectedVersion != null) {
            ext.add(0x00); ext.add(0x2b)
            ext.add(0x00); ext.add(0x02) // ext len 2
            ext.add((selectedVersion ushr 8) and 0xff); ext.add(selectedVersion and 0xff)
        }
        body.add((ext.size ushr 8) and 0xff); body.add(ext.size and 0xff)
        body.addAll(ext)
        return wrapHandshake(0x02, body)
    }

    // Wrap a handshake body (ClientHello/ServerHello) in handshake + TLS record headers.
    private fun wrapHandshake(handshakeType: Int, body: List<Int>): ByteArray {
        val hs = ArrayList<Int>()
        hs.add(handshakeType)
        hs.add((body.size ushr 16) and 0xff); hs.add((body.size ushr 8) and 0xff); hs.add(body.size and 0xff)
        hs.addAll(body)
        val rec = ArrayList<Int>()
        rec.add(0x16); rec.add(0x03); rec.add(0x03)
        rec.add((hs.size ushr 8) and 0xff); rec.add(hs.size and 0xff)
        rec.addAll(hs)
        return ByteArray(rec.size) { rec[it].toByte() }
    }
}
