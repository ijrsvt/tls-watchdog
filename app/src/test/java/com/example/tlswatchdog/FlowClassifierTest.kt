package com.example.tlswatchdog

import com.example.tlswatchdog.detect.FlowClassifier
import com.example.tlswatchdog.detect.Verdict
import org.junit.Assert.assertEquals
import org.junit.Test

class FlowClassifierTest {
    private val TCP = 6
    private val UDP = 17

    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    @Test
    fun tlsClientHello_isTls() {
        // 0x16 (Handshake) 0x03 0x01 (len) .. 0x01 (ClientHello) ...
        val p = bytes(0x16, 0x03, 0x01, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x28)
        assertEquals(Verdict.TLS, FlowClassifier.classify(TCP, p))
    }

    @Test
    fun tls13RecordVersion_isTls() {
        val p = bytes(0x16, 0x03, 0x03, 0x00, 0x50, 0x01)
        assertEquals(Verdict.TLS, FlowClassifier.classify(TCP, p))
    }

    @Test
    fun httpGet_isCleartext() {
        val p = "GET / HTTP/1.1\r\n".toByteArray(Charsets.US_ASCII)
        assertEquals(Verdict.CLEARTEXT_HTTP, FlowClassifier.classify(TCP, p))
    }

    @Test
    fun httpPost_isCleartext() {
        val p = "POST /login HTTP/1.1\r\n".toByteArray(Charsets.US_ASCII)
        assertEquals(Verdict.CLEARTEXT_HTTP, FlowClassifier.classify(TCP, p))
    }

    @Test
    fun binaryNonTls_isUnknown() {
        val p = bytes(0x00, 0x01, 0xff, 0xfe, 0x80, 0x7f, 0x00, 0x00)
        assertEquals(Verdict.UNKNOWN, FlowClassifier.classify(TCP, p))
    }

    @Test
    fun plainTextNonHttp_isCleartextOther() {
        val p = "USER anonymous\r\n".toByteArray(Charsets.US_ASCII)
        assertEquals(Verdict.CLEARTEXT_OTHER, FlowClassifier.classify(TCP, p))
    }

    @Test
    fun tooShort_isUnknown() {
        assertEquals(Verdict.UNKNOWN, FlowClassifier.classify(TCP, bytes(0x16)))
    }

    @Test
    fun udp_isUnknown() {
        val p = bytes(0x16, 0x03, 0x01, 0x00, 0x2c, 0x01)
        assertEquals(Verdict.UNKNOWN, FlowClassifier.classify(UDP, p))
    }
}
