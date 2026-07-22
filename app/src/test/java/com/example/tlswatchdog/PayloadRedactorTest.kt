package com.example.tlswatchdog

import com.example.tlswatchdog.util.PayloadRedactor
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PayloadRedactorTest {

    @Test fun redactsAuthorizationHeader() {
        val req = "GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer sk-secret-123\r\n\r\n"
        val out = PayloadRedactor.redactText(req)
        assertFalse(out.contains("sk-secret-123"))
        assertTrue(out.contains("Authorization: [REDACTED]"))
        // Non-sensitive headers are preserved.
        assertTrue(out.contains("Host: example.com"))
    }

    @Test fun redactsCookieAndSetCookie() {
        val req = "GET / HTTP/1.1\r\nCookie: session=abc123; theme=dark\r\n\r\n"
        val resp = "HTTP/1.1 200 OK\r\nSet-Cookie: session=xyz789; HttpOnly\r\n\r\n"
        assertFalse(PayloadRedactor.redactText(req).contains("abc123"))
        assertFalse(PayloadRedactor.redactText(resp).contains("xyz789"))
    }

    @Test fun caseInsensitiveHeaderNames() {
        val req = "GET / HTTP/1.1\r\ncookie: session=abc123\r\n\r\n"
        assertFalse(PayloadRedactor.redactText(req).contains("abc123"))
    }

    @Test fun leavesNonHttpTextUntouched() {
        val s = "just some plain text with the word authorization in it"
        assertEquals(s, PayloadRedactor.redactText(s))
    }

    @Test fun binaryBytesRoundTripUnchanged() {
        // A TLS ClientHello-like prefix must never be mangled by redaction.
        val tls = byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x2c, 0x01, 0x00, 0x00, 0x28, 0xff.toByte(), 0x00)
        assertTrue(PayloadRedactor.redactBytes(tls).contentEquals(tls))
    }

    @Test fun redactBytesMasksHttpCredential() {
        val req = "GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"
            .toByteArray(Charsets.ISO_8859_1)
        val out = String(PayloadRedactor.redactBytes(req), Charsets.ISO_8859_1)
        assertFalse(out.contains("dXNlcjpwYXNz"))
    }
}
