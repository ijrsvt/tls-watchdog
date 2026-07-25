package com.example.tlswatchdog

import com.example.tlswatchdog.crypto.FlowCrypto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FlowCryptoTest {

    private val appSecret = ByteArray(32) { it.toByte() }
    private val crypto = FlowCrypto(appSecret)
    private val keyId = "11111111-2222-3333-4444-555555555555"

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { ((Character.digit(s[it * 2], 16) shl 4) + Character.digit(s[it * 2 + 1], 16)).toByte() }

    @Test fun hkdf_rfc5869_case1() {
        // RFC 5869 Appendix A.1 (SHA-256) test vector.
        val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val expected = "3cb25f25faacd57a90434f64d0362f2a" +
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
            "34007208d5b887185865"
        val okm = FlowCrypto.hkdf(ikm, salt, info, 42)
        assertEquals(expected, okm.joinToString("") { "%02x".format(it) })
    }

    @Test fun roundTrip() {
        for (plain in listOf("", "hello", "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "x".repeat(5000))) {
            val ct = crypto.encrypt(plain, keyId, "sampleText")!!
            assertNotEquals(plain, ct)
            assertEquals(plain, crypto.decrypt(ct, keyId, "sampleText"))
        }
    }

    @Test fun nullPassesThrough() {
        assertNull(crypto.encrypt(null, keyId, "sampleText"))
        assertNull(crypto.decrypt(null, keyId, "sampleText"))
    }

    @Test fun wrongColumnAad_failsToDecrypt() {
        val ct = crypto.encrypt("secret", keyId, "sampleText")!!
        assertNull(crypto.decrypt(ct, keyId, "responseText")) // AAD mismatch → null, not throw
    }

    @Test fun wrongKeyId_failsToDecrypt() {
        val ct = crypto.encrypt("secret", keyId, "sampleText")!!
        assertNull(crypto.decrypt(ct, "00000000-0000-0000-0000-000000000000", "sampleText"))
    }

    @Test fun tamperedCiphertext_failsToDecrypt() {
        val ct = crypto.encrypt("secret", keyId, "sampleText")!!
        val corrupted = ct.dropLast(2) + if (ct.last() == 'A') "BB" else "AA"
        assertNull(crypto.decrypt(corrupted, keyId, "sampleText"))
    }

    @Test fun ivIsUniquePerEncryption() {
        val a = crypto.encrypt("same", keyId, "sampleText")
        val b = crypto.encrypt("same", keyId, "sampleText")
        assertNotEquals(a, b) // random IV per call → different ciphertext
    }

    @Test fun garbageInput_decryptsToNull() {
        assertNull(crypto.decrypt("not-base64!!", keyId, "sampleText"))
        assertNull(crypto.decrypt("AAAA", keyId, "sampleText")) // too short to hold iv+tag
    }
}
