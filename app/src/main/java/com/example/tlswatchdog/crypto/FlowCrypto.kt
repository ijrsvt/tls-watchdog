package com.example.tlswatchdog.crypto

import android.content.Context
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Per-row field encryption for captured payloads (M-1).
 *
 * Each row carries a random `keyId` (UUID). The row's key is HKDF-SHA256(appSecret,
 * salt = keyId, info) and each field is sealed with AES-256-GCM under a fresh 96-bit IV,
 * bound to its slot via AAD = "keyId:column". Output is Base64(iv || ciphertext || tag).
 *
 * This class is deliberately free of Android APIs (uses java.util.Base64 + JCA) so it is
 * unit-testable on the local JVM. The Keystore-backed secret comes from [KeyMaster].
 */
class FlowCrypto(private val appSecret: ByteArray) {

    fun encrypt(plain: String?, keyId: String, column: String): String? {
        if (plain == null) return null
        val key = rowKey(keyId)
        val iv = ByteArray(IV_LEN).also { SecureRandom().nextBytes(it) }
        val c = Cipher.getInstance(TRANSFORM)
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BITS, iv))
        c.updateAAD(aad(keyId, column))
        val ct = c.doFinal(plain.toByteArray(Charsets.UTF_8))
        return B64_ENC.encodeToString(iv + ct)
    }

    /** Returns null on any failure (corrupt/tampered ciphertext, wrong slot) — never throws. */
    fun decrypt(b64: String?, keyId: String, column: String): String? {
        if (b64 == null) return null
        return try {
            val raw = B64_DEC.decode(b64)
            if (raw.size <= IV_LEN) return null
            val iv = raw.copyOfRange(0, IV_LEN)
            val ct = raw.copyOfRange(IV_LEN, raw.size)
            val c = Cipher.getInstance(TRANSFORM)
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(rowKey(keyId), "AES"), GCMParameterSpec(TAG_BITS, iv))
            c.updateAAD(aad(keyId, column))
            String(c.doFinal(ct), Charsets.UTF_8)
        } catch (e: Exception) {
            null
        }
    }

    private fun aad(keyId: String, column: String) = "$keyId:$column".toByteArray(Charsets.UTF_8)

    private fun rowKey(keyId: String): ByteArray =
        hkdf(appSecret, keyId.toByteArray(Charsets.UTF_8), INFO, KEY_LEN)

    companion object {
        private const val TRANSFORM = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128
        private const val IV_LEN = 12
        private const val KEY_LEN = 32
        private val INFO = "tls-watchdog-row-v1".toByteArray(Charsets.UTF_8)
        private val B64_ENC = Base64.getEncoder()
        private val B64_DEC = Base64.getDecoder()

        @Volatile
        private var instance: FlowCrypto? = null

        fun get(context: Context): FlowCrypto =
            instance ?: synchronized(this) {
                instance ?: FlowCrypto(KeyMaster.appSecret(context.applicationContext)).also { instance = it }
            }

        /** RFC 5869 HKDF over HMAC-SHA256 (extract + expand). */
        fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
            val prk = hmac(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
            val out = ByteArray(length)
            var t = ByteArray(0)
            var pos = 0
            var counter = 1
            while (pos < length) {
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(prk, "HmacSHA256"))
                mac.update(t)
                mac.update(info)
                mac.update(counter.toByte())
                t = mac.doFinal()
                val n = minOf(t.size, length - pos)
                System.arraycopy(t, 0, out, pos, n)
                pos += n
                counter++
            }
            return out
        }

        private fun hmac(key: ByteArray, data: ByteArray): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(key, "HmacSHA256"))
            return mac.doFinal(data)
        }
    }
}
