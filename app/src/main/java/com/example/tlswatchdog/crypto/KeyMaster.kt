package com.example.tlswatchdog.crypto

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Owns the app's master secret used to derive per-row encryption keys (M-1).
 *
 * A non-exportable AES-256-GCM key in the Android Keystore ("flow-master") never leaves
 * the TEE, so it cannot itself feed HKDF. Instead it *wraps* a random 32-byte appSecret,
 * which is stored (already GCM-sealed) in ordinary prefs and unwrapped into memory once.
 * FlowCrypto runs HKDF over that appSecret.
 *
 * setUserAuthenticationRequired(false): capture writes rows on a background thread with
 * no unlocked-auth window, so requiring auth would break encryption while the device is
 * locked — exactly when capture is busiest. Trade-off documented in the plan.
 */
object KeyMaster {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val MASTER_ALIAS = "flow-master"
    private const val PREFS = "flow-crypto"
    private const val PREF_SECRET = "app_secret_v1"
    private const val GCM_TAG_BITS = 128
    private const val IV_LEN = 12
    private const val SECRET_LEN = 32

    @Volatile
    private var cached: ByteArray? = null

    /** Load (or first-run generate) the 32-byte app secret. Cached for the process. */
    fun appSecret(context: Context): ByteArray {
        cached?.let { return it }
        synchronized(this) {
            cached?.let { return it }
            val prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val stored = prefs.getString(PREF_SECRET, null)
            val secret = if (stored != null) {
                unwrap(Base64.getDecoder().decode(stored))
            } else {
                ByteArray(SECRET_LEN).also { SecureRandom().nextBytes(it) }.also { fresh ->
                    prefs.edit().putString(PREF_SECRET, Base64.getEncoder().encodeToString(wrap(fresh))).apply()
                }
            }
            cached = secret
            return secret
        }
    }

    private fun masterKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getEntry(MASTER_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        gen.init(
            KeyGenParameterSpec.Builder(
                MASTER_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return gen.generateKey()
    }

    /** iv(12) || GCM(appSecret) under the Keystore master key. */
    private fun wrap(secret: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, masterKey())
        val ct = c.doFinal(secret)
        return c.iv + ct
    }

    private fun unwrap(blob: ByteArray): ByteArray {
        val iv = blob.copyOfRange(0, IV_LEN)
        val ct = blob.copyOfRange(IV_LEN, blob.size)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, masterKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return c.doFinal(ct)
    }
}
