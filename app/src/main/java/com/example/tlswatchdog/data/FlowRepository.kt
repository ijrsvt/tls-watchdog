package com.example.tlswatchdog.data

import android.content.Context
import com.example.tlswatchdog.crypto.FlowCrypto
import kotlinx.coroutines.flow.Flow

/**
 * Crypto boundary for the flow store (M-1). Sensitive payload fields are encrypted on the
 * way in and decrypted lazily on the way out — only [decryptDetail] decrypts, and it is
 * called just for a single row shown in the detail view or during CSV export, never for the
 * live 2000-row list (which reads cleartext metadata only).
 */
class FlowRepository(context: Context) {
    private val dao = FlowDatabase.get(context).flowDao()
    private val crypto = FlowCrypto.get(context)

    fun observeAll(): Flow<List<FlowEntity>> = dao.observeAll()
    fun observeOffenders(): Flow<List<FlowEntity>> = dao.observeOffenders()

    /** Encrypts the sensitive fields using the entity's keyId (set by the caller). */
    suspend fun insert(flow: FlowEntity): Long {
        val keyId = flow.keyId ?: return dao.insert(flow) // legacy path: shouldn't happen for new rows
        return dao.insert(
            flow.copy(
                firstBytesHex = crypto.encrypt(flow.firstBytesHex, keyId, "firstBytesHex") ?: flow.firstBytesHex,
                sampleText = crypto.encrypt(flow.sampleText, keyId, "sampleText"),
                responseText = crypto.encrypt(flow.responseText, keyId, "responseText"),
            ),
        )
    }

    suspend fun updateStats(
        id: Long,
        keyId: String?,
        bytesOut: Long,
        bytesIn: Long,
        packets: Int,
        durationMs: Long,
        sampleText: String?,
        responseText: String?,
    ) = dao.updateStats(
        id, bytesOut, bytesIn, packets, durationMs,
        keyId?.let { crypto.encrypt(sampleText, it, "sampleText") } ?: sampleText,
        keyId?.let { crypto.encrypt(responseText, it, "responseText") } ?: responseText,
    )

    /** Update the detected TLS version, optionally promoting the row to an offender (old TLS). */
    suspend fun updateTlsVersion(id: Long, tlsVersion: String?, markOffender: Boolean) {
        dao.updateTlsVersion(id, tlsVersion)
        if (markOffender) dao.markOffender(id)
    }

    /** Decrypt the sensitive fields of a single row for display/export. */
    fun decryptDetail(f: FlowEntity): FlowEntity {
        val keyId = f.keyId ?: return f // legacy plaintext row
        return f.copy(
            firstBytesHex = crypto.decrypt(f.firstBytesHex, keyId, "firstBytesHex") ?: f.firstBytesHex,
            sampleText = crypto.decrypt(f.sampleText, keyId, "sampleText"),
            responseText = crypto.decrypt(f.responseText, keyId, "responseText"),
        )
    }

    suspend fun snapshot(): List<FlowEntity> = dao.snapshot()
    suspend fun clear() = dao.clear()
}
