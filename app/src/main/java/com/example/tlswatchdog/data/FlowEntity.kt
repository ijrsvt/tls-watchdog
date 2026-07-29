package com.example.tlswatchdog.data

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "flows")
data class FlowEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val timestamp: Long,
    val uid: Int,
    val packageName: String?,
    val appLabel: String?,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int,
    val host: String? = null,
    val proto: Int,
    val verdict: String,
    val isOffender: Boolean,
    /** Negotiated TLS version ("1.3", "1.2", …) or offered ("1.3 (offered)"); null when not TLS. */
    val tlsVersion: String? = null,
    /**
     * Per-row key id (a UUID) used to derive this row's encryption key. Null for rows
     * written before encryption existed (legacy plaintext) — see FlowCrypto/FlowRepository.
     */
    val keyId: String? = null,
    /** AES-GCM ciphertext (Base64) when [keyId] != null; plaintext hex for legacy rows. */
    val firstBytesHex: String,
    /** Encrypted printable preview of the cleartext request; null unless recording was on. */
    val sampleText: String? = null,
    /** Encrypted printable preview of the cleartext response; null unless recording was on. */
    val responseText: String? = null,
    // Lifetime stats, filled in when the connection closes.
    val bytesOut: Long = 0,
    val bytesIn: Long = 0,
    val packets: Int = 0,
    val durationMs: Long = 0,
)
