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
    val proto: Int,
    val verdict: String,
    val isOffender: Boolean,
    val firstBytesHex: String,
)
