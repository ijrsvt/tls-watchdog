package com.example.tlswatchdog.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Dao
interface FlowDao {
    @Insert
    suspend fun insert(flow: FlowEntity): Long

    @Query(
        "UPDATE flows SET bytesOut = :bytesOut, bytesIn = :bytesIn, " +
            "packets = :packets, durationMs = :durationMs, " +
            "sampleText = :sampleText, responseText = :responseText WHERE id = :id",
    )
    suspend fun updateStats(
        id: Long,
        bytesOut: Long,
        bytesIn: Long,
        packets: Int,
        durationMs: Long,
        sampleText: String?,
        responseText: String?,
    )

    @Query("SELECT * FROM flows ORDER BY timestamp DESC LIMIT 2000")
    fun observeAll(): Flow<List<FlowEntity>>

    @Query("SELECT * FROM flows WHERE isOffender = 1 ORDER BY timestamp DESC LIMIT 2000")
    fun observeOffenders(): Flow<List<FlowEntity>>

    @Query("SELECT * FROM flows ORDER BY timestamp DESC")
    suspend fun snapshot(): List<FlowEntity>

    @Query("DELETE FROM flows")
    suspend fun clear()
}
