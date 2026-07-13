package com.example.tlswatchdog.data

import android.content.Context
import kotlinx.coroutines.flow.Flow

class FlowRepository(context: Context) {
    private val dao = FlowDatabase.get(context).flowDao()

    fun observeAll(): Flow<List<FlowEntity>> = dao.observeAll()
    fun observeOffenders(): Flow<List<FlowEntity>> = dao.observeOffenders()

    suspend fun insert(flow: FlowEntity): Long = dao.insert(flow)
    suspend fun updateStats(id: Long, bytesOut: Long, bytesIn: Long, packets: Int, durationMs: Long) =
        dao.updateStats(id, bytesOut, bytesIn, packets, durationMs)
    suspend fun snapshot(): List<FlowEntity> = dao.snapshot()
    suspend fun clear() = dao.clear()
}
