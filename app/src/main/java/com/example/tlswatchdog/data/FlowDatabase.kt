package com.example.tlswatchdog.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(entities = [FlowEntity::class], version = 1, exportSchema = false)
abstract class FlowDatabase : RoomDatabase() {
    abstract fun flowDao(): FlowDao

    companion object {
        @Volatile
        private var instance: FlowDatabase? = null

        fun get(context: Context): FlowDatabase =
            instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    FlowDatabase::class.java,
                    "flows.db",
                ).build().also { instance = it }
            }
    }
}
