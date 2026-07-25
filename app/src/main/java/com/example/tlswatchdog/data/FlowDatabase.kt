package com.example.tlswatchdog.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

// exportSchema = true writes the schema JSON (see room.schemaLocation in build.gradle)
// so migrations can be authored. No destructive fallback: a schema change must ship a
// real Migration rather than silently wiping recorded history.
@Database(entities = [FlowEntity::class], version = 6, exportSchema = true)
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
                ).addMigrations(MIGRATION_5_6).build().also { instance = it }
            }
    }
}
