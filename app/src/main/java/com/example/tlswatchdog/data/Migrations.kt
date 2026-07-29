package com.example.tlswatchdog.data

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/**
 * v5 → v6: adds [FlowEntity.tlsVersion] (M-4 TLS version detection) and
 * [FlowEntity.keyId] (M-1 row-level encryption). Both are nullable, so existing
 * rows keep NULL — a NULL keyId marks a legacy plaintext row on read.
 *
 * Deliberately one migration for both column additions (see the plan): never ship
 * two migrations that each claim (5, 6).
 */
val MIGRATION_5_6 = object : Migration(5, 6) {
    override fun migrate(db: SupportSQLiteDatabase) {
        db.execSQL("ALTER TABLE flows ADD COLUMN tlsVersion TEXT")
        db.execSQL("ALTER TABLE flows ADD COLUMN keyId TEXT")
    }
}
