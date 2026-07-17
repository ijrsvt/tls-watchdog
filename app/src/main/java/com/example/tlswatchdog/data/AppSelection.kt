package com.example.tlswatchdog.data

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "app_selection")

/** Persists the set of package names the user wants to monitor. */
object AppSelection {
    private val KEY = stringSetPreferencesKey("monitored_packages")
    private val RECORD_KEY = booleanPreferencesKey("record_cleartext")

    fun observe(context: Context): Flow<Set<String>> =
        context.dataStore.data.map { it[KEY] ?: emptySet() }

    suspend fun get(context: Context): Set<String> = observe(context).first()

    suspend fun set(context: Context, packages: Set<String>) {
        context.dataStore.edit { it[KEY] = packages }
    }

    fun observeRecord(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[RECORD_KEY] ?: false }

    suspend fun getRecord(context: Context): Boolean = observeRecord(context).first()

    suspend fun setRecord(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[RECORD_KEY] = enabled }
    }

    // --- other settings ---
    private val CAP_KEY = intPreferencesKey("record_cap_bytes")
    private val FLAG_UDP_KEY = booleanPreferencesKey("flag_non_quic_udp")
    private val AUTOSTART_KEY = booleanPreferencesKey("auto_start")

    const val DEFAULT_CAP = 64 * 1024
    const val MAX_CAP = 4 * 1024 * 1024

    fun observeCap(context: Context): Flow<Int> =
        context.dataStore.data.map { (it[CAP_KEY] ?: DEFAULT_CAP).coerceIn(1024, MAX_CAP) }

    suspend fun getCap(context: Context): Int = observeCap(context).first()

    suspend fun setCap(context: Context, bytes: Int) {
        context.dataStore.edit { it[CAP_KEY] = bytes.coerceIn(1024, MAX_CAP) }
    }

    fun observeFlagUdp(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[FLAG_UDP_KEY] ?: false }

    suspend fun getFlagUdp(context: Context): Boolean = observeFlagUdp(context).first()

    suspend fun setFlagUdp(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[FLAG_UDP_KEY] = enabled }
    }

    fun observeAutoStart(context: Context): Flow<Boolean> =
        context.dataStore.data.map { it[AUTOSTART_KEY] ?: false }

    suspend fun setAutoStart(context: Context, enabled: Boolean) {
        context.dataStore.edit { it[AUTOSTART_KEY] = enabled }
    }
}
