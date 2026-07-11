package com.example.tlswatchdog.data

import android.content.Context
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
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
}
