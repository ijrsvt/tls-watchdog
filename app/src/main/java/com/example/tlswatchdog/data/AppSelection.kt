package com.example.tlswatchdog.data

import android.content.Context
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

    fun observe(context: Context): Flow<Set<String>> =
        context.dataStore.data.map { it[KEY] ?: emptySet() }

    suspend fun get(context: Context): Set<String> = observe(context).first()

    suspend fun set(context: Context, packages: Set<String>) {
        context.dataStore.edit { it[KEY] = packages }
    }
}
