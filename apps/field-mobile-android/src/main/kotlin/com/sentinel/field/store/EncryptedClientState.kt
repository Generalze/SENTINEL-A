package com.sentinel.field.store

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * ============================================================================
 * SECURE LOCAL STORAGE — THE ANDROID HALF.
 *
 * A thin adapter and NOTHING ELSE. Every rule about what may be stored lives in
 * [ClientStateStore], where the JVM tests can execute it; this file only says
 * WHERE the bytes go.
 *
 * WHY `androidx.security:security-crypto` AND NOT A HAND-ROLLED KEYSTORE WRAP
 * --------------------------------------------------------------------------
 * The alternative — plain `SharedPreferences` with values wrapped by an
 * AndroidKeystore AES/GCM key of our own — would mean this application calling
 * `Cipher.getInstance` and building a second `KeyGenParameterSpec`. Both are
 * things `NoPrivateKeyExportSourceTest` refuses on sight, and for good reason:
 * that test's whole value is that the app has exactly ONE key generation spec
 * and no cipher primitives at all, so a private-key export path cannot be
 * assembled quietly. Hand-rolling storage encryption would have meant
 * weakening that gate to make room for it, which trades a proven property for
 * an unproven one. `EncryptedSharedPreferences` keeps the primitives inside a
 * reviewed library, behind a master key that is itself keystore-held.
 *
 * IT IS AN ALPHA, AND THAT IS ACKNOWLEDGED. `1.1.0-alpha06` is the version
 * everything in the ecosystem actually uses for this class; the 1.0.0 line
 * predates the `MasterKey` API used below. The coordinate is pinned exactly,
 * like every other dependency in this project.
 *
 * WHAT THIS FILE IS NOT: it is not backup-visible (the manifest sets
 * `allowBackup="false"`), and it is not an offline queue. WP-29 owns queueing.
 * ============================================================================
 */
object EncryptedClientState {

    /**
     * The encrypted preference file. One file, one purpose. A second file would
     * be the moment somebody stores "just the form fields" beside it.
     */
    const val FILE_NAME = "sentinel-field-client-state"

    /**
     * Opens the encrypted store.
     *
     * Throws if the platform cannot produce the master key — deliberately NOT
     * caught here and NOT quietly downgraded to plain preferences. A client
     * that fell back to plaintext storage when encryption was unavailable would
     * be a client whose storage guarantee depends on the weather.
     */
    fun open(context: Context): ClientStateStore =
        ClientStateStore(SharedPreferencesKeyValueStore(preferences(context)))

    private fun preferences(context: Context): SharedPreferences {
        val application = context.applicationContext
        val masterKey = MasterKey.Builder(application)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            application,
            FILE_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }
}

/** The adapter. No policy, no key list, no decisions. */
private class SharedPreferencesKeyValueStore(
    private val preferences: SharedPreferences,
) : KeyValueStore {

    override fun readString(key: String): String? = preferences.getString(key, null)

    override fun writeString(key: String, value: String) {
        preferences.edit().putString(key, value).apply()
    }

    override fun removeKey(key: String) {
        preferences.edit().remove(key).apply()
    }
}
