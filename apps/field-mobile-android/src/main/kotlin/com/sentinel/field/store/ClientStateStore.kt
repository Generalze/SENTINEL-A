package com.sentinel.field.store

/**
 * ============================================================================
 * SECURE LOCAL STORAGE — THE POLICY HALF.
 *
 * Pure Kotlin over a [KeyValueStore], so that WHAT MAY BE STORED is decided in
 * code the JVM unit tests can execute, not in code only a handset can run. The
 * Android half — the encrypted file this writes into — is
 * [EncryptedClientState], which contains no policy whatsoever.
 *
 * TWO RULES, AND THEY ARE THE WHOLE POINT OF THE CLASS
 * ---------------------------------------------------
 *  1. AN ALLOWLIST OF KEYS. [PERSISTABLE_KEYS] is the complete set of keys this
 *     app may write. There is no public method that accepts a caller-chosen
 *     key, and the private writer re-checks the allowlist anyway, so a future
 *     edit that adds a `remember...` method for something new has to add the
 *     key here — a visible, reviewable act — rather than discovering that an
 *     arbitrary string already worked.
 *
 *  2. ABSENT IS ABSENT. A null or blank value REMOVES its key instead of
 *     writing an empty string. A store that answers `""` to "what site was
 *     this?" is a store that will eventually have `""` compared against a real
 *     site id.
 *
 * WHY THIS IS NOT AN OFFLINE QUEUE. WP-29 owns the queue. There is no method
 * here that stores an operation, a payload, a proof or a retry — the only
 * things this class can hold are the six ids in [ClientState].
 * ============================================================================
 */
class ClientStateStore(private val backing: KeyValueStore) {

    companion object {
        const val KEY_DEVICE_ID = "device_id"
        const val KEY_CONTEXT_ID = "context_id"
        const val KEY_CONTEXT_EXPIRES_AT = "context_expires_at"
        const val KEY_IDENTITY_ORGANISATION_ID = "identity_organisation_id"
        const val KEY_IDENTITY_USER_ID = "identity_user_id"
        const val KEY_IDENTITY_SITE_ID = "identity_site_id"

        /**
         * THE COMPLETE SET OF KEYS THIS APPLICATION MAY PERSIST.
         *
         * `ClientStateStoreTest` asserts that nothing secret-shaped can ever be
         * added to it, by checking every entry against a list of words that
         * name a secret.
         */
        val PERSISTABLE_KEYS: List<String> = listOf(
            KEY_DEVICE_ID,
            KEY_CONTEXT_ID,
            KEY_CONTEXT_EXPIRES_AT,
            KEY_IDENTITY_ORGANISATION_ID,
            KEY_IDENTITY_USER_ID,
            KEY_IDENTITY_SITE_ID,
        )

        /** True when [key] is one this application is permitted to write. */
        fun isPersistableKey(key: String): Boolean = PERSISTABLE_KEYS.contains(key)
    }

    /** Everything currently remembered, with absent keys as nulls. */
    fun read(): ClientState = ClientState(
        deviceId = readOrNull(KEY_DEVICE_ID),
        contextId = readOrNull(KEY_CONTEXT_ID),
        contextExpiresAt = readOrNull(KEY_CONTEXT_EXPIRES_AT),
        organisationId = readOrNull(KEY_IDENTITY_ORGANISATION_ID),
        userId = readOrNull(KEY_IDENTITY_USER_ID),
        siteId = readOrNull(KEY_IDENTITY_SITE_ID),
    )

    /** The device id the SERVER concluded at commit. */
    fun rememberDevice(deviceId: String?) {
        put(KEY_DEVICE_ID, deviceId)
    }

    /**
     * The WP-25 context this client last established, and the expiry the SERVER
     * stamped on it.
     *
     * Recording the expiry lets the UI say "this context has lapsed" without
     * asking, which is the honest thing to render. It is NOT a licence to keep
     * using the context up to that instant: the server re-decides on every
     * single operation, and this value is only ever advisory here.
     */
    fun rememberContext(contextId: String?, expiresAt: String?) {
        put(KEY_CONTEXT_ID, contextId)
        put(KEY_CONTEXT_EXPIRES_AT, expiresAt)
    }

    /** The last identity the SERVER reported for this session. */
    fun rememberIdentity(organisationId: String?, userId: String?, siteId: String?) {
        put(KEY_IDENTITY_ORGANISATION_ID, organisationId)
        put(KEY_IDENTITY_USER_ID, userId)
        put(KEY_IDENTITY_SITE_ID, siteId)
    }

    /** Forgets the context only. The device and the identity survive. */
    fun forgetContext() {
        backing.removeKey(KEY_CONTEXT_ID)
        backing.removeKey(KEY_CONTEXT_EXPIRES_AT)
    }

    /**
     * Forgets everything. Called when the device key is discarded, because a
     * remembered device id whose key no longer exists is a lie the UI would
     * otherwise keep telling.
     */
    fun forgetAll() {
        for (key in PERSISTABLE_KEYS) backing.removeKey(key)
    }

    private fun readOrNull(key: String): String? = backing.readString(key)?.takeIf { it.isNotBlank() }

    /**
     * The ONLY writer. Re-checks the allowlist even though every caller above
     * passes a constant from it, because the cost of the check is nothing and
     * the thing it prevents is a caller-supplied key.
     */
    private fun put(key: String, value: String?) {
        require(isPersistableKey(key)) { "'$key' is not a persistable client-state key" }
        val trimmed = value?.trim()
        if (trimmed.isNullOrEmpty()) {
            backing.removeKey(key)
        } else {
            backing.writeString(key, trimmed)
        }
    }
}
