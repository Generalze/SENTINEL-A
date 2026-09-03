package com.sentinel.field.store

/**
 * ============================================================================
 * THE ONE WAY ANYTHING IN THIS APP REACHES DISK.
 *
 * A three-method interface over a string key/value backing store. It exists so
 * that the RULES about what may be persisted live in pure Kotlin — where the
 * JVM unit tests can reach them — while the Android binding
 * ([com.sentinel.field.store.EncryptedClientState]) stays a thin adapter with
 * no policy in it at all.
 *
 * There is deliberately no `clear()`, no bulk `writeAll(Map)`, and no method
 * that takes a caller-supplied key without [ClientStateStore] having vetted it
 * first. A bulk write is the shape through which "just persist the form state"
 * ends up persisting the bootstrap grant token.
 * ============================================================================
 */
interface KeyValueStore {

    /** The stored value for [key], or null when nothing is stored under it. */
    fun readString(key: String): String?

    /** Stores [value] under [key], replacing anything already there. */
    fun writeString(key: String, value: String)

    /** Removes [key]. Removing an absent key is not an error. */
    fun removeKey(key: String)
}
