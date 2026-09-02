package com.sentinel.field.store

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * WHAT SECURE LOCAL STORAGE STORES, AND WHAT IT REFUSES TO STORE.
 *
 * `ClientStateStore` is pure Kotlin over a `KeyValueStore` for exactly this
 * reason: the RULES about what may be persisted are the part worth testing, and
 * they can be executed on the JVM. The Android half — the encrypted file the
 * bytes actually land in — is `EncryptedClientState`, which holds no policy and
 * can only be exercised on a device.
 *
 * SO BE CLEAR ABOUT WHAT THIS FILE PROVES AND WHAT IT DOES NOT. It proves the
 * key allowlist, the absent-is-absent rule and the forget semantics. It proves
 * NOTHING about whether the bytes are encrypted at rest — that is
 * `EncryptedSharedPreferences`' property, established on real hardware, and no
 * JVM test can stand in for it.
 * ============================================================================
 */
class ClientStateStoreTest {

    /**
     * The test double. Deliberately lives here and not in the main sources: a
     * forgetful store that looked like a persistent one is exactly the thing
     * that must never be reachable from the app.
     */
    private class FakeKeyValueStore(
        val entries: MutableMap<String, String> = linkedMapOf(),
    ) : KeyValueStore {
        override fun readString(key: String): String? = entries[key]

        override fun writeString(key: String, value: String) {
            entries[key] = value
        }

        override fun removeKey(key: String) {
            entries.remove(key)
        }
    }

    private fun store(backing: FakeKeyValueStore = FakeKeyValueStore()) =
        backing to ClientStateStore(backing)

    // -----------------------------------------------------------------------
    // The allowlist
    // -----------------------------------------------------------------------

    @Test
    fun `the persistable key allowlist names nothing secret`() {
        val forbidden = listOf("token", "bootstrap", "grant", "secret", "password", "session", "key", "signature")
        for (key in ClientStateStore.PERSISTABLE_KEYS) {
            for (word in forbidden) {
                assertFalse(
                    "'$key' is on the persistable allowlist and names a secret ('$word')",
                    key.lowercase().contains(word),
                )
            }
        }
    }

    @Test
    fun `the allowlist is exactly the six client-state ids and nothing else`() {
        assertEquals(
            listOf(
                "device_id",
                "context_id",
                "context_expires_at",
                "identity_organisation_id",
                "identity_user_id",
                "identity_site_id",
            ),
            ClientStateStore.PERSISTABLE_KEYS,
        )
    }

    @Test
    fun `isPersistableKey refuses anything that is not on the list`() {
        assertTrue(ClientStateStore.isPersistableKey(ClientStateStore.KEY_DEVICE_ID))
        assertFalse(ClientStateStore.isPersistableKey("bootstrap_token"))
        assertFalse(ClientStateStore.isPersistableKey("session"))
        assertFalse(ClientStateStore.isPersistableKey(""))
        assertFalse(ClientStateStore.isPersistableKey("DEVICE_ID"))
    }

    @Test
    fun `every public mutation writes only allowlisted keys`() {
        val (backing, subject) = store()
        subject.rememberDevice("device-1")
        subject.rememberContext("context-1", "2026-01-01T00:00:00.000Z")
        subject.rememberIdentity("org-1", "user-1", "site-1")
        for (key in backing.entries.keys) {
            assertTrue("'$key' was written but is not persistable", ClientStateStore.isPersistableKey(key))
        }
        assertEquals(6, backing.entries.size)
    }

    // -----------------------------------------------------------------------
    // Round trip
    // -----------------------------------------------------------------------

    @Test
    fun `what goes in comes back out`() {
        val (_, subject) = store()
        subject.rememberDevice("device-1")
        subject.rememberContext("context-1", "2026-01-01T00:00:00.000Z")
        subject.rememberIdentity("org-1", "user-1", "site-1")
        assertEquals(
            ClientState(
                deviceId = "device-1",
                contextId = "context-1",
                contextExpiresAt = "2026-01-01T00:00:00.000Z",
                organisationId = "org-1",
                userId = "user-1",
                siteId = "site-1",
            ),
            subject.read(),
        )
    }

    @Test
    fun `an untouched store reads back empty`() {
        val (_, subject) = store()
        val state = subject.read()
        assertTrue(state.isEmpty)
        assertNull(state.deviceId)
        assertTrue(state.describe().contains("nothing yet"))
    }

    @Test
    fun `values are trimmed on the way in`() {
        val (backing, subject) = store()
        subject.rememberDevice("  device-1  ")
        assertEquals("device-1", backing.entries[ClientStateStore.KEY_DEVICE_ID])
    }

    // -----------------------------------------------------------------------
    // Absent is absent
    // -----------------------------------------------------------------------

    @Test
    fun `a null value removes the key rather than storing an empty string`() {
        val (backing, subject) = store()
        subject.rememberDevice("device-1")
        subject.rememberDevice(null)
        assertFalse(backing.entries.containsKey(ClientStateStore.KEY_DEVICE_ID))
        assertNull(subject.read().deviceId)
    }

    @Test
    fun `a blank value removes the key rather than storing whitespace`() {
        val (backing, subject) = store()
        subject.rememberIdentity("org-1", "user-1", "   ")
        assertFalse(backing.entries.containsKey(ClientStateStore.KEY_IDENTITY_SITE_ID))
        assertEquals("org-1", subject.read().organisationId)
        assertNull(subject.read().siteId)
    }

    @Test
    fun `a blank value already on disk reads back as null, not as an empty string`() {
        val backing = FakeKeyValueStore(mutableMapOf(ClientStateStore.KEY_DEVICE_ID to "   "))
        assertNull(ClientStateStore(backing).read().deviceId)
    }

    // -----------------------------------------------------------------------
    // Forgetting
    // -----------------------------------------------------------------------

    @Test
    fun `forgetContext drops the context and keeps the device and the identity`() {
        val (_, subject) = store()
        subject.rememberDevice("device-1")
        subject.rememberContext("context-1", "2026-01-01T00:00:00.000Z")
        subject.rememberIdentity("org-1", "user-1", "site-1")

        subject.forgetContext()

        val state = subject.read()
        assertNull(state.contextId)
        assertNull(state.contextExpiresAt)
        assertEquals("device-1", state.deviceId)
        assertEquals("user-1", state.userId)
    }

    @Test
    fun `forgetAll removes every persistable key`() {
        val (backing, subject) = store()
        subject.rememberDevice("device-1")
        subject.rememberContext("context-1", "2026-01-01T00:00:00.000Z")
        subject.rememberIdentity("org-1", "user-1", "site-1")

        subject.forgetAll()

        assertTrue(subject.read().isEmpty)
        assertTrue(backing.entries.isEmpty())
    }

    /**
     * `forgetAll` removes the keys it owns, one by one — it does NOT clear the
     * whole backing file. Anything another part of the platform put in the same
     * store is not this class's to delete.
     */
    @Test
    fun `forgetAll leaves a key this store does not own alone`() {
        val backing = FakeKeyValueStore(mutableMapOf("someone_elses_key" to "value"))
        val subject = ClientStateStore(backing)
        subject.rememberDevice("device-1")

        subject.forgetAll()

        assertEquals(mapOf("someone_elses_key" to "value"), backing.entries.toMap())
    }

    // -----------------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------------

    @Test
    fun `describe names every remembered value and invents none`() {
        val (_, subject) = store()
        subject.rememberDevice("device-1")
        subject.rememberContext("context-1", "2026-01-01T00:00:00.000Z")
        val described = subject.read().describe()
        assertTrue(described.contains("device-1"))
        assertTrue(described.contains("context-1"))
        assertTrue(described.contains("2026-01-01T00:00:00.000Z"))
        assertFalse(described.contains("null"))
    }
}
