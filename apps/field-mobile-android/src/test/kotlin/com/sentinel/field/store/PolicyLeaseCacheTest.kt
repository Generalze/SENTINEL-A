package com.sentinel.field.store

import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * THE CACHED POLICY LEASE — WHAT IS STORED, AND WHAT IT IS WORTH.
 *
 * The rules are the sibling's rules, tested the sibling's way: an allowlist of
 * keys that names nothing secret, and absent-is-absent. What is added here is
 * the rule that makes a lease different from an id — A PARTIAL LEASE IS NO
 * LEASE. Eight of nine fields is not a lease with a gap in it; it is not a
 * lease, and answering with one would put a blank site id into a decision about
 * what may be queued.
 *
 * WHAT THIS FILE CANNOT PROVE, AND SAYS SO. It cannot prove that a tampered
 * cache is powerless, because that is a property of the SERVER: it re-resolves
 * the lease by id on arrival and judges the operation against its own record,
 * never against this copy. No test on this side can establish that, and none
 * below pretends to.
 * ============================================================================
 */
class PolicyLeaseCacheTest {

    /** The same forgetful double the sibling test uses, and for the same reason. */
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

    private fun lease(): PolicyLease = PolicyLease(
        leaseId = "lease-1",
        organisationId = "org-1",
        siteId = "site-1",
        deviceId = "device-1",
        actorUserId = "user-1",
        authorityBasisId = "basis-1",
        scope = listOf("INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE"),
        issuedAt = "2026-09-05T08:00:00Z",
        expiresAt = "2026-09-05T14:00:00Z",
    )

    private fun cache(backing: FakeKeyValueStore = FakeKeyValueStore()) =
        backing to PolicyLeaseCache(backing)

    // -----------------------------------------------------------------------
    // The allowlist
    // -----------------------------------------------------------------------

    @Test
    fun `the persistable key allowlist names nothing secret`() {
        val forbidden = listOf("token", "bootstrap", "grant", "secret", "password", "session", "key", "signature")
        for (key in PolicyLeaseCache.PERSISTABLE_KEYS) {
            for (word in forbidden) {
                assertFalse(
                    "'$key' is on the persistable allowlist and names a secret ('$word')",
                    key.lowercase().contains(word),
                )
            }
        }
    }

    @Test
    fun `the allowlist is exactly the nine lease fields and nothing else`() {
        assertEquals(
            listOf(
                "lease_id",
                "lease_organisation_id",
                "lease_site_id",
                "lease_device_id",
                "lease_actor_user_id",
                "lease_authority_basis_id",
                "lease_scope",
                "lease_issued_at",
                "lease_expires_at",
            ),
            PolicyLeaseCache.PERSISTABLE_KEYS,
        )
    }

    @Test
    fun `isPersistableKey refuses anything that is not on the list`() {
        assertTrue(PolicyLeaseCache.isPersistableKey(PolicyLeaseCache.KEY_LEASE_ID))
        assertFalse(PolicyLeaseCache.isPersistableKey("device_id"))
        assertFalse(PolicyLeaseCache.isPersistableKey(""))
        assertFalse(PolicyLeaseCache.isPersistableKey("LEASE_ID"))
    }

    @Test
    fun `remembering a lease writes only allowlisted keys`() {
        val (backing, subject) = cache()
        subject.remember(lease())
        for (key in backing.entries.keys) {
            assertTrue("'$key' was written but is not persistable", PolicyLeaseCache.isPersistableKey(key))
        }
        assertEquals(9, backing.entries.size)
    }

    /**
     * The two stores share one encrypted file and nothing else. Neither can
     * write the other keys, and this pins that they do not collide.
     */
    @Test
    fun `the lease keys do not collide with the client-state keys`() {
        for (key in PolicyLeaseCache.PERSISTABLE_KEYS) {
            assertFalse("'$key' is claimed by both stores", ClientStateStore.isPersistableKey(key))
        }
        for (key in ClientStateStore.PERSISTABLE_KEYS) {
            assertFalse("'$key' is claimed by both stores", PolicyLeaseCache.isPersistableKey(key))
        }
    }

    // -----------------------------------------------------------------------
    // Round trip
    // -----------------------------------------------------------------------

    @Test
    fun `what goes in comes back out`() {
        val (_, subject) = cache()
        subject.remember(lease())
        assertEquals(lease(), subject.read())
    }

    @Test
    fun `a multi-kind scope round trips in order`() {
        val (_, subject) = cache()
        val many = lease().copy(
            scope = listOf("INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE", "FIELD_ASSIGNMENT_ACCEPT"),
        )
        subject.remember(many)
        assertEquals(many.scope, subject.read()!!.scope)
    }

    @Test
    fun `an untouched cache reads back as no lease at all`() {
        val (_, subject) = cache()
        assertNull(subject.read())
    }

    // -----------------------------------------------------------------------
    // Absent is absent, and a partial lease is no lease
    // -----------------------------------------------------------------------

    @Test
    fun `a lease missing any single field reads back as no lease`() {
        for (key in PolicyLeaseCache.PERSISTABLE_KEYS) {
            val (backing, subject) = cache()
            subject.remember(lease())
            backing.entries.remove(key)
            assertNull("removing '$key' must leave no readable lease", subject.read())
        }
    }

    @Test
    fun `a blank value on disk reads back as absent, not as an empty string`() {
        val (backing, subject) = cache()
        subject.remember(lease())
        backing.entries[PolicyLeaseCache.KEY_LEASE_SITE_ID] = "   "
        assertNull(subject.read())
    }

    @Test
    fun `an unreadable scope reads back as no lease rather than as an empty scope`() {
        // An empty scope that reads as "permits nothing" today reads as
        // "permits everything" the first time somebody inverts a condition, so
        // it is never produced from a value this class could not parse.
        for (broken in listOf("not json", "{}", """["ok",7]""", """[]""")) {
            val (backing, subject) = cache()
            subject.remember(lease())
            backing.entries[PolicyLeaseCache.KEY_LEASE_SCOPE] = broken
            assertNull("'$broken' must not produce a lease", subject.read())
        }
    }

    @Test
    fun `forgetting removes every lease key and leaves the rest alone`() {
        val backing = FakeKeyValueStore(mutableMapOf("device_id" to "device-1"))
        val subject = PolicyLeaseCache(backing)
        subject.remember(lease())

        subject.forget()

        assertNull(subject.read())
        assertEquals(mapOf("device_id" to "device-1"), backing.entries.toMap())
    }

    @Test
    fun `remembering a null lease forgets rather than holding a stale copy`() {
        val (backing, subject) = cache()
        subject.remember(lease())
        subject.remember(null)
        assertNull(subject.read())
        assertTrue(backing.entries.isEmpty())
    }

    // -----------------------------------------------------------------------
    // What the cache may decide locally
    // -----------------------------------------------------------------------

    @Test
    fun `the cached scope gates what may be queued`() {
        val subject = lease()
        assertTrue(subject.permits("INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE"))
        assertFalse(subject.permits("FIELD_ASSIGNMENT_ACCEPT"))
        assertFalse(subject.permits(""))
    }

    /**
     * FAIL-CLOSED IN EVERY DIRECTION, and expiry is EXCLUSIVE, exactly as the
     * server judges it. A local "false" is a useful refusal; a local "true" is
     * not evidence of anything.
     */
    @Test
    fun `the local window refuses before issue, at expiry and after it`() {
        val subject = lease()
        assertFalse(subject.looksUsableAt(Instant.parse("2026-09-05T07:59:59Z")))
        assertTrue(subject.looksUsableAt(Instant.parse("2026-09-05T08:00:00Z")))
        assertTrue(subject.looksUsableAt(Instant.parse("2026-09-05T13:59:59Z")))
        assertFalse(subject.looksUsableAt(Instant.parse("2026-09-05T14:00:00Z")))
        assertFalse(subject.looksUsableAt(Instant.parse("2026-09-06T00:00:00Z")))
    }

    @Test
    fun `an unreadable instant is not usable`() {
        val broken = lease().copy(expiresAt = "whenever")
        assertFalse(broken.looksUsableAt(Instant.parse("2026-09-05T10:00:00Z")))
        val brokenIssue = lease().copy(issuedAt = "")
        assertFalse(brokenIssue.looksUsableAt(Instant.parse("2026-09-05T10:00:00Z")))
    }

    @Test
    fun `describe names the lease and invents nothing`() {
        val described = lease().describe()
        assertTrue(described.contains("lease-1"))
        assertTrue(described.contains("user-1"))
        assertTrue(described.contains("basis-1"))
        assertTrue(described.contains("INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE"))
        assertFalse(described.contains("null"))
    }
}
