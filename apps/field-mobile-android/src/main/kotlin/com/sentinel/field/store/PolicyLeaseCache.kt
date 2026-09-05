package com.sentinel.field.store

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray

/**
 * ============================================================================
 * THE LOCAL COPY OF THE SERVER-ISSUED POLICY LEASE — THE POLICY HALF.
 *
 * A SIBLING OF [ClientStateStore], NOT AN EXTENSION OF IT, AND THE CHOICE IS
 * DELIBERATE
 * ----------------------------------------------------------------------------
 * `ClientStateStore` holds six ids and its test asserts that the allowlist is
 * EXACTLY those six and nothing else. That assertion is not an obstacle to be
 * edited around; it is the mechanism by which "what this app remembers" stays a
 * short, reviewable list. Widening it to admit nine more keys would have made a
 * standing guarantee weaker in order to make new work fit, which is the one
 * thing a correction batch must never do.
 *
 * So the lease gets its own store, with its own allowlist, obeying the same two
 * rules the sibling states and for the same reasons:
 *
 *   1. AN ALLOWLIST OF KEYS. [PERSISTABLE_KEYS] is the complete set this class
 *      may write; there is no public method that accepts a caller-chosen key,
 *      and the private writer re-checks the allowlist anyway.
 *
 *   2. ABSENT IS ABSENT. A null or blank value REMOVES its key rather than
 *      writing an empty string, and a PARTIAL lease reads back as NO LEASE at
 *      all. A cache that answered with a lease whose `expires_at` was `""`
 *      would eventually have `""` compared against a real instant.
 *
 * WHAT IS CACHED HERE IS NOT AUTHORITY. [PolicyLease] carries that argument in
 * full and it is not repeated here, except for the one sentence that governs
 * every method below: the server RE-RESOLVES the lease by id on arrival and
 * judges the operation against its OWN record, so nothing written through this
 * class can cause central acceptance of anything.
 *
 * It shares the encrypted preference file with the client-state store — see
 * [EncryptedClientState] — because a second protected file is a second thing to
 * get right. They share bytes and share nothing else: each has its own
 * allowlist, and neither can write the other keys.
 * ============================================================================
 */
class PolicyLeaseCache(private val backing: KeyValueStore) {

    companion object {
        const val KEY_LEASE_ID = "lease_id"
        const val KEY_LEASE_ORGANISATION_ID = "lease_organisation_id"
        const val KEY_LEASE_SITE_ID = "lease_site_id"
        const val KEY_LEASE_DEVICE_ID = "lease_device_id"
        const val KEY_LEASE_ACTOR_USER_ID = "lease_actor_user_id"
        const val KEY_LEASE_AUTHORITY_BASIS_ID = "lease_authority_basis_id"
        const val KEY_LEASE_SCOPE = "lease_scope"
        const val KEY_LEASE_ISSUED_AT = "lease_issued_at"
        const val KEY_LEASE_EXPIRES_AT = "lease_expires_at"

        /**
         * THE COMPLETE SET OF KEYS THIS CLASS MAY PERSIST.
         *
         * `PolicyLeaseCacheTest` holds it against the same list of words that
         * name a secret which `ClientStateStoreTest` uses, so a future edit that
         * files something confidential under a lease-shaped name fails the
         * build rather than passing review.
         */
        val PERSISTABLE_KEYS: List<String> = listOf(
            KEY_LEASE_ID,
            KEY_LEASE_ORGANISATION_ID,
            KEY_LEASE_SITE_ID,
            KEY_LEASE_DEVICE_ID,
            KEY_LEASE_ACTOR_USER_ID,
            KEY_LEASE_AUTHORITY_BASIS_ID,
            KEY_LEASE_SCOPE,
            KEY_LEASE_ISSUED_AT,
            KEY_LEASE_EXPIRES_AT,
        )

        /** True when [key] is one this class is permitted to write. */
        fun isPersistableKey(key: String): Boolean = PERSISTABLE_KEYS.contains(key)
    }

    /**
     * The cached lease, or null.
     *
     * NULL WHEN ANYTHING IS MISSING. A lease with eight of its nine parts is not
     * a lease with a gap in it — it is not a lease, and the honest answer is
     * that nothing is cached. Returning a partial one would put a blank site id
     * or an empty scope into a decision about what may be queued, and an empty
     * scope that reads as "permits nothing" today reads as "permits everything"
     * the first time somebody inverts a condition.
     */
    fun read(): PolicyLease? {
        val leaseId = readOrNull(KEY_LEASE_ID) ?: return null
        val organisationId = readOrNull(KEY_LEASE_ORGANISATION_ID) ?: return null
        val siteId = readOrNull(KEY_LEASE_SITE_ID) ?: return null
        val deviceId = readOrNull(KEY_LEASE_DEVICE_ID) ?: return null
        val actorUserId = readOrNull(KEY_LEASE_ACTOR_USER_ID) ?: return null
        val authorityBasisId = readOrNull(KEY_LEASE_AUTHORITY_BASIS_ID) ?: return null
        val issuedAt = readOrNull(KEY_LEASE_ISSUED_AT) ?: return null
        val expiresAt = readOrNull(KEY_LEASE_EXPIRES_AT) ?: return null
        val scope = readScope() ?: return null
        if (scope.isEmpty()) return null
        return PolicyLease(
            leaseId = leaseId,
            organisationId = organisationId,
            siteId = siteId,
            deviceId = deviceId,
            actorUserId = actorUserId,
            authorityBasisId = authorityBasisId,
            scope = scope,
            issuedAt = issuedAt,
            expiresAt = expiresAt,
        )
    }

    /**
     * Replaces the cached copy with the lease the SERVER issued.
     *
     * Every field is written explicitly, in one place, so that a lease gaining a
     * tenth field on the server does not silently half-arrive here. A null lease
     * forgets, which is what a device does when the server declines to issue
     * one: it holds no stale copy to fall back on.
     */
    fun remember(lease: PolicyLease?) {
        if (lease == null) {
            forget()
            return
        }
        put(KEY_LEASE_ID, lease.leaseId)
        put(KEY_LEASE_ORGANISATION_ID, lease.organisationId)
        put(KEY_LEASE_SITE_ID, lease.siteId)
        put(KEY_LEASE_DEVICE_ID, lease.deviceId)
        put(KEY_LEASE_ACTOR_USER_ID, lease.actorUserId)
        put(KEY_LEASE_AUTHORITY_BASIS_ID, lease.authorityBasisId)
        put(KEY_LEASE_SCOPE, encodeScope(lease.scope))
        put(KEY_LEASE_ISSUED_AT, lease.issuedAt)
        put(KEY_LEASE_EXPIRES_AT, lease.expiresAt)
    }

    /**
     * Forgets the cached lease.
     *
     * Removes the keys it owns, one by one — it does not clear the backing file.
     * Anything another part of this app put in the same store is not this class
     * to delete.
     */
    fun forget() {
        for (key in PERSISTABLE_KEYS) backing.removeKey(key)
    }

    private fun readOrNull(key: String): String? = backing.readString(key)?.takeIf { it.isNotBlank() }

    /**
     * The scope, stored as a JSON array of strings.
     *
     * A JSON array rather than a delimiter-joined string, because a delimiter
     * join is a decision about which character can never appear in an operation
     * kind, and that decision is invisible until the day it is wrong. A value
     * that is not an array of strings is NOT partially salvaged: it answers
     * null, the read answers "no lease", and the device queues nothing until the
     * server issues a lease it can read.
     */
    private fun readScope(): List<String>? {
        val text = readOrNull(KEY_LEASE_SCOPE) ?: return null
        val element = try {
            Json.parseToJsonElement(text)
        } catch (error: Exception) {
            return null
        }
        val array = element as? JsonArray ?: return null
        val kinds = ArrayList<String>(array.size)
        for (item in array) {
            val primitive = item as? JsonPrimitive ?: return null
            if (!primitive.isString) return null
            kinds.add(primitive.content)
        }
        return kinds
    }

    private fun encodeScope(scope: List<String>): String =
        buildJsonArray { for (kind in scope) add(JsonPrimitive(kind)) }.toString()

    /**
     * The ONLY writer. Re-checks the allowlist even though every caller above
     * passes a constant from it, because the cost of the check is nothing and
     * the thing it prevents is a caller-supplied key.
     */
    private fun put(key: String, value: String?) {
        require(isPersistableKey(key)) { "'$key' is not a persistable lease key" }
        val trimmed = value?.trim()
        if (trimmed.isNullOrEmpty()) {
            backing.removeKey(key)
        } else {
            backing.writeString(key, trimmed)
        }
    }
}
