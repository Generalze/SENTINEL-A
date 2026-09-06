package com.sentinel.field.store

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * ============================================================================
 * ONE QUEUED OPERATION, AS IT SITS ON DISK BETWEEN BEING SIGNED AND BEING
 * ACCEPTED.
 *
 * Sixteen of the fields below are the C14-04 offline envelope, field for field:
 * they are the values the hardware key SIGNED, at the moment the operative
 * pressed the button, with no network in sight. They are immutable for the life
 * of the entry, because changing any one of them after the fact would leave a
 * signature over bytes that no longer exist — and the server verifies the bytes,
 * not the intention.
 *
 * Four are LOCAL ONLY. [payloadJson] is the semantic payload this device
 * digested — it travels, but BESIDE the envelope, never inside it — and
 * [attemptCount], [lastAttemptAt] and [state] are this client's own record of
 * what it has tried. None of them is signed and none of them is authority.
 *
 * WHAT MAY NEVER APPEAR IN THIS CLASS, AND WHY IT IS SAID HERE
 * -----------------------------------------------------------
 * NO private key material. NO bearer credential. NO session credential. NO
 * enrollment grant. A queue entry is the one structure in this application that
 * is written to disk and SURVIVES — across a restart, across a shift change,
 * across a lost handset — so it is exactly the structure into which somebody
 * would eventually be tempted to tuck "the thing we need in order to send it
 * later". There is nothing to tuck: the signature is already made, the human
 * session is typed in each time it is needed, and the private half of the
 * device key never leaves StrongBox. `OfflineOutboxEntryTest` holds
 * [PERSISTED_FIELDS] against a list of words that name a secret, exactly as
 * `ClientStateStoreTest` holds the client-state allowlist, so adding one fails
 * the build.
 *
 * The names `key_id`, `signature` and `nonce` DO appear, and they are not
 * exceptions to that rule. A key id NAMES a registered key and confers nothing;
 * a signature is the public output the server verifies; a nonce is a one-shot
 * freshness value the SERVER scopes and spends. All three are already on the
 * wire in clear. The rule is about secrets, not about the word "key".
 *
 * WHY THE JSON IS WRITTEN BY HAND RATHER THAN BY `@Serializable`
 * -------------------------------------------------------------
 * The serialization compiler plugin IS applied to this project, so the
 * annotation would work. It is not used, for two reasons and the first is
 * decisive: `NoPrivateKeyExportSourceTest` refuses the substring `Serializable`
 * in EVERY main source file, because Java serialisation is one of the ways key
 * material leaves a process, and the gate does not — and should not — try to
 * tell one `Serializable` from another. Weakening that scan to admit an
 * annotation would trade a proven property for a convenience.
 *
 * The second is that generated codec is a codec nobody reads. The mapping below
 * is the exact list of what reaches disk, in one place, beside the fields it
 * writes, and the reader refuses rather than defaults — which is the behaviour
 * a generated one would have to be configured into anyway.
 * ============================================================================
 */
data class OfflineOutboxEntry(
    /** The operation identity. A uuid, minted once, never regenerated on retry. */
    val offlineOperationId: String,
    val organisationId: String,
    val siteId: String,
    /** Part of the replay identity: one device, many shifts (C14-02). */
    val actorUserId: String,
    val deviceId: String,
    val keyId: String,
    val keyVersion: Int,
    val operationKind: String,
    /**
     * The per-device queue position. CONTIGUOUS, allocated by [OfflineOutbox]
     * and never chosen by a caller — see that class for why this is the single
     * most important value in the file.
     */
    val deviceSequence: Long,
    val idempotencyKey: String,
    val payloadDigest: String,
    /**
     * C14-04. The authority this operation claims to have acted under, INSIDE
     * the signed bytes, so the operation names the lease rather than resting on
     * a timestamp this device controls.
     */
    val policyLeaseId: String,
    val nonce: String,
    /**
     * CLIENT TELEMETRY, and nothing else (C10-06 / D23-12). It is signed, so it
     * cannot be altered in transit, and it is never authority: it cannot revive
     * an expired lease, backdate a transition or extend a window. The server
     * admissibility evaluator never reads it at all.
     */
    val createdAt: String,
    /**
     * C15-01. The non-authoritative CLAIM about this device profile, which the
     * server equality-binds to the profile on its registry key record before any
     * verifier is reachable. It is deliberately a DIFFERENT field from the
     * `signature_profile` inside the signed statement, and this client must
     * never derive one from the other.
     */
    val claimedSignatureProfile: String,
    /** IEEE P1363 `r || s`, unpadded base64url, low-S. The output, not a secret. */
    val signature: String,
    /**
     * The semantic payload as CANONICAL JSON TEXT — the exact bytes
     * [payloadDigest] was taken over.
     *
     * Stored as text rather than as a parsed structure, so that what is
     * re-digested on arrival cannot differ from what was digested here because
     * some intermediate map reordered its keys on the way through.
     */
    val payloadJson: String,
    /** Local only. How many times this entry has been handed to the transport. */
    val attemptCount: Int = 0,
    /** Local only. ISO-8601 UTC, or null when it has never been attempted. */
    val lastAttemptAt: String? = null,
    /** Local only. See [OfflineEntryState]. */
    val state: OfflineEntryState = OfflineEntryState.QUEUED,
) {

    /** True when the server has answered TERMINALLY about this exact envelope. */
    val isTerminal: Boolean
        get() = state == OfflineEntryState.TERMINAL

    /**
     * A one-line rendering for the log.
     *
     * Every field named here is already on the wire in clear and none of them
     * authorises anything on its own. The PAYLOAD is deliberately not printed:
     * it is operational content, and a log is not a need-to-know boundary.
     */
    fun describe(): String =
        "$offlineOperationId  seq=$deviceSequence  $operationKind  $state  " +
            "attempts=$attemptCount  last=${lastAttemptAt ?: "-"}  site=$siteId  lease=$policyLeaseId"

    fun toJson(): JsonObject = buildJsonObject {
        put(FIELD_OFFLINE_OPERATION_ID, offlineOperationId)
        put(FIELD_ORGANISATION_ID, organisationId)
        put(FIELD_SITE_ID, siteId)
        put(FIELD_ACTOR_USER_ID, actorUserId)
        put(FIELD_DEVICE_ID, deviceId)
        put(FIELD_KEY_ID, keyId)
        put(FIELD_KEY_VERSION, keyVersion)
        put(FIELD_OPERATION_KIND, operationKind)
        put(FIELD_DEVICE_SEQUENCE, deviceSequence)
        put(FIELD_IDEMPOTENCY_KEY, idempotencyKey)
        put(FIELD_PAYLOAD_DIGEST, payloadDigest)
        put(FIELD_POLICY_LEASE_ID, policyLeaseId)
        put(FIELD_NONCE, nonce)
        put(FIELD_CREATED_AT, createdAt)
        put(FIELD_CLAIMED_SIGNATURE_PROFILE, claimedSignatureProfile)
        put(FIELD_SIGNATURE, signature)
        put(FIELD_PAYLOAD_JSON, payloadJson)
        put(FIELD_ATTEMPT_COUNT, attemptCount)
        put(FIELD_LAST_ATTEMPT_AT, lastAttemptAt)
        put(FIELD_STATE, state.name)
    }

    companion object {

        const val FIELD_OFFLINE_OPERATION_ID = "offline_operation_id"
        const val FIELD_ORGANISATION_ID = "organisation_id"
        const val FIELD_SITE_ID = "site_id"
        const val FIELD_ACTOR_USER_ID = "actor_user_id"
        const val FIELD_DEVICE_ID = "device_id"
        const val FIELD_KEY_ID = "key_id"
        const val FIELD_KEY_VERSION = "key_version"
        const val FIELD_OPERATION_KIND = "operation_kind"
        const val FIELD_DEVICE_SEQUENCE = "device_sequence"
        const val FIELD_IDEMPOTENCY_KEY = "idempotency_key"
        const val FIELD_PAYLOAD_DIGEST = "payload_digest"
        const val FIELD_POLICY_LEASE_ID = "policy_lease_id"
        const val FIELD_NONCE = "nonce"
        const val FIELD_CREATED_AT = "created_at"
        const val FIELD_CLAIMED_SIGNATURE_PROFILE = "claimed_signature_profile"
        const val FIELD_SIGNATURE = "signature"

        /**
         * The local-only fields carry a `local_` prefix, so that no reader on
         * either side can mistake one for a value that was signed.
         */
        const val FIELD_PAYLOAD_JSON = "local_payload_json"
        const val FIELD_ATTEMPT_COUNT = "local_attempt_count"
        const val FIELD_LAST_ATTEMPT_AT = "local_last_attempt_at"
        const val FIELD_STATE = "local_state"

        /**
         * Every field this class persists, in the order it is written.
         *
         * Named as data rather than discovered by reflection, so that the test
         * can hold the list against a forbidden-word check the same way
         * `ClientStateStoreTest` holds the key allowlist: adding a field means
         * adding a name here, which is a visible, reviewable act.
         */
        val PERSISTED_FIELDS: List<String> = listOf(
            FIELD_OFFLINE_OPERATION_ID,
            FIELD_ORGANISATION_ID,
            FIELD_SITE_ID,
            FIELD_ACTOR_USER_ID,
            FIELD_DEVICE_ID,
            FIELD_KEY_ID,
            FIELD_KEY_VERSION,
            FIELD_OPERATION_KIND,
            FIELD_DEVICE_SEQUENCE,
            FIELD_IDEMPOTENCY_KEY,
            FIELD_PAYLOAD_DIGEST,
            FIELD_POLICY_LEASE_ID,
            FIELD_NONCE,
            FIELD_CREATED_AT,
            FIELD_CLAIMED_SIGNATURE_PROFILE,
            FIELD_SIGNATURE,
            FIELD_PAYLOAD_JSON,
            FIELD_ATTEMPT_COUNT,
            FIELD_LAST_ATTEMPT_AT,
            FIELD_STATE,
        )

        /**
         * Reads one entry back, BY NAME AND BY TYPE.
         *
         * Anything missing, null or of the wrong shape is a [MalformedOutbox]
         * and never a default. A reader that answered `0` for an unreadable
         * `device_sequence` would hand the transport an envelope whose signature
         * covers a different position, and the refusal that came back would name
         * nothing anybody could act on.
         */
        fun fromJson(value: JsonObject): OfflineOutboxEntry = OfflineOutboxEntry(
            offlineOperationId = value.requiredString(FIELD_OFFLINE_OPERATION_ID),
            organisationId = value.requiredString(FIELD_ORGANISATION_ID),
            siteId = value.requiredString(FIELD_SITE_ID),
            actorUserId = value.requiredString(FIELD_ACTOR_USER_ID),
            deviceId = value.requiredString(FIELD_DEVICE_ID),
            keyId = value.requiredString(FIELD_KEY_ID),
            keyVersion = value.requiredLong(FIELD_KEY_VERSION).toInt(),
            operationKind = value.requiredString(FIELD_OPERATION_KIND),
            deviceSequence = value.requiredLong(FIELD_DEVICE_SEQUENCE),
            idempotencyKey = value.requiredString(FIELD_IDEMPOTENCY_KEY),
            payloadDigest = value.requiredString(FIELD_PAYLOAD_DIGEST),
            policyLeaseId = value.requiredString(FIELD_POLICY_LEASE_ID),
            nonce = value.requiredString(FIELD_NONCE),
            createdAt = value.requiredString(FIELD_CREATED_AT),
            claimedSignatureProfile = value.requiredString(FIELD_CLAIMED_SIGNATURE_PROFILE),
            signature = value.requiredString(FIELD_SIGNATURE),
            payloadJson = value.requiredString(FIELD_PAYLOAD_JSON),
            attemptCount = value.requiredLong(FIELD_ATTEMPT_COUNT).toInt(),
            lastAttemptAt = value.optionalString(FIELD_LAST_ATTEMPT_AT),
            state = OfflineEntryState.parse(value.requiredString(FIELD_STATE)),
        )
    }
}

/**
 * The two states a queued operation can be in, and there are only two.
 *
 *   QUEUED     the server has not answered terminally about this envelope. It
 *              is eligible for submission, and it MUST NOT be discarded however
 *              many attempts have failed.
 *
 *   TERMINAL   the server answered terminally — a final receipt, or an
 *              authoritative refusal — so this entry is finished and will never
 *              be sent again. It is recorded BEFORE the entry is removed, so a
 *              crash in the gap leaves an entry that is skipped rather than one
 *              that is re-sent.
 *
 * There is deliberately no FAILED, no EXPIRED and no ABANDONED. Each of those
 * would be a state in which this client decided, on its own, that an operation
 * the operative actually performed is not going to happen — and this client is
 * not in a position to decide that. Only the server ends a queued operation.
 */
enum class OfflineEntryState {
    QUEUED,
    TERMINAL;

    companion object {
        /** Refuses an unknown state rather than defaulting it to QUEUED. */
        fun parse(name: String): OfflineEntryState = when (name) {
            QUEUED.name -> QUEUED
            TERMINAL.name -> TERMINAL
            else -> throw MalformedOutbox("'$name' is not an outbox entry state")
        }
    }
}

/**
 * The by-name readers, kept in this package rather than borrowed from `net`.
 *
 * The storage layer must not acquire a dependency on the network layer: the two
 * fail for different reasons, and a shared reader would eventually be tuned to
 * suit whichever of them complained most recently.
 */
internal fun JsonObject.requiredString(key: String): String {
    val primitive = this[key] as? JsonPrimitive
        ?: throw MalformedOutbox("the stored queue has no readable '$key'")
    if (!primitive.isString) throw MalformedOutbox("the stored '$key' is not a JSON string")
    return primitive.content
}

/** A JSON null or an absent field is ABSENT. It is never the four characters `null`. */
internal fun JsonObject.optionalString(key: String): String? {
    val primitive = this[key] as? JsonPrimitive ?: return null
    if (!primitive.isString) return null
    return primitive.content
}

internal fun JsonObject.requiredLong(key: String): Long {
    val primitive = this[key] as? JsonPrimitive
        ?: throw MalformedOutbox("the stored queue has no readable '$key'")
    if (primitive.isString) throw MalformedOutbox("the stored '$key' is a string, not a number")
    return primitive.content.toLongOrNull()
        ?: throw MalformedOutbox("the stored '$key' is not an integer")
}
