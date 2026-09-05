package com.sentinel.field.net

import com.sentinel.field.security.CanonicalJson
import com.sentinel.field.security.CanonicalPublicKey
import com.sentinel.field.security.DeviceStatements
import com.sentinel.field.store.MalformedOutbox
import com.sentinel.field.store.OfflineOutboxEntry
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * ============================================================================
 * THE C14-04 OFFLINE OPERATION ENVELOPE — EXACTLY WHAT THE HARDWARE KEY SIGNS
 * WHEN THERE IS NO NETWORK.
 *
 * This mirrors ONE server-side object literal, field for field, in the same
 * order the server writes it: `deviceOfflineOperationStatementObject` in
 * `packages/contracts/src/device-offline.ts`. It is listed explicitly and never
 * assembled by spreading a parsed response, for the reason `DeviceStatements`
 * gives for its own builders — a field added to a statement must not slip into
 * the signed bytes without somebody deciding it should be there. If the server
 * adds an eighteenth field, this client digest stops matching LOUDLY at the
 * next integration run, instead of quietly signing a different set.
 *
 * THE FIELD THAT MAKES THE WHOLE MODULE WORK
 * ------------------------------------------
 * `policy_lease_id` is inside the signature. The operation therefore NAMES THE
 * AUTHORITY IT ACTED UNDER, and central can judge that lease on its own terms —
 * the issue and expiry instants the SERVER stamped — rather than on the device
 * word about when it acted. Without it the only evidence about the authority in
 * force would be a timestamp the device controls, and a compromised client
 * would simply backdate. `created_at` is signed too, and it is signed as
 * TELEMETRY: the server admissibility evaluator never reads it, so it cannot
 * revive an expired lease however carefully it is chosen.
 *
 * `payload_digest` RATHER THAN THE PAYLOAD. The envelope binds the body without
 * carrying it (D23-14), so an envelope sitting in an audit trail discloses
 * nothing operational. The payload travels beside the envelope and is
 * re-digested on arrival.
 *
 * C15-01 — TWO PROFILE FIELDS, NAMED DIFFERENTLY ON PURPOSE
 * ---------------------------------------------------------
 * The statement carries `signature_profile`, which is the profile the SERVER
 * resolved from its registry key record. The wire envelope carries
 * `claimed_signature_profile`, which is the device CLAIM, and the server
 * equality-binds the claim to its own answer BEFORE the fingerprint is computed
 * or any verifier is reached. `deviceOfflineOperationStatementInput` exists on
 * the server precisely to replace the claim with the server answer, and its type
 * forbids passing an envelope straight through.
 *
 * They are the same string here — `P256_ECDSA_SHA256` is the only approved
 * profile and the only one StrongBox can produce — and they are still never
 * derived from one another. What the device is really doing when it signs is
 * asserting the profile it BELIEVES the registry holds for its key. If that
 * belief is wrong the signature is over bytes the server never reconstructs,
 * and the operation is refused. That is the correct outcome and it is why this
 * client must not, ever, start reading the profile out of its own claim.
 *
 * WP-29A SCOPE. Only `INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE` is in scope. The
 * builders below are general because the envelope is general, but there is no
 * payload builder here for any other kind, and adding one is a work package
 * rather than an afternoon.
 * ============================================================================
 */
object OfflineEnvelope {

    /** Domain separator, distinct from the request-proof and Whisper domains. */
    const val DOMAIN = "sentinel.device.offline-operation.v1"

    const val SCHEMA_VERSION = 1

    /** The one operation kind WP-29A queues. */
    const val KIND_MESSAGE_ACKNOWLEDGE = "INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE"

    /**
     * The semantic payload for a message acknowledgement.
     *
     * `OfflineIncidentMessageAcknowledgePayloadSchema` is `.strict()` and holds
     * exactly one field, so an extra one here is a parse failure rather than an
     * ignored extra. There is deliberately no `seen_at`: §76 keeps the device
     * claim about when it saw something as telemetry, never authority, and a
     * field that looked like delivery evidence would be read as delivery
     * evidence eventually.
     */
    fun acknowledgePayload(messageId: String): Map<String, Any?> =
        linkedMapOf("message_id" to messageId)

    /**
     * SHA-256 hex over the canonical JSON of the semantic payload.
     *
     * `deviceCanonicalDigest` — "the one digest recipe WP-23 uses" — applied to
     * the payload object that travels beside the envelope. The server recomputes
     * it from the payload that ARRIVED and compares; a mismatch is
     * PAYLOAD_DIGEST_MISMATCH, which is what makes the signature cover the body
     * without the envelope having to carry it.
     *
     * It goes through [CanonicalJson] rather than any serialiser, so the bytes
     * digested here are the bytes the contract canonicaliser produces for the
     * same object — the two implementations exist because the phone must produce
     * the server bytes before it can sign them, and they are held together by
     * `CanonicalJsonTest` against fixtures from the contract own algorithm.
     */
    fun payloadDigest(payload: Map<String, Any?>): String =
        CanonicalPublicKey.sha256HexUtf8(CanonicalJson.encode(payload))

    /**
     * EXACTLY what the device signs.
     *
     * Domain-tagged canonical JSON for the C11-01 reason: a delimiter-joined
     * string lets a field containing the delimiter forge a different identity
     * tuple under one signature.
     */
    fun statement(
        offlineOperationId: String,
        organisationId: String,
        siteId: String,
        actorUserId: String,
        deviceId: String,
        keyId: String,
        keyVersion: Int,
        operationKind: String,
        deviceSequence: Long,
        idempotencyKey: String,
        payloadDigest: String,
        policyLeaseId: String,
        nonce: String,
        createdAt: String,
        signatureProfile: String = DeviceStatements.SIGNATURE_PROFILE,
    ): String = CanonicalJson.encode(
        linkedMapOf(
            "domain" to DOMAIN,
            "schema_version" to SCHEMA_VERSION,
            "offline_operation_id" to offlineOperationId,
            "organisation_id" to organisationId,
            "site_id" to siteId,
            "actor_user_id" to actorUserId,
            "device_id" to deviceId,
            "key_id" to keyId,
            "key_version" to keyVersion,
            "operation_kind" to operationKind,
            "device_sequence" to deviceSequence,
            "idempotency_key" to idempotencyKey,
            "payload_digest" to payloadDigest,
            "policy_lease_id" to policyLeaseId,
            "nonce" to nonce,
            "created_at" to createdAt,
            "signature_profile" to signatureProfile,
        ),
    )

    /** The same statement, rebuilt from a queued entry. */
    fun statementFor(entry: OfflineOutboxEntry): String = statement(
        offlineOperationId = entry.offlineOperationId,
        organisationId = entry.organisationId,
        siteId = entry.siteId,
        actorUserId = entry.actorUserId,
        deviceId = entry.deviceId,
        keyId = entry.keyId,
        keyVersion = entry.keyVersion,
        operationKind = entry.operationKind,
        deviceSequence = entry.deviceSequence,
        idempotencyKey = entry.idempotencyKey,
        payloadDigest = entry.payloadDigest,
        policyLeaseId = entry.policyLeaseId,
        nonce = entry.nonce,
        createdAt = entry.createdAt,
    )

    /**
     * The operation identity as a digest — `deviceOfflineOperationFingerprint`.
     *
     * This is what an Edge receipt witnesses and what an audit row records,
     * never the envelope contents. It is also what this client puts in the WP-25
     * request proof `payload_digest` when it submits: the proof then covers the
     * exact envelope it is carrying, so a proof minted for one queued operation
     * cannot be presented with another.
     */
    fun fingerprint(entry: OfflineOutboxEntry): String =
        CanonicalPublicKey.sha256HexUtf8(statementFor(entry))

    /**
     * Builds and SIGNS one queued operation.
     *
     * The signature is made HERE, at enqueue time, with no network anywhere in
     * sight — that is the entire point of the offline path. What is stored is
     * the finished envelope; submission later rebuilds the same bytes from the
     * same stored fields and never re-signs, because re-signing would mean a
     * second signature over a second `created_at` for one act.
     *
     * [signer] is a function rather than the key manager itself, so this whole
     * builder is exercisable on the JVM with a stub signer. The production
     * caller passes `keys::signCanonicalStatement`, which signs in StrongBox and
     * returns the contract wire form.
     *
     * [deviceSequence] is NOT chosen here. `OfflineOutbox.enqueue` allocates it
     * and hands it to this builder, because the sequence is inside the signed
     * bytes and must be the position the queue actually persists.
     *
     * [idempotencyKey] defaults to the operation id, and that default is the
     * right one: the key is inside the signed bytes, so it must be STABLE across
     * every retry of this operation, and the operation id is the one value that
     * is minted once and never changes. It is deliberately not the server
     * downstream key — C10-09 has the executor derive that server-side, so that
     * two queue entries cannot steer unrelated domain calls into one idempotency
     * namespace.
     */
    fun signedEntry(
        offlineOperationId: String,
        organisationId: String,
        siteId: String,
        actorUserId: String,
        deviceId: String,
        keyId: String,
        keyVersion: Int,
        operationKind: String,
        deviceSequence: Long,
        policyLeaseId: String,
        payload: Map<String, Any?>,
        nonce: String,
        createdAt: String,
        idempotencyKey: String = offlineOperationId,
        signer: (String) -> String,
    ): OfflineOutboxEntry {
        val digest = payloadDigest(payload)
        val statement = statement(
            offlineOperationId = offlineOperationId,
            organisationId = organisationId,
            siteId = siteId,
            actorUserId = actorUserId,
            deviceId = deviceId,
            keyId = keyId,
            keyVersion = keyVersion,
            operationKind = operationKind,
            deviceSequence = deviceSequence,
            idempotencyKey = idempotencyKey,
            payloadDigest = digest,
            policyLeaseId = policyLeaseId,
            nonce = nonce,
            createdAt = createdAt,
        )
        return OfflineOutboxEntry(
            offlineOperationId = offlineOperationId,
            organisationId = organisationId,
            siteId = siteId,
            actorUserId = actorUserId,
            deviceId = deviceId,
            keyId = keyId,
            keyVersion = keyVersion,
            operationKind = operationKind,
            deviceSequence = deviceSequence,
            idempotencyKey = idempotencyKey,
            payloadDigest = digest,
            policyLeaseId = policyLeaseId,
            nonce = nonce,
            createdAt = createdAt,
            claimedSignatureProfile = DeviceStatements.SIGNATURE_PROFILE,
            signature = signer(statement),
            // The same canonical text the digest above was taken over. Stored
            // rather than rebuilt, so that what is sent and what was signed
            // cannot drift apart through a map that reordered itself.
            payloadJson = CanonicalJson.encode(payload),
        )
    }

    // -----------------------------------------------------------------------
    // The WP-25 submission: ONE object, digested and posted
    // -----------------------------------------------------------------------

    /**
     * The gateway kind a queued submission travels under.
     *
     * `OFFLINE_QUEUE_SUBMIT` is a GATEWAY kind and is not the same species as
     * [KIND_MESSAGE_ACKNOWLEDGE], which is the FIELD-OFFLINE kind inside the
     * signed envelope. The first says how this REQUEST is authenticated; the
     * second says what the QUEUED STATEMENT does. Confusing the two is easy and
     * expensive, so they are named separately here rather than one being reused
     * for both.
     */
    const val GATEWAY_KIND_OFFLINE_QUEUE_SUBMIT = "OFFLINE_QUEUE_SUBMIT"

    /**
     * The envelope as it goes on the wire: seventeen members, and no others.
     *
     * `DeviceOfflineOperationEnvelopeSchema` is `.strict()`, so any extra
     * top-level key is REFUSED rather than silently discarded — and it should
     * be, because an extra key is a value the device did not sign.
     *
     * Built as a MAP rather than as JSON directly, because this same object has
     * to be canonicalised for the proof digest AND serialised into the body,
     * and two literals drift. See [submission].
     */
    fun envelopeMap(entry: OfflineOutboxEntry): Map<String, Any?> = linkedMapOf(
        "schema_version" to SCHEMA_VERSION,
        "offline_operation_id" to entry.offlineOperationId,
        "organisation_id" to entry.organisationId,
        "site_id" to entry.siteId,
        "actor_user_id" to entry.actorUserId,
        "device_id" to entry.deviceId,
        "key_id" to entry.keyId,
        "key_version" to entry.keyVersion,
        "operation_kind" to entry.operationKind,
        "device_sequence" to entry.deviceSequence,
        "idempotency_key" to entry.idempotencyKey,
        "payload_digest" to entry.payloadDigest,
        "policy_lease_id" to entry.policyLeaseId,
        "nonce" to entry.nonce,
        "created_at" to entry.createdAt,
        "claimed_signature_profile" to entry.claimedSignatureProfile,
        "signature" to entry.signature,
    )

    /**
     * THE WP-25 SEMANTIC PAYLOAD FOR A QUEUED SUBMISSION. Two members, and the
     * split between them is the whole design.
     *
     *   `envelope`  what the device SIGNED while disconnected.
     *   `payload`   what that signature COMMITS TO without carrying (D23-14),
     *               so an envelope retained in an audit trail discloses nothing
     *               operational. The server re-digests it on arrival rather
     *               than believing the digest it was handed.
     *
     * ONE OBJECT, BUILT ONCE. The proof digest is taken over this and the body
     * is serialised from this, so the digest cannot come to cover something
     * other than what was sent. It is the discipline WP-27 applies to the
     * device-action claims map, for the same reason: a drift makes the proof
     * cover bytes nobody transmitted, and what comes back is a signature
     * failure naming nothing anybody can act on.
     *
     * THE PAYLOAD IS RECONSTRUCTED FROM THE STORED CANONICAL TEXT, AND THE
     * RECONSTRUCTION IS CHECKED. `payloadJson` is what the envelope signature
     * commits to through `payload_digest`; reading it back through a JSON parse
     * and a map conversion is two chances to change it. So the round trip is
     * verified — re-encoding the reconstructed map must reproduce the stored
     * text exactly — and a disagreement throws rather than being posted. Left
     * unchecked it would reach the server as PAYLOAD_DIGEST_MISMATCH, which is
     * terminal, and a terminal answer removes the entry: a local conversion bug
     * would silently destroy an operation the operative performed.
     */
    fun submission(entry: OfflineOutboxEntry): Map<String, Any?> {
        val payload = canonicalMapOf(parsePayload(entry))
        if (CanonicalJson.encode(payload) != entry.payloadJson) {
            throw MalformedOutbox(
                "the stored payload for ${entry.offlineOperationId} does not survive a canonical round trip",
            )
        }
        return linkedMapOf(
            "envelope" to envelopeMap(entry),
            "payload" to payload,
        )
    }

    /**
     * `proof.payload_digest` for a queued submission.
     *
     * This is the WP-25 GATEWAY ENVELOPE DIGEST — `deviceGatewayEnvelopeDigest`,
     * domain `sentinel.wp25.device-gateway.operation-envelope.v1` — computed
     * exactly as every other operation on this client computes it, through the
     * single builder in [DeviceStatements]. It is NOT the offline fingerprint.
     *
     * TWO SIGNATURES, TWO PREIMAGES, AND THEY MUST STAY APART.
     * `deviceOfflineOperationFingerprint` ([fingerprint]) is the identity of the
     * QUEUED STATEMENT: it is what the envelope signature is over, what an Edge
     * receipt witnesses, and what an audit row records. This digest is the
     * identity of THIS REQUEST: what the fresh proof attests reached the server
     * intact, right now, from a device that still holds the key. Using either
     * where the other belongs produces a proof over bytes the server never
     * reconstructs, and the refusal names nothing.
     *
     * [organisationId], [actorUserId] and [deviceId] come from the ISSUED
     * CONTEXT and never from the entry — the server rebuilds this same envelope
     * from its own persisted context columns, so a value invented here simply
     * fails to agree. [siteId] is the site the proof is minted for, which is the
     * site the envelope names; the server binds the two and refuses a
     * disagreement rather than preferring one.
     *
     * `target_id` is the QUEUED OPERATION'S OWN ID. Not the operative: a proof
     * targeting the operative would describe any of their queued operations
     * equally well, and a live device could then present one statement beside a
     * proof minted for another.
     */
    fun gatewayPayloadDigest(
        entry: OfflineOutboxEntry,
        organisationId: String,
        siteId: String,
        actorUserId: String,
        deviceId: String,
    ): String = DeviceStatements.operationEnvelopeDigest(
        operationKind = GATEWAY_KIND_OFFLINE_QUEUE_SUBMIT,
        organisationId = organisationId,
        siteId = siteId,
        actorUserId = actorUserId,
        deviceId = deviceId,
        targetId = entry.offlineOperationId,
        semanticPayload = submission(entry),
    )

    /**
     * The same [submission] object, as the JSON body member.
     *
     * Converted FROM the map rather than built beside it, so the bytes posted
     * and the bytes digested are the same object by construction rather than by
     * two authors agreeing.
     */
    fun submissionJson(entry: OfflineOutboxEntry): JsonObject = jsonObjectOf(submission(entry))

    /** The signed envelope alone, as JSON. */
    fun wire(entry: OfflineOutboxEntry): JsonObject = jsonObjectOf(envelopeMap(entry))

    // -----------------------------------------------------------------------
    // The two conversions, both explicit by type, both refusing the rest
    // -----------------------------------------------------------------------

    /**
     * The stored canonical payload text, parsed.
     *
     * A payload that will not parse means the stored queue has been altered
     * underneath this application. That is a [MalformedOutbox] rather than
     * something to send anyway: sending it produces a digest mismatch, which is
     * a refusal, which is terminal, which removes the entry — so continuing
     * quietly would convert a local storage fault into a destroyed operation.
     */
    private fun parsePayload(entry: OfflineOutboxEntry): JsonObject {
        val element = try {
            Json.parseToJsonElement(entry.payloadJson)
        } catch (error: Exception) {
            throw MalformedOutbox("the stored payload for ${entry.offlineOperationId} is not JSON")
        }
        return element as? JsonObject
            ?: throw MalformedOutbox("the stored payload for ${entry.offlineOperationId} is not a JSON object")
    }

    /**
     * JSON to the value types [CanonicalJson] accepts, and NOTHING ELSE.
     *
     * A number is admitted only as a [Long]. There is deliberately no
     * floating-point branch: `CanonicalJson` refuses `Double` permanently
     * because Kotlin number printing does not always agree with V8's, and a
     * converter that quietly produced one here would reintroduce that exact
     * problem one layer up. A fractional value throws.
     *
     * `JsonNull` is matched BEFORE `JsonPrimitive` because it IS one, and its
     * `content` is the four characters `null` — which a reader that reached for
     * `content` directly would turn into the string "null" and then digest.
     */
    internal fun canonicalValueOf(element: JsonElement): Any? = when (element) {
        is JsonNull -> null
        is JsonObject -> canonicalMapOf(element)
        is JsonArray -> element.map { canonicalValueOf(it) }
        is JsonPrimitive -> when {
            element.isString -> element.content
            element.content == "true" -> true
            element.content == "false" -> false
            else -> element.content.toLongOrNull()
                ?: throw MalformedOutbox("a stored payload value has no canonical form: ${element.content}")
        }
        else -> throw MalformedOutbox("a stored payload value has no canonical form")
    }

    /** [canonicalValueOf] for an object, with the insertion order preserved. */
    internal fun canonicalMapOf(value: JsonObject): Map<String, Any?> {
        val out = LinkedHashMap<String, Any?>(value.size)
        for (member in value) out[member.key] = canonicalValueOf(member.value)
        return out
    }

    /**
     * The reverse: a canonical map as JSON, EXPLICIT BY TYPE, throwing on
     * anything else.
     *
     * The `else` branch is the point. The only thing that can go wrong when
     * serialising a map that has already been digested is a value type whose
     * JSON form differs between the canonicaliser and the serialiser, and that
     * branch refuses to let it happen quietly. `Double` has no branch here for
     * the same reason it has none above.
     */
    private fun jsonElementOf(value: Any?): JsonElement = when (value) {
        null -> JsonNull
        is String -> JsonPrimitive(value)
        is Int -> JsonPrimitive(value)
        is Long -> JsonPrimitive(value)
        is Boolean -> JsonPrimitive(value)
        is Map<*, *> -> {
            val out = LinkedHashMap<String, JsonElement>(value.size)
            for (member in value) {
                val key = member.key as? String
                    ?: throw IllegalArgumentException("a submission object has a non-string key")
                out[key] = jsonElementOf(member.value)
            }
            JsonObject(out)
        }
        is List<*> -> JsonArray(value.map { jsonElementOf(it) })
        else -> throw IllegalArgumentException(
            "a submission value has no canonical JSON form: ${value.javaClass.name}",
        )
    }

    private fun jsonObjectOf(value: Map<String, Any?>): JsonObject {
        val element = jsonElementOf(value)
        return element as? JsonObject
            ?: throw IllegalArgumentException("a submission object did not serialise as a JSON object")
    }
}
