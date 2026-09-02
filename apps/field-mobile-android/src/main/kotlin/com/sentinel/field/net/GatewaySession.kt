package com.sentinel.field.net

import com.sentinel.field.security.ClientNonce
import com.sentinel.field.security.DeviceStatements
import com.sentinel.field.security.StrongBoxKeyManager
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

/**
 * ============================================================================
 * WP-25 CONTEXT ESTABLISHMENT, AND THE THREE OPERATION SURFACES.
 *
 * THE CIRCLE, AND HOW THE CEREMONY BREAKS IT
 * ------------------------------------------
 * A `DeviceRequestProof` is bound to a `context_id`, and the evaluator that
 * judges it takes an `AuthenticatedDeviceContext`. Requiring an issued context
 * in order to obtain the FIRST context cannot work. D25-03A breaks it without a
 * bearer bootstrap: the server proposes a context id and a nonce FROM ITS OWN
 * STATE, the device signs a frozen proof whose `payload_digest` is the digest of
 * the EXACT challenge, and the server assembles an in-memory candidate purely so
 * the frozen evaluator has something to judge.
 *
 * The challenge is NOT A SECRET and this client must never treat it as one.
 * Steal `establishment_id`, `proposed_context_id`, the nonce, the device id, the
 * key id, the key version and the site, and you have zero device authority:
 * issuance still needs the private key, which never leaves StrongBox, AND the
 * independent live human session, which no amount of challenge material can
 * manufacture.
 *
 * A FRESH HARDWARE SIGNATURE FOR EVERY EFFECT (D25-01)
 * ----------------------------------------------------
 * Every effect-causing call below mints its OWN proof, with its OWN one-shot
 * nonce, over its OWN payload digest. Nothing is cached, nothing is reused, and
 * there is no method on this class that performs an operation without signing
 * one. A proof replayed verbatim is refused; a proof minted for one purpose,
 * payload or operation is refused for another.
 *
 * THE THREE SURFACES, AND ONLY THREE (D25-10)
 * -------------------------------------------
 * Field state update, assignment ACCEPT/DECLINE, and incident Field message
 * acknowledgement. `start`, `complete`, `cancel` and reassignment are not
 * "refused" by a check somebody could delete — this class has no method, no
 * kind and no route for them, exactly as the server has none.
 * ============================================================================
 */
class GatewaySession(
    private val http: SentinelHttp,
    private val keys: StrongBoxKeyManager,
) {

    companion object {
        private const val GATEWAY = "/api/v1/device-gateway"

        const val KIND_FIELD_STATE_UPDATE = "FIELD_STATE_UPDATE"
        const val KIND_ASSIGNMENT_ACCEPT = "ASSIGNMENT_ACCEPT"
        const val KIND_ASSIGNMENT_DECLINE = "ASSIGNMENT_DECLINE"
        const val KIND_MESSAGE_ACKNOWLEDGE = "INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE"
    }

    /** The challenge, exactly as the server issued it. Every field is the server's. */
    data class EstablishmentChallenge(
        val establishmentId: String,
        val proposedContextId: String,
        val organisationId: String,
        val actorUserId: String,
        val deviceId: String,
        val siteId: String,
        val keyId: String,
        val keyVersion: Int,
        val nonce: String,
        val issuedAt: String,
        val expiresAt: String,
    )

    /**
     * The ISSUED context.
     *
     * A SCOPE STATEMENT, not a credential: holding one says what a device WOULD
     * be entitled to IF the hardware were present AND the operative were the one
     * calling. It may be logged and echoed without conferring anything.
     */
    data class DeviceContext(
        val contextId: String,
        val organisationId: String,
        val actorUserId: String,
        val deviceId: String,
        val authorisedSiteIds: List<String>,
        val deviceTrust: String,
        val keyId: String,
        val keyVersion: Int,
        val issuedAt: String,
        val expiresAt: String,
    )

    // -----------------------------------------------------------------------
    // Step one — a HUMAN SESSION asks for a challenge
    // -----------------------------------------------------------------------

    fun requestEstablishment(
        sessionUserId: String,
        organisationId: String,
        deviceId: String,
        siteId: String,
    ): CeremonyStep<EstablishmentChallenge> {
        val answer = http.post(
            "$GATEWAY/contexts/establishment",
            sessionUserId,
            buildJsonObject {
                put("organisation_id", organisationId)
                put("device_id", deviceId)
                put("site_id", siteId)
            },
        )
        val body = answer.body
        if (!answer.ok || body == null) return CeremonyStep.refused(answer.status, answer.text)
        val challenge = body["challenge"]?.jsonObject
            ?: return CeremonyStep.refused(answer.status, "no challenge in the response")
        return CeremonyStep.ok(
            EstablishmentChallenge(
                establishmentId = challenge.text("establishment_id"),
                proposedContextId = challenge.text("proposed_context_id"),
                organisationId = challenge.text("organisation_id"),
                actorUserId = challenge.text("actor_user_id"),
                deviceId = challenge.text("device_id"),
                siteId = challenge.text("site_id"),
                keyId = challenge.text("key_id"),
                keyVersion = challenge.int("key_version"),
                nonce = challenge.text("nonce"),
                issuedAt = challenge.text("issued_at"),
                expiresAt = challenge.text("expires_at"),
            ),
        )
    }

    // -----------------------------------------------------------------------
    // Step two — the DEVICE signs the digest of the EXACT challenge
    // -----------------------------------------------------------------------

    /**
     * The proof's purpose is `RECONNECT_HANDSHAKE`, because D23-13's handshake
     * obeys the same possession rule as everything else and the purpose enum is
     * an allowlist rather than a free string: a device that could invent its own
     * purpose could sign a statement whose meaning the platform never reviewed.
     *
     * The SAME authenticated human who opened the ceremony submits its answer
     * (C17-01). A perfect proof carried by somebody else's live session is
     * refused, which is why `sessionUserId` is threaded through both steps
     * rather than derived from the challenge.
     */
    fun completeEstablishment(
        sessionUserId: String,
        challenge: EstablishmentChallenge,
    ): CeremonyStep<DeviceContext> {
        val payloadDigest = DeviceStatements.establishmentChallengeDigest(
            establishmentId = challenge.establishmentId,
            proposedContextId = challenge.proposedContextId,
            organisationId = challenge.organisationId,
            actorUserId = challenge.actorUserId,
            deviceId = challenge.deviceId,
            siteId = challenge.siteId,
            keyId = challenge.keyId,
            keyVersion = challenge.keyVersion,
            nonce = challenge.nonce,
            issuedAt = challenge.issuedAt,
            expiresAt = challenge.expiresAt,
        )
        val proof = signProof(
            contextId = challenge.proposedContextId,
            organisationId = challenge.organisationId,
            siteId = challenge.siteId,
            actorUserId = challenge.actorUserId,
            deviceId = challenge.deviceId,
            keyId = challenge.keyId,
            keyVersion = challenge.keyVersion,
            purpose = DeviceStatements.PURPOSE_RECONNECT_HANDSHAKE,
            payloadDigest = payloadDigest,
        )
        val answer = http.post(
            "$GATEWAY/contexts",
            sessionUserId,
            buildJsonObject {
                put("establishment_id", challenge.establishmentId)
                put("proof", proof)
            },
        )
        val body = answer.body
        if (!answer.ok || body == null) return CeremonyStep.refused(answer.status, answer.text)
        val context = body["context"]?.jsonObject
            ?: return CeremonyStep.refused(answer.status, "no context in the response")
        // Read out by name and by type. A site id that is not a JSON string is
        // dropped rather than coerced: this list decides which site the device
        // then signs its operations against.
        val sites = (context["authorised_site_ids"] as? JsonArray)
            ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            ?: emptyList()
        return CeremonyStep.ok(
            DeviceContext(
                contextId = context.text("context_id"),
                organisationId = context.text("organisation_id"),
                actorUserId = context.text("actor_user_id"),
                deviceId = context.text("device_id"),
                authorisedSiteIds = sites,
                deviceTrust = context.text("device_trust"),
                keyId = context.text("key_id"),
                keyVersion = context.int("key_version"),
                issuedAt = context.text("issued_at"),
                expiresAt = context.text("expires_at"),
            ),
        )
    }

    // -----------------------------------------------------------------------
    // A. Field state update — the target is the operative themselves
    // -----------------------------------------------------------------------

    /**
     * There is no target id in the route: it is resolved from the persisted
     * context. A route that took one would be a route through which a device
     * could name whose state it is writing. The client mirrors that by putting
     * the context's own `actor_user_id` in the envelope's `target_id`, which is
     * what the server resolves for itself.
     */
    fun updateFieldState(
        sessionUserId: String,
        context: DeviceContext,
        siteId: String,
        state: String,
        freshnessMs: Int = 0,
    ): CeremonyStep<JsonObject> {
        val sourceAt = ClientNonce.nowIso()
        val payload = linkedMapOf<String, Any?>(
            "state" to state,
            // Telemetry the server does not use as authority. Sent as an
            // explicit null rather than omitted, because the semantic schema is
            // `.strict()` and declares the field as nullable, not optional.
            "location" to null,
            "source_at" to sourceAt,
            "freshness_ms" to freshnessMs,
        )
        val digest = DeviceStatements.operationEnvelopeDigest(
            operationKind = KIND_FIELD_STATE_UPDATE,
            organisationId = context.organisationId,
            siteId = siteId,
            actorUserId = context.actorUserId,
            deviceId = context.deviceId,
            targetId = context.actorUserId,
            semanticPayload = payload,
        )
        val proof = signProof(
            contextId = context.contextId,
            organisationId = context.organisationId,
            siteId = siteId,
            actorUserId = context.actorUserId,
            deviceId = context.deviceId,
            keyId = context.keyId,
            keyVersion = context.keyVersion,
            purpose = DeviceStatements.PURPOSE_FIELD_OPERATION,
            payloadDigest = digest,
        )
        return operate(
            sessionUserId,
            "$GATEWAY/operations/field-state",
            proof,
            buildJsonObject {
                put("state", state)
                put("location", JsonNull)
                put("source_at", sourceAt)
                put("freshness_ms", freshnessMs)
            },
        )
    }

    // -----------------------------------------------------------------------
    // B. Assignment ACCEPT / DECLINE
    // -----------------------------------------------------------------------

    fun actOnAssignment(
        sessionUserId: String,
        context: DeviceContext,
        siteId: String,
        assignmentId: String,
        accept: Boolean,
        expectedStatus: String = "REQUESTED",
    ): CeremonyStep<JsonObject> {
        val kind = if (accept) KIND_ASSIGNMENT_ACCEPT else KIND_ASSIGNMENT_DECLINE
        val route = if (accept) "accept" else "decline"
        val payload = linkedMapOf<String, Any?>("expected_status" to expectedStatus)
        val digest = DeviceStatements.operationEnvelopeDigest(
            operationKind = kind,
            organisationId = context.organisationId,
            siteId = siteId,
            actorUserId = context.actorUserId,
            deviceId = context.deviceId,
            targetId = assignmentId,
            semanticPayload = payload,
        )
        val proof = signProof(
            contextId = context.contextId,
            organisationId = context.organisationId,
            siteId = siteId,
            actorUserId = context.actorUserId,
            deviceId = context.deviceId,
            keyId = context.keyId,
            keyVersion = context.keyVersion,
            purpose = DeviceStatements.PURPOSE_FIELD_OPERATION,
            payloadDigest = digest,
        )
        return operate(
            sessionUserId,
            "$GATEWAY/operations/assignments/$assignmentId/$route",
            proof,
            buildJsonObject { put("expected_status", expectedStatus) },
        )
    }

    // -----------------------------------------------------------------------
    // C. Incident Field Message acknowledgement
    // -----------------------------------------------------------------------

    /**
     * The payload is empty, and that is the honest shape: §76 keeps the device's
     * claim about when it saw something as telemetry, never authority, so there
     * is no `seen_at` here to be mistaken for delivery evidence.
     */
    fun acknowledgeMessage(
        sessionUserId: String,
        context: DeviceContext,
        siteId: String,
        messageId: String,
    ): CeremonyStep<JsonObject> {
        val payload = linkedMapOf<String, Any?>()
        val digest = DeviceStatements.operationEnvelopeDigest(
            operationKind = KIND_MESSAGE_ACKNOWLEDGE,
            organisationId = context.organisationId,
            siteId = siteId,
            actorUserId = context.actorUserId,
            deviceId = context.deviceId,
            targetId = messageId,
            semanticPayload = payload,
        )
        val proof = signProof(
            contextId = context.contextId,
            organisationId = context.organisationId,
            siteId = siteId,
            actorUserId = context.actorUserId,
            deviceId = context.deviceId,
            keyId = context.keyId,
            keyVersion = context.keyVersion,
            purpose = DeviceStatements.PURPOSE_FIELD_OPERATION,
            payloadDigest = digest,
        )
        return operate(
            sessionUserId,
            "$GATEWAY/operations/messages/$messageId/acknowledge",
            proof,
            buildJsonObject { },
        )
    }

    // -----------------------------------------------------------------------
    // The one place a proof is minted, and the one place a body is posted
    // -----------------------------------------------------------------------

    /**
     * Mints a fresh proof and signs it with the hardware key.
     *
     * `nonce` is one-shot; `issued_at` is the device's CLAIM and is judged
     * against the server clock. The statement is built from the SERVER's
     * resolved profile, and the wire field beside the signature is the device's
     * `claimed_signature_profile` — the same string, deliberately named
     * differently, and never derived from one another.
     */
    private fun signProof(
        contextId: String,
        organisationId: String,
        siteId: String,
        actorUserId: String,
        deviceId: String,
        keyId: String,
        keyVersion: Int,
        purpose: String,
        payloadDigest: String,
    ): JsonObject {
        val nonce = ClientNonce.next()
        val issuedAt = ClientNonce.nowIso()
        val statement = DeviceStatements.requestProofStatement(
            contextId = contextId,
            organisationId = organisationId,
            siteId = siteId,
            actorUserId = actorUserId,
            deviceId = deviceId,
            keyId = keyId,
            keyVersion = keyVersion,
            purpose = purpose,
            payloadDigest = payloadDigest,
            nonce = nonce,
            issuedAt = issuedAt,
        )
        val signature = keys.signCanonicalStatement(statement)
        return buildJsonObject {
            put("schema_version", 1)
            put("context_id", contextId)
            put("organisation_id", organisationId)
            put("site_id", siteId)
            put("actor_user_id", actorUserId)
            put("device_id", deviceId)
            put("key_id", keyId)
            put("key_version", keyVersion)
            put("purpose", purpose)
            put("payload_digest", payloadDigest)
            put("nonce", nonce)
            put("issued_at", issuedAt)
            put("claimed_signature_profile", DeviceStatements.SIGNATURE_PROFILE)
            put("signature", signature)
        }
    }

    /**
     * The request body carries the proof and the SEMANTIC payload, and nothing
     * else.
     *
     * C17-06: the server's envelope schema is `.strict()`, so any top-level key
     * the device did not sign is REFUSED rather than silently discarded. This
     * client therefore sends exactly two keys — no `organisation_id`, no
     * `context_id`, no `idempotency_key`, no echoed `operation_kind`. The
     * optional echoes the server permits are omitted because they add nothing
     * and each one is another value that has to keep agreeing.
     */
    private fun operate(
        sessionUserId: String,
        path: String,
        proof: JsonObject,
        payload: JsonObject,
    ): CeremonyStep<JsonObject> {
        val answer = http.post(
            path,
            sessionUserId,
            buildJsonObject {
                put("proof", proof)
                put("payload", payload)
            },
        )
        val body = answer.body
        if (!answer.ok || body == null) return CeremonyStep.refused(answer.status, answer.text)
        return CeremonyStep.ok(body)
    }
}
