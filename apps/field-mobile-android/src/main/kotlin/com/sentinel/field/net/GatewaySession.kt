package com.sentinel.field.net

import com.sentinel.field.security.CanonicalJson
import com.sentinel.field.security.ClientNonce
import com.sentinel.field.security.DeviceActionStatements
import com.sentinel.field.security.DeviceStatements
import com.sentinel.field.security.StrongBoxKeyManager
import java.math.BigDecimal
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

        /** WP-27. The fourth surface, and the only one whose payload is itself signed. */
        const val KIND_DEVICE_ACTION = "DEVICE_ACTION"

        /**
         * The server's own "I cannot yet say what your submission produced".
         *
         * Named here, as `EnrollmentCeremony` names its own, so that the one
         * status this client must NOT read as a refusal is a constant somebody
         * has to delete on purpose rather than a magic number in a comparison.
         */
        private const val COMPLETION_UNKNOWN = 409
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
    // D. WP-27 — the M3 device-action statement
    // -----------------------------------------------------------------------

    /**
     * TWO SIGNATURES, OVER TWO DIFFERENT THINGS, AND THAT IS THE POINT.
     *
     * Every other operation on this class signs ONE thing: a request proof whose
     * `payload_digest` covers the gateway envelope. A device action signs that
     * too — nothing about the WP-25 pipeline is relaxed here — and it ALSO signs
     * the v2 device-action statement itself, which is the artefact the platform
     * keeps. The proof authenticates the REQUEST; the statement authenticates
     * the CLAIM, survives the request, and is what a later audit reads.
     *
     * THE ORDER MATTERS AND IS NOT INTERCHANGEABLE. The statement is signed
     * first, because its signature is a FIELD OF THE CLAIMS; the claims are the
     * envelope's semantic payload; the envelope's digest is what the proof
     * covers. So the proof transitively covers the statement signature, and a
     * statement lifted out of one request cannot be replayed inside another
     * without the proof failing.
     *
     * THERE IS NO TARGET ID IN THE ROUTE, and none is sent. The server resolves
     * it from the persisted context — the operative themselves — exactly as the
     * field-state route does. THE WHISPER SIGNAL IS NOT IN THE ROUTE EITHER: it
     * is a signed claim inside the payload, so it binds cryptographically
     * without appearing in a URL or an access log. W21-14 — on a covert channel
     * that is the difference between a discreet configuration and a published
     * one, and a client that "helpfully" put the signal id in the path would
     * undo it from this side.
     *
     * WHAT THIS CLIENT DOES NOT NAME. No algorithm, no profile, no curve, no
     * digest, no public key travels in the payload. `signature_profile` appears
     * in the bytes that are SIGNED, because the server puts it there; it appears
     * in no field this method sends. The claims schema is `.strict()`, so a
     * profile field would be a parse failure rather than an ignored extra.
     *
     * THIS IS NOT WHISPER RECOGNITION AND DOES NOT CLAIM TO BE. This client
     * resolves no signal, consults no roster and compares no threshold. What it
     * produces is a hardware-signed statement that a registered device made this
     * exact claim, freshly, inside a server-issued context.
     */
    fun submitDeviceAction(
        sessionUserId: String,
        context: DeviceContext,
        siteId: String,
        whisperSignalId: String,
        whisperSignalVersion: Int,
        deviceActionId: String,
        confidenceHundredths: Int,
    ): CeremonyStep<JsonObject> {
        // Both are CLIENT-MINTED and neither is authority. `recognised_at` is
        // judged against the server clock; the nonce is one-shot and the SERVER
        // decides the identity it is spent against (D23-12).
        val recognisedAt = ClientNonce.nowIso()
        val antiReplayNonce = ClientNonce.next()

        // The identity fields come from the ISSUED context, never from the UI:
        // the server rebuilds the same statement from its own persisted columns,
        // so a value invented here would simply fail to verify.
        val statement = DeviceActionStatements.statement(
            contextId = context.contextId,
            organisationId = context.organisationId,
            siteId = siteId,
            actorUserId = context.actorUserId,
            deviceId = context.deviceId,
            keyId = context.keyId,
            keyVersion = context.keyVersion,
            whisperSignalId = whisperSignalId,
            whisperSignalVersion = whisperSignalVersion,
            deviceActionId = deviceActionId,
            recognisedAt = recognisedAt,
            confidenceHundredths = confidenceHundredths,
            antiReplayNonce = antiReplayNonce,
        )
        val statementSignature = keys.signCanonicalStatement(statement)

        // ONE map, built once: the digest below and the body posted at the end
        // are the same object. Two literals drift, and a drift here would let
        // the proof cover something other than what was sent.
        val claims = DeviceActionStatements.claims(
            keyId = context.keyId,
            keyVersion = context.keyVersion,
            whisperSignalId = whisperSignalId,
            whisperSignalVersion = whisperSignalVersion,
            deviceActionId = deviceActionId,
            recognisedAt = recognisedAt,
            confidenceHundredths = confidenceHundredths,
            antiReplayNonce = antiReplayNonce,
            signature = statementSignature,
        )
        val digest = DeviceStatements.operationEnvelopeDigest(
            operationKind = KIND_DEVICE_ACTION,
            organisationId = context.organisationId,
            siteId = siteId,
            actorUserId = context.actorUserId,
            deviceId = context.deviceId,
            targetId = context.actorUserId,
            semanticPayload = claims,
        )
        val proof = signProof(
            contextId = context.contextId,
            organisationId = context.organisationId,
            siteId = siteId,
            actorUserId = context.actorUserId,
            deviceId = context.deviceId,
            keyId = context.keyId,
            keyVersion = context.keyVersion,
            // NOT `FIELD_OPERATION`. The route selects `WHISPER_DEVICE_ACTION`,
            // whose permitted trust is `['TRUSTED']` alone, and the purpose is
            // inside the signed proof.
            purpose = DeviceStatements.PURPOSE_WHISPER_DEVICE_ACTION,
            payloadDigest = digest,
        )
        return submitUnprovable(
            sessionUserId,
            "$GATEWAY/operations/device-action",
            proof,
            jsonPayload(claims),
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

    /**
     * C18-R1, applied to the ONE operation whose submission spends a one-shot
     * identity the client cannot re-mint.
     *
     * The three surfaces above are idempotent enough to treat every non-2xx as
     * terminal: press the button again and the same field state, the same
     * accept or the same acknowledgement is sent. A DEVICE ACTION IS NOT LIKE
     * THAT. Its `anti_replay_nonce` is one-shot, and the server may have
     * consumed it and committed while the answer was lost — so "the network
     * failed" and "the server refused" are DIFFERENT facts here, and collapsing
     * them would have this client report a refusal for an action that happened.
     *
     * So only an AUTHORITATIVE 4xx that is not the server's own `409` is
     * terminal. A transport failure (status 0), a 5xx, the `409`, and a 2xx
     * whose body cannot be read as JSON are all UNPROVEN, and this client says
     * so instead of guessing. Retrying an unproven submission mints a NEW nonce
     * and a NEW statement, which the server will judge on its own merits — it is
     * a fresh claim, not a replay of the lost one.
     */
    private fun submitUnprovable(
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
        if (answer.ok && body != null) return CeremonyStep.ok(body)
        val terminal = answer.status in 400..499 && answer.status != COMPLETION_UNKNOWN
        if (terminal) return CeremonyStep.refused(answer.status, answer.text)
        return CeremonyStep.completionUnknown(answer.status, answer.text)
    }

    /**
     * The canonical semantic payload, as the JSON body that carries it.
     *
     * EXPLICIT, BY TYPE, AND IT THROWS ON ANYTHING ELSE. The map this converts
     * is the same map the envelope digest was taken over, so the only thing
     * that could go wrong is a value type whose JSON form differs between the
     * canonicaliser and the serialiser — which is exactly what the `else`
     * branch refuses to let happen quietly.
     *
     * `CanonicalJson.JsonNumber` goes through `BigDecimal` rather than a
     * `Double`, so the digits on the wire are the digits that were signed. A
     * `Double` here would re-enter the number-printing problem the
     * canonicaliser exists to avoid.
     */
    private fun jsonPayload(payload: Map<String, Any?>): JsonObject = buildJsonObject {
        for (entry in payload) {
            val value = entry.value
            when (value) {
                null -> put(entry.key, JsonNull)
                is String -> put(entry.key, JsonPrimitive(value))
                is Int -> put(entry.key, JsonPrimitive(value))
                is Boolean -> put(entry.key, JsonPrimitive(value))
                is CanonicalJson.JsonNumber -> put(entry.key, JsonPrimitive(BigDecimal(value.text)))
                else -> throw IllegalArgumentException(
                    "a semantic payload value has no canonical JSON form: ${entry.key}",
                )
            }
        }
    }
}
