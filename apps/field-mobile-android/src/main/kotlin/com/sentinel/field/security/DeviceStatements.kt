package com.sentinel.field.security

/**
 * ============================================================================
 * EXACTLY WHAT THE HARDWARE KEY SIGNS — the client half of four frozen
 * statements.
 *
 * Every builder below mirrors ONE server-side object literal, field for field,
 * in the same file order the server writes them. They are listed explicitly and
 * never assembled by spreading a parsed response, for the reason the contract
 * gives for its own builders: a field added to a statement must not slip into
 * the signed bytes without somebody deciding it should be there. If the server
 * adds a thirteenth field to the establishment challenge, this client's digest
 * stops matching — LOUDLY, at the next integration run — instead of quietly
 * signing a different set.
 *
 * The four statements, and where each is defined:
 *
 *   POSSESSION           `canonicalDevicePossessionStatement`
 *                        packages/contracts/src/device-identity.ts
 *                        domain: sentinel.device.possession-challenge.v1
 *
 *   REQUEST PROOF        `canonicalDeviceRequestProofStatement`
 *                        packages/contracts/src/device-context.ts
 *                        domain: sentinel.device.request-proof.v1
 *
 *   ESTABLISHMENT        `deviceContextEstablishmentChallengeDigest`
 *   CHALLENGE            services/core-api/.../device-context.challenge.ts
 *                        domain: sentinel.wp25.device-gateway.establishment-challenge.v1
 *
 *   OPERATION ENVELOPE   `deviceGatewayEnvelopeDigest`
 *                        services/core-api/.../device-gateway.envelope.ts
 *                        domain: sentinel.wp25.device-gateway.operation-envelope.v1
 *
 * THE PROFILE FIELD IS THE SERVER'S, NOT A CHOICE (C15-01)
 * -------------------------------------------------------
 * `signature_profile` inside a signed statement is the profile the SERVER
 * resolved from its registry key record. `claimed_signature_profile`, the field
 * that travels on the wire beside the signature, is the device's CLAIM and is
 * equality-bound to the server's before any verifier is reachable. They are the
 * same string here — `P256_ECDSA_SHA256` is the only approved profile and the
 * only one StrongBox can produce — but they are named differently on purpose,
 * and this client must never start deriving one from the other.
 * ============================================================================
 */
object DeviceStatements {

    /** The only approved profile. An allowlist with one member is still an allowlist. */
    const val SIGNATURE_PROFILE = "P256_ECDSA_SHA256"

    const val POSSESSION_DOMAIN = "sentinel.device.possession-challenge.v1"
    const val REQUEST_PROOF_DOMAIN = "sentinel.device.request-proof.v1"
    const val ESTABLISHMENT_CHALLENGE_DOMAIN = "sentinel.wp25.device-gateway.establishment-challenge.v1"
    const val OPERATION_ENVELOPE_DOMAIN = "sentinel.wp25.device-gateway.operation-envelope.v1"

    /** The gateway purposes this client mints proofs for. Nothing else is reachable. */
    const val PURPOSE_RECONNECT_HANDSHAKE = "RECONNECT_HANDSHAKE"
    const val PURPOSE_FIELD_OPERATION = "FIELD_OPERATION"

    // -----------------------------------------------------------------------
    // Enrollment: the possession statement (D23-03 / C15-03)
    // -----------------------------------------------------------------------

    /**
     * The APPROVED request's fingerprint is inside the statement, so a signature
     * proving possession of an attacker's key cannot be presented against an
     * approval issued for someone else's request — the bytes would not match.
     */
    fun possessionStatement(
        challengeId: String,
        enrollmentRequestId: String,
        enrollmentRequestFingerprint: String,
        nonce: String,
        publicKeyThumbprint: String,
        signatureProfile: String = SIGNATURE_PROFILE,
    ): String = CanonicalJson.encode(
        linkedMapOf(
            "domain" to POSSESSION_DOMAIN,
            "challenge_id" to challengeId,
            "enrollment_request_id" to enrollmentRequestId,
            "enrollment_request_fingerprint" to enrollmentRequestFingerprint,
            "nonce" to nonce,
            "public_key_thumbprint" to publicKeyThumbprint,
            "signature_profile" to signatureProfile,
        ),
    )

    // -----------------------------------------------------------------------
    // Gateway: the per-request proof (C14-03)
    // -----------------------------------------------------------------------

    /**
     * The proof binds the tenant, site and actor as well as the context id.
     *
     * A proof that bound only `context_id` would be replayable against any
     * context whose id an attacker learned; binding the whole tuple makes a
     * mismatch between the proof and the context a cryptographic contradiction
     * rather than a lookup somebody could skip.
     *
     * `signature` is excluded because it is the output. `device_trust` is
     * excluded because it is the platform's judgement, never the device's.
     */
    fun requestProofStatement(
        contextId: String,
        organisationId: String,
        siteId: String,
        actorUserId: String,
        deviceId: String,
        keyId: String,
        keyVersion: Int,
        purpose: String,
        payloadDigest: String,
        nonce: String,
        issuedAt: String,
        signatureProfile: String = SIGNATURE_PROFILE,
    ): String = CanonicalJson.encode(
        linkedMapOf(
            "domain" to REQUEST_PROOF_DOMAIN,
            "schema_version" to 1,
            "context_id" to contextId,
            "organisation_id" to organisationId,
            "site_id" to siteId,
            "actor_user_id" to actorUserId,
            "device_id" to deviceId,
            "key_id" to keyId,
            "key_version" to keyVersion,
            "purpose" to purpose,
            "payload_digest" to payloadDigest,
            "nonce" to nonce,
            "issued_at" to issuedAt,
            "signature_profile" to signatureProfile,
        ),
    )

    // -----------------------------------------------------------------------
    // Gateway: the pre-context establishment challenge (D25-03A)
    // -----------------------------------------------------------------------

    /**
     * The challenge the server issued, as the device must hash it.
     *
     * The device never chooses any of these values; every one is read back out
     * of the server's own response. What the device contributes is the
     * signature, which is the only thing it has that the challenge does not
     * already contain — steal every field here and you have zero device
     * authority.
     */
    fun establishmentChallengeStatement(
        establishmentId: String,
        proposedContextId: String,
        organisationId: String,
        actorUserId: String,
        deviceId: String,
        siteId: String,
        keyId: String,
        keyVersion: Int,
        nonce: String,
        issuedAt: String,
        expiresAt: String,
    ): String = CanonicalJson.encode(
        linkedMapOf(
            "domain" to ESTABLISHMENT_CHALLENGE_DOMAIN,
            "schema_version" to 1,
            "establishment_id" to establishmentId,
            "proposed_context_id" to proposedContextId,
            "organisation_id" to organisationId,
            "actor_user_id" to actorUserId,
            "device_id" to deviceId,
            "site_id" to siteId,
            "key_id" to keyId,
            "key_version" to keyVersion,
            "nonce" to nonce,
            "issued_at" to issuedAt,
            "expires_at" to expiresAt,
        ),
    )

    /** The value a conforming device puts in `DeviceRequestProof.payload_digest`. */
    fun establishmentChallengeDigest(
        establishmentId: String,
        proposedContextId: String,
        organisationId: String,
        actorUserId: String,
        deviceId: String,
        siteId: String,
        keyId: String,
        keyVersion: Int,
        nonce: String,
        issuedAt: String,
        expiresAt: String,
    ): String = CanonicalPublicKey.sha256HexUtf8(
        establishmentChallengeStatement(
            establishmentId = establishmentId,
            proposedContextId = proposedContextId,
            organisationId = organisationId,
            actorUserId = actorUserId,
            deviceId = deviceId,
            siteId = siteId,
            keyId = keyId,
            keyVersion = keyVersion,
            nonce = nonce,
            issuedAt = issuedAt,
            expiresAt = expiresAt,
        ),
    )

    // -----------------------------------------------------------------------
    // Gateway: the canonical typed operation envelope (D25-11)
    // -----------------------------------------------------------------------

    /** The four kinds the gateway exposes, and the target type fixed for each. */
    val TARGET_TYPE_FOR_KIND: Map<String, String> = mapOf(
        "FIELD_STATE_UPDATE" to "FIELD_OPERATIVE_STATE",
        "ASSIGNMENT_ACCEPT" to "FIELD_ASSIGNMENT",
        "ASSIGNMENT_DECLINE" to "FIELD_ASSIGNMENT",
        "INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE" to "INCIDENT_FIELD_MESSAGE",
    )

    /**
     * A DEVICE MUST NOT SIGN `SHA256(whatever JSON arrived)`.
     *
     * If the signed digest were taken over raw request bytes, two operations
     * whose bodies happened to serialise identically would share a signature and
     * a proof minted for an assignment accept could be carried to a field-state
     * update. The server owns the envelope, builds it from a PARSED semantic
     * object and hashes THAT; the device reproduces the same envelope from the
     * context it holds and the site it is acting at, which is what makes the
     * digest computable on both sides.
     */
    fun operationEnvelopeStatement(
        operationKind: String,
        organisationId: String,
        siteId: String,
        actorUserId: String,
        deviceId: String,
        targetId: String,
        semanticPayload: Map<String, Any?>,
    ): String {
        val targetType = TARGET_TYPE_FOR_KIND[operationKind]
            ?: throw IllegalArgumentException("unknown gateway operation kind: $operationKind")
        return CanonicalJson.encode(
            linkedMapOf(
                "domain" to OPERATION_ENVELOPE_DOMAIN,
                "schema_version" to 1,
                "operation_kind" to operationKind,
                "organisation_id" to organisationId,
                "site_id" to siteId,
                "actor_user_id" to actorUserId,
                "device_id" to deviceId,
                "target_type" to targetType,
                "target_id" to targetId,
                "semantic_payload" to semanticPayload,
            ),
        )
    }

    /** The value a conforming device puts in `DeviceRequestProof.payload_digest`. */
    fun operationEnvelopeDigest(
        operationKind: String,
        organisationId: String,
        siteId: String,
        actorUserId: String,
        deviceId: String,
        targetId: String,
        semanticPayload: Map<String, Any?>,
    ): String = CanonicalPublicKey.sha256HexUtf8(
        operationEnvelopeStatement(
            operationKind = operationKind,
            organisationId = organisationId,
            siteId = siteId,
            actorUserId = actorUserId,
            deviceId = deviceId,
            targetId = targetId,
            semanticPayload = semanticPayload,
        ),
    )
}
