package com.sentinel.field.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * THE FOUR SIGNED STATEMENTS, AGAINST FIXTURES FROM THE SERVER'S OWN ALGORITHM.
 *
 * Each expected string and digest below was produced by running the contract's
 * `canonicalDeviceJson` / `deviceCanonicalDigest` on V8 over the same object
 * literal the corresponding server file builds, and pasted here verbatim. A
 * client that agrees with these fixtures produces bytes the server will hash to
 * the same value; one that does not fails here rather than in the field, where
 * the symptom would be an indistinguishable 403.
 *
 * WHAT THIS DOES NOT PROVE. It proves the CLIENT and the CONTRACT agree about
 * the bytes. It does not prove the server is fed the same field values at
 * runtime — that is what physical device acceptance, against a live core-api, is
 * for.
 * ============================================================================
 */
class DeviceStatementsTest {

    // -----------------------------------------------------------------------
    // Possession — packages/contracts/src/device-identity.ts
    // -----------------------------------------------------------------------

    @Test
    fun `the possession statement matches canonicalDevicePossessionStatement`() {
        val statement = DeviceStatements.possessionStatement(
            challengeId = "chal-1",
            enrollmentRequestId = "req-1",
            enrollmentRequestFingerprint = "a".repeat(64),
            nonce = "bm9uY2UtdmFsdWUtMTIzNA",
            publicKeyThumbprint = "b".repeat(64),
        )
        assertEquals(
            "{\"challenge_id\":\"chal-1\"," +
                "\"domain\":\"sentinel.device.possession-challenge.v1\"," +
                "\"enrollment_request_fingerprint\":\"" + "a".repeat(64) + "\"," +
                "\"enrollment_request_id\":\"req-1\"," +
                "\"nonce\":\"bm9uY2UtdmFsdWUtMTIzNA\"," +
                "\"public_key_thumbprint\":\"" + "b".repeat(64) + "\"," +
                "\"signature_profile\":\"P256_ECDSA_SHA256\"}",
            statement,
        )
    }

    // -----------------------------------------------------------------------
    // Request proof — packages/contracts/src/device-context.ts
    // -----------------------------------------------------------------------

    @Test
    fun `the request proof statement matches canonicalDeviceRequestProofStatement`() {
        val statement = DeviceStatements.requestProofStatement(
            contextId = "ctx-1",
            organisationId = "org-1",
            siteId = "site-1",
            actorUserId = "user-1",
            deviceId = "dev-1",
            keyId = "key-1",
            keyVersion = 3,
            purpose = DeviceStatements.PURPOSE_FIELD_OPERATION,
            payloadDigest = "c".repeat(64),
            nonce = "bm9uY2UtdmFsdWUtMTIzNA",
            issuedAt = "2026-09-02T10:11:12.345Z",
        )
        assertEquals(
            "{\"actor_user_id\":\"user-1\"," +
                "\"context_id\":\"ctx-1\"," +
                "\"device_id\":\"dev-1\"," +
                "\"domain\":\"sentinel.device.request-proof.v1\"," +
                "\"issued_at\":\"2026-09-02T10:11:12.345Z\"," +
                "\"key_id\":\"key-1\"," +
                "\"key_version\":3," +
                "\"nonce\":\"bm9uY2UtdmFsdWUtMTIzNA\"," +
                "\"organisation_id\":\"org-1\"," +
                "\"payload_digest\":\"" + "c".repeat(64) + "\"," +
                "\"purpose\":\"FIELD_OPERATION\"," +
                "\"schema_version\":1," +
                "\"signature_profile\":\"P256_ECDSA_SHA256\"," +
                "\"site_id\":\"site-1\"}",
            statement,
        )
        // `deviceRequestProofFingerprint` over the same object.
        assertEquals(
            "b160b9489ff8b78b4ba47201653b767a2ad78208dfac3b7888d97792933c0181",
            CanonicalPublicKey.sha256HexUtf8(statement),
        )
    }

    @Test
    fun `key_version is bound as a NUMBER, not a string`() {
        // The server writes `key_version: challenge.key_version` straight from a
        // JSON number. Quoting it here would produce a statement that differs by
        // two bytes and a signature that verifies over nothing the server hashed.
        assertTrue(
            DeviceStatements.requestProofStatement(
                contextId = "c", organisationId = "o", siteId = "s", actorUserId = "u",
                deviceId = "d", keyId = "k", keyVersion = 1,
                purpose = DeviceStatements.PURPOSE_RECONNECT_HANDSHAKE,
                payloadDigest = "0".repeat(64), nonce = "n".repeat(16),
                issuedAt = "2026-09-02T10:11:12.345Z",
            ).contains("\"key_version\":1,"),
        )
    }

    // -----------------------------------------------------------------------
    // Establishment challenge — device-context.challenge.ts
    // -----------------------------------------------------------------------

    @Test
    fun `the establishment challenge statement and digest match the server`() {
        val statement = DeviceStatements.establishmentChallengeStatement(
            establishmentId = "est-1",
            proposedContextId = "ctx-1",
            organisationId = "org-1",
            actorUserId = "user-1",
            deviceId = "dev-1",
            siteId = "site-1",
            keyId = "key-1",
            keyVersion = 1,
            nonce = "bm9uY2UtdmFsdWUtMTIzNA",
            issuedAt = "2026-09-02T10:11:12.345Z",
            expiresAt = "2026-09-02T10:13:12.345Z",
        )
        assertEquals(
            "{\"actor_user_id\":\"user-1\"," +
                "\"device_id\":\"dev-1\"," +
                "\"domain\":\"sentinel.wp25.device-gateway.establishment-challenge.v1\"," +
                "\"establishment_id\":\"est-1\"," +
                "\"expires_at\":\"2026-09-02T10:13:12.345Z\"," +
                "\"issued_at\":\"2026-09-02T10:11:12.345Z\"," +
                "\"key_id\":\"key-1\"," +
                "\"key_version\":1," +
                "\"nonce\":\"bm9uY2UtdmFsdWUtMTIzNA\"," +
                "\"organisation_id\":\"org-1\"," +
                "\"proposed_context_id\":\"ctx-1\"," +
                "\"schema_version\":1," +
                "\"site_id\":\"site-1\"}",
            statement,
        )
        assertEquals(
            "ec4d461a2a78c1b6e598a8c615034c7c07a3941dc55d7d3de9776bed915c97c5",
            DeviceStatements.establishmentChallengeDigest(
                establishmentId = "est-1",
                proposedContextId = "ctx-1",
                organisationId = "org-1",
                actorUserId = "user-1",
                deviceId = "dev-1",
                siteId = "site-1",
                keyId = "key-1",
                keyVersion = 1,
                nonce = "bm9uY2UtdmFsdWUtMTIzNA",
                issuedAt = "2026-09-02T10:11:12.345Z",
                expiresAt = "2026-09-02T10:13:12.345Z",
            ),
        )
    }

    // -----------------------------------------------------------------------
    // Operation envelope — device-gateway.envelope.ts
    // -----------------------------------------------------------------------

    @Test
    fun `the field state envelope statement and digest match the server`() {
        val payload = linkedMapOf<String, Any?>(
            "state" to "AVAILABLE",
            "location" to null,
            "source_at" to "2026-09-02T10:11:12.345Z",
            "freshness_ms" to 0,
        )
        val statement = DeviceStatements.operationEnvelopeStatement(
            operationKind = "FIELD_STATE_UPDATE",
            organisationId = "org-1",
            siteId = "site-1",
            actorUserId = "user-1",
            deviceId = "dev-1",
            targetId = "user-1",
            semanticPayload = payload,
        )
        assertEquals(
            "{\"actor_user_id\":\"user-1\"," +
                "\"device_id\":\"dev-1\"," +
                "\"domain\":\"sentinel.wp25.device-gateway.operation-envelope.v1\"," +
                "\"operation_kind\":\"FIELD_STATE_UPDATE\"," +
                "\"organisation_id\":\"org-1\"," +
                "\"schema_version\":1," +
                "\"semantic_payload\":{" +
                "\"freshness_ms\":0," +
                "\"location\":null," +
                "\"source_at\":\"2026-09-02T10:11:12.345Z\"," +
                "\"state\":\"AVAILABLE\"}," +
                "\"site_id\":\"site-1\"," +
                "\"target_id\":\"user-1\"," +
                "\"target_type\":\"FIELD_OPERATIVE_STATE\"}",
            statement,
        )
        assertEquals(
            "7a566328ca6138c817d2f7ab111ce714655ef92f5cdc0b17ec8e11241da52dff",
            DeviceStatements.operationEnvelopeDigest(
                operationKind = "FIELD_STATE_UPDATE",
                organisationId = "org-1",
                siteId = "site-1",
                actorUserId = "user-1",
                deviceId = "dev-1",
                targetId = "user-1",
                semanticPayload = payload,
            ),
        )
    }

    @Test
    fun `the target type is fixed by the kind and is never taken from a caller`() {
        assertEquals("FIELD_OPERATIVE_STATE", DeviceStatements.TARGET_TYPE_FOR_KIND["FIELD_STATE_UPDATE"])
        assertEquals("FIELD_ASSIGNMENT", DeviceStatements.TARGET_TYPE_FOR_KIND["ASSIGNMENT_ACCEPT"])
        assertEquals("FIELD_ASSIGNMENT", DeviceStatements.TARGET_TYPE_FOR_KIND["ASSIGNMENT_DECLINE"])
        assertEquals("INCIDENT_FIELD_MESSAGE", DeviceStatements.TARGET_TYPE_FOR_KIND["INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE"])
        // WP-27 added the fifth kind. The count is asserted so a kind cannot be
        // added without a reviewer seeing it here.
        assertEquals("DEVICE_ACTION_STATEMENT", DeviceStatements.TARGET_TYPE_FOR_KIND["DEVICE_ACTION"])
        // WP-29A added the sixth, and the count moved 5 -> 6 as the deliberate,
        // visible act this assertion exists to force. It is the ONLY change
        // made here: nothing above was relaxed, and the new kind is enumerated
        // by name like every other one rather than being absorbed by a looser
        // count.
        //
        // `OFFLINE_QUEUE_SUBMIT` is the submission of ONE operation the device
        // produced while disconnected. Its target is the QUEUED OPERATION
        // itself — the `offline_operation_id` inside the signed offline
        // envelope — and not the operative, because that is what binds a
        // freshly minted proof to the specific queued statement it carries.
        assertEquals("FIELD_OFFLINE_OPERATION", DeviceStatements.TARGET_TYPE_FOR_KIND["OFFLINE_QUEUE_SUBMIT"])
        assertEquals(6, DeviceStatements.TARGET_TYPE_FOR_KIND.size)
    }

    @Test
    fun `D25-10 - the ungated assignment transitions have no kind at all`() {
        // They are not "refused" by a check somebody could delete. Nothing in
        // this client constructs them.
        for (absent in listOf("ASSIGNMENT_START", "ASSIGNMENT_COMPLETE", "ASSIGNMENT_CANCEL", "ASSIGNMENT_REASSIGN")) {
            assertNull(DeviceStatements.TARGET_TYPE_FOR_KIND[absent])
        }
    }

    // -----------------------------------------------------------------------
    // Domain separation
    // -----------------------------------------------------------------------

    @Test
    fun `the four domains are distinct, and none is Whispers`() {
        val domains = listOf(
            DeviceStatements.POSSESSION_DOMAIN,
            DeviceStatements.REQUEST_PROOF_DOMAIN,
            DeviceStatements.ESTABLISHMENT_CHALLENGE_DOMAIN,
            DeviceStatements.OPERATION_ENVELOPE_DOMAIN,
        )
        assertEquals(domains.size, domains.toSet().size)
        // A signature minted over one statement must never verify as another,
        // and a shared tag makes that possible the moment two statements happen
        // to share a shape.
        for (domain in domains) {
            assertNotEquals("sentinel.whisper.device-action.v1", domain)
        }
    }
}
