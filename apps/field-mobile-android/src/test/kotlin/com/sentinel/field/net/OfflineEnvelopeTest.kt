package com.sentinel.field.net

import com.sentinel.field.security.CanonicalJson
import com.sentinel.field.security.CanonicalPublicKey
import com.sentinel.field.security.DeviceStatements
import com.sentinel.field.store.MalformedOutbox
import com.sentinel.field.store.OfflineOutboxEntry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * THE BYTES THE HARDWARE KEY SIGNS WHEN THERE IS NO NETWORK.
 *
 * The statement fixture below is not a value this test read out of the code it
 * is testing. It was written out by hand from
 * `deviceOfflineOperationStatementObject` in
 * `packages/contracts/src/device-offline.ts`, sorted with an independent sort,
 * and hashed with an independent SHA-256. If the Kotlin canonicaliser orders a
 * key differently, prints an integer differently, or the builder drops or adds
 * a field, this fails — which is the only thing standing between this client
 * and a signature the server can never reconstruct.
 *
 * WHAT THIS PROVES AND WHAT IT DOES NOT. It proves the SHAPE of the signed
 * bytes. It proves nothing about the signature itself, which is made in
 * StrongBox and is established on physical hardware and nowhere else.
 * ============================================================================
 */
class OfflineEnvelopeTest {

    private companion object {
        const val OPERATION_ID = "11111111-1111-4111-8111-111111111111"
        const val MESSAGE_ID = "22222222-2222-4222-8222-222222222222"
        const val NONCE = "nonce-0123456789abcdef"
        const val CREATED_AT = "2026-09-05T10:00:00Z"

        /** SHA-256 of the canonical payload text, computed outside this codebase. */
        const val PAYLOAD_DIGEST = "032c6ac159c32198b4287477cae0eea2dbef37e41cf9ffec2b39c4a9a9ab5a5a"

        /** SHA-256 of [EXPECTED_STATEMENT], computed outside this codebase. */
        const val EXPECTED_FINGERPRINT = "e240927cd731c8ded1c6315c333b288092f00cd751954c5babeb8badf360a027"

        /**
         * The WP-25 gateway envelope digest for this submission, also computed
         * outside this codebase, by an independent canonicaliser that sorts
         * keys RECURSIVELY through the nested envelope and payload.
         */
        const val EXPECTED_GATEWAY_DIGEST = "a8c13f873fdb83b02e3f27c512bfa3b12d209adb1b9eebebdcef406daff7d855"

        val EXPECTED_STATEMENT =
            """{"actor_user_id":"user-1","created_at":"2026-09-05T10:00:00Z",""" +
                """"device_id":"device-1","device_sequence":7,""" +
                """"domain":"sentinel.device.offline-operation.v1",""" +
                """"idempotency_key":"11111111-1111-4111-8111-111111111111",""" +
                """"key_id":"key-1","key_version":3,"nonce":"nonce-0123456789abcdef",""" +
                """"offline_operation_id":"11111111-1111-4111-8111-111111111111",""" +
                """"operation_kind":"INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE","organisation_id":"org-1",""" +
                """"payload_digest":"032c6ac159c32198b4287477cae0eea2dbef37e41cf9ffec2b39c4a9a9ab5a5a",""" +
                """"policy_lease_id":"lease-1","schema_version":1,""" +
                """"signature_profile":"P256_ECDSA_SHA256","site_id":"site-1"}"""
    }

    /** A signer that records what it was asked to sign and returns a marker. */
    private class RecordingSigner {
        var signed: String? = null

        fun sign(statement: String): String {
            signed = statement
            return "signature-of-${statement.length}"
        }
    }

    private fun entry(signer: RecordingSigner = RecordingSigner()): OfflineOutboxEntry =
        OfflineEnvelope.signedEntry(
            offlineOperationId = OPERATION_ID,
            organisationId = "org-1",
            siteId = "site-1",
            actorUserId = "user-1",
            deviceId = "device-1",
            keyId = "key-1",
            keyVersion = 3,
            operationKind = OfflineEnvelope.KIND_MESSAGE_ACKNOWLEDGE,
            deviceSequence = 7L,
            policyLeaseId = "lease-1",
            payload = OfflineEnvelope.acknowledgePayload(MESSAGE_ID),
            nonce = NONCE,
            createdAt = CREATED_AT,
            signer = signer::sign,
        )

    // -----------------------------------------------------------------------
    // The signed bytes
    // -----------------------------------------------------------------------

    @Test
    fun `the statement is the contract canonical form, field for field`() {
        assertEquals(EXPECTED_STATEMENT, OfflineEnvelope.statementFor(entry()))
    }

    @Test
    fun `the statement carries the domain separator and the server profile`() {
        val statement = OfflineEnvelope.statementFor(entry())
        assertTrue(statement.contains("\"domain\":\"sentinel.device.offline-operation.v1\""))
        // C15-01: the SIGNED field is `signature_profile`, the server's answer.
        // The device's own claim is a different field and it is not in here.
        assertTrue(statement.contains("\"signature_profile\":\"P256_ECDSA_SHA256\""))
        assertTrue(
            "the device claim must never appear inside the signed bytes",
            !statement.contains("claimed_signature_profile"),
        )
    }

    @Test
    fun `the fingerprint is the digest of exactly those bytes`() {
        assertEquals(EXPECTED_FINGERPRINT, OfflineEnvelope.fingerprint(entry()))
        assertEquals(
            CanonicalPublicKey.sha256HexUtf8(EXPECTED_STATEMENT),
            OfflineEnvelope.fingerprint(entry()),
        )
    }

    @Test
    fun `the payload digest is taken over the canonical payload text`() {
        val payload = OfflineEnvelope.acknowledgePayload(MESSAGE_ID)
        assertEquals(PAYLOAD_DIGEST, OfflineEnvelope.payloadDigest(payload))
        assertEquals(
            CanonicalPublicKey.sha256HexUtf8("""{"message_id":"$MESSAGE_ID"}"""),
            OfflineEnvelope.payloadDigest(payload),
        )
    }

    /**
     * The sequence is inside the signed bytes, so a different position is a
     * different statement. This is what makes a re-used or shifted sequence a
     * signature failure rather than a quiet duplicate.
     */
    @Test
    fun `a different sequence produces different signed bytes`() {
        val one = OfflineEnvelope.statementFor(entry())
        val two = OfflineEnvelope.statementFor(entry().copy(deviceSequence = 8L))
        assertTrue(one != two)
    }

    /**
     * `policy_lease_id` is the load-bearing field of the whole module: the
     * operation names the authority it acted under, so an expired or revoked
     * lease can be judged on its own terms rather than on a timestamp this
     * device controls.
     */
    @Test
    fun `the lease identity is inside the signature`() {
        assertTrue(OfflineEnvelope.statementFor(entry()).contains("\"policy_lease_id\":\"lease-1\""))
    }

    // -----------------------------------------------------------------------
    // What is signed, and what is stored
    // -----------------------------------------------------------------------

    @Test
    fun `the signer is handed exactly the canonical statement`() {
        val signer = RecordingSigner()
        entry(signer)
        assertEquals(EXPECTED_STATEMENT, signer.signed)
    }

    @Test
    fun `the stored payload text is the text the digest was taken over`() {
        val stored = entry()
        assertEquals("""{"message_id":"$MESSAGE_ID"}""", stored.payloadJson)
        assertEquals(PAYLOAD_DIGEST, stored.payloadDigest)
    }

    /**
     * The idempotency key is inside the signed bytes, so it must be STABLE
     * across every retry. The operation id is the one value minted once and
     * never changed, which is why it is the default.
     */
    @Test
    fun `the idempotency key defaults to the operation id`() {
        assertEquals(OPERATION_ID, entry().idempotencyKey)
    }

    // -----------------------------------------------------------------------
    // The wire envelope
    // -----------------------------------------------------------------------

    @Test
    fun `the wire envelope carries seventeen members and no others`() {
        val wire = OfflineEnvelope.wire(entry())
        assertEquals(
            setOf(
                "schema_version",
                "offline_operation_id",
                "organisation_id",
                "site_id",
                "actor_user_id",
                "device_id",
                "key_id",
                "key_version",
                "operation_kind",
                "device_sequence",
                "idempotency_key",
                "payload_digest",
                "policy_lease_id",
                "nonce",
                "created_at",
                "claimed_signature_profile",
                "signature",
            ),
            wire.keys,
        )
    }

    /**
     * C15-01. The wire field is the device's CLAIM; the signed field is the
     * server's answer. They hold the same string and they are never derived
     * from one another, so `domain` — which only the statement carries — must
     * not appear on the wire either.
     */
    @Test
    fun `the wire envelope carries the claim and never the domain`() {
        val wire = OfflineEnvelope.wire(entry())
        assertTrue(wire.containsKey("claimed_signature_profile"))
        assertTrue(!wire.containsKey("signature_profile"))
        assertTrue(!wire.containsKey("domain"))
    }

    // -----------------------------------------------------------------------
    // The WP-25 submission, and the digest the fresh proof covers
    // -----------------------------------------------------------------------

    @Test
    fun `the submission carries exactly two members`() {
        assertEquals(listOf("envelope", "payload"), OfflineEnvelope.submission(entry()).keys.toList())
    }

    /**
     * THE SECOND INDEPENDENT FIXTURE IN THIS FILE, AND IT IS THE ONE THAT WOULD
     * HAVE CAUGHT THE DEFECT.
     *
     * `a8c13f87…` was produced outside this codebase, by an independent
     * canonicaliser sorting keys RECURSIVELY — through the nested envelope and
     * its nested payload — and an independent SHA-256. An earlier draft of this
     * client used the offline fingerprint here instead, which would have minted
     * a proof over bytes the server never reconstructs; the answer would have
     * been a signature failure naming nothing anybody could act on.
     */
    @Test
    fun `the gateway digest is the WP-25 envelope digest over that submission`() {
        assertEquals(
            EXPECTED_GATEWAY_DIGEST,
            OfflineEnvelope.gatewayPayloadDigest(
                entry = entry(),
                organisationId = "org-1",
                siteId = "site-1",
                actorUserId = "user-1",
                deviceId = "device-1",
            ),
        )
    }

    /**
     * Two signatures, two preimages. The fingerprint is the identity of the
     * QUEUED STATEMENT and is what the envelope's own signature covers; the
     * gateway digest is the identity of THIS REQUEST. Using one where the other
     * belongs is the mistake this asserts against.
     */
    @Test
    fun `the gateway digest is not the offline fingerprint`() {
        assertNotEquals(
            OfflineEnvelope.fingerprint(entry()),
            OfflineEnvelope.gatewayPayloadDigest(
                entry = entry(),
                organisationId = "org-1",
                siteId = "site-1",
                actorUserId = "user-1",
                deviceId = "device-1",
            ),
        )
    }

    /**
     * The target is the QUEUED OPERATION, not the operative.
     *
     * A proof targeting the operative would describe any of their queued
     * operations equally well, and a live device could then present one
     * statement beside a proof minted for another.
     */
    @Test
    fun `the gateway statement targets the queued operation`() {
        val statement = DeviceStatements.operationEnvelopeStatement(
            operationKind = OfflineEnvelope.GATEWAY_KIND_OFFLINE_QUEUE_SUBMIT,
            organisationId = "org-1",
            siteId = "site-1",
            actorUserId = "user-1",
            deviceId = "device-1",
            targetId = OPERATION_ID,
            semanticPayload = OfflineEnvelope.submission(entry()),
        )
        assertTrue(statement.contains("\"operation_kind\":\"OFFLINE_QUEUE_SUBMIT\""))
        assertTrue(statement.contains("\"target_type\":\"FIELD_OFFLINE_OPERATION\""))
        assertTrue(statement.contains("\"target_id\":\"$OPERATION_ID\""))
        // The operative appears as the actor, and must not have become the target.
        assertTrue(statement.contains("\"actor_user_id\":\"user-1\""))
        assertTrue(!statement.contains("\"target_id\":\"user-1\""))
    }

    /**
     * THE BODY AND THE DIGEST ARE THE SAME OBJECT.
     *
     * `submissionJson` serialises the very map `gatewayPayloadDigest` covers, so
     * the two cannot drift. Asserted by canonicalising both and comparing: a
     * value type whose JSON form differed between the serialiser and the
     * canonicaliser would show up here rather than as a refusal in the field.
     */
    @Test
    fun `the posted body canonicalises to the bytes the proof covers`() {
        val digested = CanonicalJson.encode(OfflineEnvelope.submission(entry()))
        val posted = CanonicalJson.encode(OfflineEnvelope.canonicalMapOf(OfflineEnvelope.submissionJson(entry())))
        assertEquals(digested, posted)
    }

    @Test
    fun `the submission envelope is the same seventeen members as the wire envelope`() {
        val fromSubmission = OfflineEnvelope.submission(entry())["envelope"] as Map<*, *>
        assertEquals(OfflineEnvelope.wire(entry()).keys, fromSubmission.keys)
        assertEquals(17, fromSubmission.size)
    }

    /**
     * A STORED PAYLOAD THAT DOES NOT SURVIVE THE ROUND TRIP IS REFUSED.
     *
     * `payloadJson` is what the envelope signature commits to through
     * `payload_digest`. Reading it back through a parse and a map conversion is
     * two chances to change it, and an unnoticed change reaches the server as
     * PAYLOAD_DIGEST_MISMATCH — which is terminal, and a terminal answer removes
     * the entry. A local conversion bug would silently destroy the operation, so
     * it throws here instead.
     */
    @Test
    fun `a payload that does not survive the canonical round trip is refused`() {
        // Stored with its keys out of canonical order, which is exactly what a
        // payload written by something other than the canonicaliser looks like.
        val tampered = entry().copy(payloadJson = """{"b":1,"a":2}""")
        try {
            OfflineEnvelope.submission(tampered)
            throw AssertionError("expected a non-canonical stored payload to be refused")
        } catch (expected: MalformedOutbox) {
            assertTrue(expected.message!!.contains("round trip"))
        }
    }

    @Test
    fun `a stored payload that is not JSON is refused rather than posted`() {
        for (broken in listOf("not json", "[]", "7")) {
            try {
                OfflineEnvelope.submission(entry().copy(payloadJson = broken))
                throw AssertionError("expected '$broken' to be refused")
            } catch (expected: MalformedOutbox) {
                assertTrue(expected.message!!.isNotBlank())
            }
        }
    }

    /**
     * The converter admits only what `CanonicalJson` admits. A fractional number
     * has no branch, deliberately: `CanonicalJson` refuses `Double` permanently
     * because Kotlin's number printing does not always agree with V8's, and a
     * converter that quietly produced one would reintroduce that problem one
     * layer up.
     */
    @Test
    fun `the payload converter refuses a fractional number`() {
        try {
            OfflineEnvelope.submission(entry().copy(payloadJson = """{"confidence":0.5}"""))
            throw AssertionError("expected a fractional value to be refused")
        } catch (expected: MalformedOutbox) {
            assertTrue(expected.message!!.contains("canonical form"))
        }
    }
}
