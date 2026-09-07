package com.sentinel.field.store

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * WHAT A QUEUE ENTRY MAY CARRY, AND WHAT IT MUST REFUSE TO CARRY.
 *
 * This mirrors `ClientStateStoreTest`'s approach for the same reason: a queue
 * entry is written to disk and SURVIVES — across a restart, across a shift
 * change, across a lost handset — so it is exactly the structure into which
 * somebody would eventually be tempted to tuck the thing they need in order to
 * send it later.
 *
 * THE FORBIDDEN-WORD LIST IS NOT THE SAME LIST, AND THE DIFFERENCE IS
 * DELIBERATE
 * ----------------------------------------------------------------------------
 * `ClientStateStoreTest` forbids `key` and `signature` as well, because the six
 * ids it guards have no business naming either. This class necessarily names
 * both: `key_id` NAMES a registered key and confers nothing, and `signature` is
 * the public output the server verifies. Both are already on the wire in clear
 * and neither is a secret.
 *
 * So the list below names SECRETS specifically — a credential, a grant, a
 * password, a private key — and stating why each list differs is the point. A
 * test that quietly reused a weaker list would look like the sibling and prove
 * something else.
 * ============================================================================
 */
class OfflineOutboxEntryTest {

    private fun entry(): OfflineOutboxEntry = OfflineOutboxEntry(
        offlineOperationId = "11111111-1111-4111-8111-111111111111",
        organisationId = "org-1",
        siteId = "site-1",
        actorUserId = "user-1",
        deviceId = "device-1",
        keyId = "key-1",
        keyVersion = 4,
        operationKind = "INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE",
        deviceSequence = 17L,
        idempotencyKey = "11111111-1111-4111-8111-111111111111",
        payloadDigest = "c".repeat(64),
        policyLeaseId = "lease-1",
        nonce = "nonce-0123456789abcdef",
        createdAt = "2026-09-05T10:00:00Z",
        claimedSignatureProfile = "P256_ECDSA_SHA256",
        signature = "d".repeat(86),
        payloadJson = """{"message_id":"22222222-2222-4222-8222-222222222222"}""",
    )

    // -----------------------------------------------------------------------
    // Nothing secret-shaped, ever
    // -----------------------------------------------------------------------

    @Test
    fun `no persisted field names a secret`() {
        val forbidden = listOf(
            "credential",
            "password",
            "passphrase",
            "session",
            "bearer",
            "private",
            "grant",
            "authorization",
            "authorisation",
        )
        for (field in OfflineOutboxEntry.PERSISTED_FIELDS) {
            for (word in forbidden) {
                assertFalse(
                    "'$field' is persisted by a queue entry and names a secret ('$word')",
                    field.lowercase().contains(word),
                )
            }
        }
    }

    /**
     * The exact field list, pinned.
     *
     * Not a style assertion: every one of these is either a value the hardware
     * key SIGNED — in which case it must be here or the envelope cannot be
     * rebuilt — or a `local_` value that must never be mistaken for one. A new
     * field arriving without this list changing is the case worth catching.
     */
    @Test
    fun `the persisted field list is exactly the envelope plus five local values`() {
        assertEquals(
            listOf(
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
                "local_payload_json",
                "local_attempt_count",
                "local_last_attempt_at",
                "local_state",
                "local_edge_receipt_json",
            ),
            OfflineOutboxEntry.PERSISTED_FIELDS,
        )
    }

    @Test
    fun `every local field is prefixed so it cannot be read as a signed one`() {
        val signedFields = OfflineOutboxEntry.PERSISTED_FIELDS.filter { !it.startsWith("local_") }
        assertEquals(16, signedFields.size)
        // WP-29B added `local_edge_receipt_json`, so the local count moved from
        // four to five. THE SIXTEEN SIGNED FIELDS DID NOT MOVE, and that is the
        // half of this assertion that is load-bearing: an Edge receipt is
        // collected long after the envelope was signed, so it CANNOT be inside
        // the signature, and the day it appears without a `local_` prefix is
        // the day a reader starts believing the device attested to it.
        assertEquals(5, OfflineOutboxEntry.PERSISTED_FIELDS.size - signedFields.size)
    }

    // -----------------------------------------------------------------------
    // Round trip
    // -----------------------------------------------------------------------

    @Test
    fun `what is written is what comes back`() {
        val original = entry().copy(attemptCount = 3, lastAttemptAt = "2026-09-05T11:00:00Z")
        assertEquals(original, OfflineOutboxEntry.fromJson(original.toJson()))
    }

    @Test
    fun `a terminal entry round trips as terminal`() {
        val original = entry().copy(state = OfflineEntryState.TERMINAL)
        val restored = OfflineOutboxEntry.fromJson(original.toJson())
        assertTrue(restored.isTerminal)
        assertEquals(original, restored)
    }

    @Test
    fun `a never attempted entry keeps a null last attempt rather than the word null`() {
        val restored = OfflineOutboxEntry.fromJson(entry().toJson())
        assertNull(restored.lastAttemptAt)
        assertEquals(0, restored.attemptCount)
    }

    /**
     * The Edge witness survives the round trip, and its absence survives it too.
     *
     * The receipt is the ONLY evidence of an independent clock that will ever
     * exist for an operation queued on a disconnected handset, and it exists on
     * a LAN the device may never see again. An entry that lost it on the next
     * restart would reach central with nothing to place the operation inside
     * its lease.
     */
    @Test
    fun `an edge receipt round trips, and no receipt round trips as no receipt`() {
        val receipt = """{"edge_id":"edge-17","schema_version":1}"""
        val witnessed = entry().copy(edgeReceiptJson = receipt)
        assertEquals(receipt, OfflineOutboxEntry.fromJson(witnessed.toJson()).edgeReceiptJson)
        assertNull(OfflineOutboxEntry.fromJson(entry().toJson()).edgeReceiptJson)
    }

    /**
     * D23-10, as a property of the STORED shape.
     *
     * `EdgeReceipt` refuses a receipt carrying any of these on the way in. This
     * asserts the other half: the queue entry has no field they could be
     * written to even if one got past, because the entry stores the receipt as
     * ONE opaque text member and has no per-field surface at all.
     */
    @Test
    fun `no persisted field could carry an Edge authorisation`() {
        val forbidden = listOf("approval", "decision", "device_trust", "operation_permitted", "vouches")
        for (field in OfflineOutboxEntry.PERSISTED_FIELDS) {
            for (word in forbidden) {
                assertFalse(
                    "'$field' is persisted by a queue entry and names an Edge verdict ('$word')",
                    field.lowercase().contains(word),
                )
            }
        }
    }

    @Test
    fun `the written field names are exactly the persisted list`() {
        assertEquals(OfflineOutboxEntry.PERSISTED_FIELDS.toSet(), entry().toJson().keys)
    }

    // -----------------------------------------------------------------------
    // Reading refuses rather than inventing
    // -----------------------------------------------------------------------

    @Test
    fun `a missing field is refused rather than defaulted`() {
        val complete = entry().toJson()
        for (field in OfflineOutboxEntry.PERSISTED_FIELDS) {
            // Two fields are legitimately absent, and both are absences that
            // mean something rather than gaps: a never-attempted entry has no
            // instant to record, and an entry no Edge has witnessed holds no
            // receipt. The second is the ordinary case for a handset that was
            // simply out of coverage, and reading it as a malformed document
            // would refuse the whole queue over the normal state of affairs.
            if (field == OfflineOutboxEntry.FIELD_LAST_ATTEMPT_AT) continue
            if (field == OfflineOutboxEntry.FIELD_EDGE_RECEIPT_JSON) continue
            val without = Json.parseToJsonElement(
                complete.toString(),
            ).jsonObject.filterKeys { it != field }
            try {
                OfflineOutboxEntry.fromJson(kotlinx.serialization.json.JsonObject(without))
                throw AssertionError("expected a missing '$field' to be refused")
            } catch (expected: MalformedOutbox) {
                assertTrue(expected.message!!.contains(field))
            }
        }
    }

    @Test
    fun `a sequence stored as a string is refused, not coerced`() {
        val broken = Json.parseToJsonElement(
            entry().toJson().toString().replace("\"device_sequence\":17", "\"device_sequence\":\"17\""),
        ).jsonObject
        try {
            OfflineOutboxEntry.fromJson(broken)
            throw AssertionError("expected a string sequence to be refused")
        } catch (expected: MalformedOutbox) {
            assertTrue(expected.message!!.contains("device_sequence"))
        }
    }

    @Test
    fun `an unknown state is refused rather than treated as queued`() {
        val broken = Json.parseToJsonElement(
            entry().toJson().toString().replace("\"local_state\":\"QUEUED\"", "\"local_state\":\"ABANDONED\""),
        ).jsonObject
        try {
            OfflineOutboxEntry.fromJson(broken)
            throw AssertionError("expected an unknown state to be refused")
        } catch (expected: MalformedOutbox) {
            assertTrue(expected.message!!.contains("ABANDONED"))
        }
    }

    // -----------------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------------

    /**
     * The payload is operational content and a log is not a need-to-know
     * boundary, so `describe` names the position and the kind and never the
     * body.
     */
    @Test
    fun `describe names the position and never the payload`() {
        val described = entry().describe()
        assertTrue(described.contains("seq=17"))
        assertTrue(described.contains("INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE"))
        assertTrue(described.contains("lease-1"))
        assertTrue("an unwitnessed entry says so", described.contains("witness=none"))
        assertTrue(
            "a witnessed entry says so and never prints the receipt",
            entry().copy(edgeReceiptJson = """{"edge_id":"edge-17"}""").describe().contains("witness=edge"),
        )
        assertFalse(
            entry().copy(edgeReceiptJson = """{"edge_id":"edge-17"}""").describe().contains("edge-17"),
        )
        assertFalse(described.contains("message_id"))
        assertFalse(described.contains("22222222-2222-4222-8222-222222222222"))
    }
}
