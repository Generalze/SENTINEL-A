package com.sentinel.field.net

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * WHAT THIS CLIENT WILL ACCEPT AS AN EDGE WITNESS, AND WHAT IT WILL NOT.
 *
 * Every assertion below is about REFUSING. That is not an accident of what was
 * easy to test: the reader's whole licence to check anything is that it can
 * only cause this device to store LESS. It cannot make a receipt valid — the
 * Edge signature is checked centrally, against a registry key and an
 * `edge_trust` state this handset does not hold and must not cache — so the
 * only useful thing it can do is decline to file something that is not a
 * receipt.
 *
 * AND EVERY REFUSAL IS A `null`, NEVER A THROW. An unreadable receipt has to
 * become NOT_WITNESSED at the classifier, and a reader that threw would leave
 * the classifier by exception rather than being classified — C18-R1A, one layer
 * down.
 * ============================================================================
 */
class EdgeReceiptTest {

    private val fingerprint = "a".repeat(64)
    private val signature = "b".repeat(86)

    private fun wire(overrides: String = "", omit: String? = null): JsonObject {
        val members = linkedMapOf(
            "schema_version" to "1",
            "edge_id" to "\"edge-17\"",
            "edge_key_id" to "\"edge-key-1\"",
            "edge_key_version" to "2",
            "witnessed_operation_fingerprint" to "\"$fingerprint\"",
            "edge_trusted_time" to "\"2026-09-05T10:00:00Z\"",
            "edge_monotonic_position" to "41",
            "claimed_edge_signature_profile" to "\"P256_ECDSA_SHA256\"",
            "edge_signature" to "\"$signature\"",
        )
        if (omit != null) members.remove(omit)
        val body = members.entries.joinToString(",") { "\"${it.key}\":${it.value}" }
        val text = if (overrides.isEmpty()) "{$body}" else "{$body,$overrides}"
        return Json.parseToJsonElement(text).jsonObject
    }

    private fun parsed(): EdgeReceipt = EdgeReceipt.fromWire(wire())!!

    // -----------------------------------------------------------------------
    // The shape it accepts
    // -----------------------------------------------------------------------

    @Test
    fun `a complete receipt reads back field for field`() {
        val receipt = parsed()
        assertEquals(1, receipt.schemaVersion)
        assertEquals("edge-17", receipt.edgeId)
        assertEquals("edge-key-1", receipt.edgeKeyId)
        assertEquals(2, receipt.edgeKeyVersion)
        assertEquals(fingerprint, receipt.witnessedOperationFingerprint)
        assertEquals("2026-09-05T10:00:00Z", receipt.edgeTrustedTime)
        assertEquals(41L, receipt.edgeMonotonicPosition)
        assertEquals("P256_ECDSA_SHA256", receipt.claimedEdgeSignatureProfile)
        assertEquals(signature, receipt.edgeSignature)
    }

    @Test
    fun `the nine members are exactly the contract's nine`() {
        assertEquals(
            listOf(
                "schema_version",
                "edge_id",
                "edge_key_id",
                "edge_key_version",
                "witnessed_operation_fingerprint",
                "edge_trusted_time",
                "edge_monotonic_position",
                "claimed_edge_signature_profile",
                "edge_signature",
            ),
            EdgeReceipt.FIELDS,
        )
    }

    /**
     * An Edge with no trusted-time anchor still has ordering, and ordering is a
     * legitimate witness. `null` here is a first-class answer, not a hole: the
     * contract's own refinement requires only that ONE of the two be present.
     */
    @Test
    fun `either witness alone is enough, and neither is not a receipt`() {
        assertNotNull(EdgeReceipt.fromWire(withNull(wire(), "edge_trusted_time")))
        assertNotNull(EdgeReceipt.fromWire(withNull(wire(), "edge_monotonic_position")))
        assertNull(
            "a receipt witnessing neither an instant nor an ordering has witnessed nothing",
            EdgeReceipt.fromWire(withNull(withNull(wire(), "edge_trusted_time"), "edge_monotonic_position")),
        )
    }

    private fun withNull(value: JsonObject, key: String): JsonObject =
        Json.parseToJsonElement(
            value.toString().replace(
                Regex("\"$key\":(\"[^\"]*\"|[0-9]+|null)"),
                "\"$key\":null",
            ),
        ).jsonObject

    // -----------------------------------------------------------------------
    // D23-10 — Edge may witness, Edge may not authorize
    // -----------------------------------------------------------------------

    /**
     * `DEVICE_EDGE_RECEIPT_FORBIDDEN_FIELDS`, one at a time.
     *
     * Each is a way of saying "I authorize" or "I vouch for the device", and
     * the contract schema is `.strict()` so each is a parse failure there. This
     * asserts the client half: a receipt carrying one is not read past, not
     * read partially, and not stored.
     */
    @Test
    fun `a receipt that tries to authorise anything is refused entirely`() {
        for (field in EdgeReceipt.FORBIDDEN_FIELDS) {
            assertNull(
                "an Edge must not be able to attach '$field'",
                EdgeReceipt.fromWire(wire(overrides = "\"$field\":true")),
            )
        }
    }

    @Test
    fun `the forbidden list is the contract's list`() {
        assertEquals(
            listOf(
                "authorises_operation",
                "authorizes_operation",
                "authorisation",
                "approval",
                "approved_by",
                "decision",
                "device_trust",
                "trust_assertion",
                "vouches_for_device",
                "policy_override",
                "operation_permitted",
            ),
            EdgeReceipt.FORBIDDEN_FIELDS,
        )
    }

    /**
     * Any unknown key at all, not only the enumerated ones.
     *
     * The named list is for diagnosis; this is the rule. `.strict()` on the
     * contract side means an unknown key never reaches a parsed receipt, and a
     * client that ignored extras would be a client reading a shape the server
     * would have refused.
     */
    @Test
    fun `an unknown member is refused rather than ignored`() {
        assertNull(EdgeReceipt.fromWire(wire(overrides = "\"edge_comment\":\"hello\"")))
    }

    // -----------------------------------------------------------------------
    // Refusing rather than salvaging
    // -----------------------------------------------------------------------

    @Test
    fun `a missing member is refused, never defaulted`() {
        for (field in EdgeReceipt.FIELDS) {
            assertNull("a receipt without '$field' is not a receipt", EdgeReceipt.fromWire(wire(omit = field)))
        }
    }

    @Test
    fun `a value of the wrong type is refused, never coerced`() {
        val broken = listOf(
            "\"schema_version\":\"1\"",
            "\"edge_key_version\":\"2\"",
            "\"edge_id\":7",
            "\"edge_signature\":null",
            "\"edge_trusted_time\":1757066400",
            "\"edge_monotonic_position\":\"41\"",
        )
        for (override in broken) {
            val key = override.substringBefore(':').trim('"')
            assertNull("$override must refuse", EdgeReceipt.fromWire(wire(omit = key, overrides = override)))
        }
    }

    @Test
    fun `a negative monotonic position is refused`() {
        assertNull(
            EdgeReceipt.fromWire(wire(omit = "edge_monotonic_position", overrides = "\"edge_monotonic_position\":-1")),
        )
    }

    /**
     * A future schema version is REFUSED, not read on a best-effort basis.
     *
     * A version bump means the signed statement's shape changed, so a
     * best-effort read would store a receipt whose signature central computes
     * over different bytes — and the failure would surface at reconciliation as
     * an Edge signature that does not verify, naming nothing anybody can act
     * on.
     */
    @Test
    fun `an unknown schema version is refused`() {
        assertNull(EdgeReceipt.fromWire(wire(omit = "schema_version", overrides = "\"schema_version\":2")))
    }

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /**
     * The stored text is the same receipt, and the SAME reader reads it back.
     *
     * The stored copy is the one that travels to central, so a second, more
     * forgiving reader for stored text would be a second opinion about what a
     * receipt is — and the stored one is the copy that had better still parse.
     */
    @Test
    fun `a receipt survives being written and read back`() {
        val original = parsed()
        val text = original.canonicalJson()
        assertEquals(original, EdgeReceipt.fromStored(text))
        assertEquals(text, EdgeReceipt.fromStored(text)!!.canonicalJson())
    }

    @Test
    fun `the canonical text is stable and sorted`() {
        assertEquals(parsed().canonicalJson(), parsed().canonicalJson())
        assertTrue(parsed().canonicalJson().startsWith("{\"claimed_edge_signature_profile\""))
    }

    @Test
    fun `stored text that is not a receipt reads back as none`() {
        for (text in listOf("", "not json", "[]", "{}", "{\"edge_id\":\"edge-17\"}")) {
            assertNull("'$text' is not a stored receipt", EdgeReceipt.fromStored(text))
        }
    }

    /**
     * The rendering names the Edge and the operation and omits the signature.
     *
     * Not because a signature is secret — it is the public output central
     * verifies — but because a log line long enough to hold one is a log line
     * nobody reads.
     */
    @Test
    fun `describe names the witness and not the signature`() {
        val described = parsed().describe()
        assertTrue(described.contains("edge-17"))
        assertTrue(described.contains(fingerprint))
        assertTrue(!described.contains(signature))
    }
}
