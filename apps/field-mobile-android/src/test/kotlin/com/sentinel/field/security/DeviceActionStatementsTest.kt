package com.sentinel.field.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * ============================================================================
 * WP-27 — WHAT THE DEVICE-ACTION STATEMENT BINDS, AND WHAT THE CLIENT REFUSES
 * TO SAY.
 *
 * `DeviceActionStatementsInteropTest` proves the BYTES against the committed
 * server fixture. This file proves the two properties a fixture cannot: that
 * every bound field actually changes the statement, and that the claim half
 * names no algorithm, profile, curve, digest or key of its own.
 *
 * WHY "EVERY FIELD CHANGES THE BYTES" IS A SECURITY TEST AND NOT A TAUTOLOGY.
 * A field that is documented as bound but silently dropped from the builder
 * produces a signature that is valid for a statement it was never meant to
 * cover — and every such omission is invisible until somebody replays one
 * operative's action as another's. The fixture would not catch it: a dropped
 * field whose fixture value happens to be the one being compared still matches.
 * ============================================================================
 */
class DeviceActionStatementsTest {

    // The interop fixture's own values, so a reader can line the two files up.
    private val contextId = "9f1c0c1e-0000-4000-8000-000000000001"
    private val organisationId = "wp27-interop-org"
    private val siteId = "wp27-interop-site"
    private val actorUserId = "wp27-interop-operative"
    private val deviceId = "9f1c0c1e-0000-4000-8000-0000000000de"
    private val keyId = "wp27-interop-key"
    private val keyVersion = 1
    private val whisperSignalId = "wp27-interop-signal"
    private val whisperSignalVersion = 1
    private val deviceActionId = "wp27-interop-action"
    private val recognisedAt = "2026-03-01T12:00:00.000Z"
    private val confidenceHundredths = 87
    private val antiReplayNonce = "wp27-interop-nonce-0001"
    private val signature =
        "OXX1Nh05GIefkhyX5eQqxouhWy6-vZP13oD6br2ePpkDSzI9dVTK9_7-hFqe4E3IXnSH64qVTNaAZsT6qz9o5w"

    private fun statement(
        contextId: String = this.contextId,
        organisationId: String = this.organisationId,
        siteId: String = this.siteId,
        actorUserId: String = this.actorUserId,
        deviceId: String = this.deviceId,
        keyId: String = this.keyId,
        keyVersion: Int = this.keyVersion,
        whisperSignalId: String = this.whisperSignalId,
        whisperSignalVersion: Int = this.whisperSignalVersion,
        deviceActionId: String = this.deviceActionId,
        recognisedAt: String = this.recognisedAt,
        confidenceHundredths: Int = this.confidenceHundredths,
        antiReplayNonce: String = this.antiReplayNonce,
        signatureProfile: String = DeviceStatements.SIGNATURE_PROFILE,
    ): String = DeviceActionStatements.statement(
        contextId = contextId,
        organisationId = organisationId,
        siteId = siteId,
        actorUserId = actorUserId,
        deviceId = deviceId,
        keyId = keyId,
        keyVersion = keyVersion,
        whisperSignalId = whisperSignalId,
        whisperSignalVersion = whisperSignalVersion,
        deviceActionId = deviceActionId,
        recognisedAt = recognisedAt,
        confidenceHundredths = confidenceHundredths,
        antiReplayNonce = antiReplayNonce,
        signatureProfile = signatureProfile,
    )

    private fun claims(): Map<String, Any?> = DeviceActionStatements.claims(
        keyId = keyId,
        keyVersion = keyVersion,
        whisperSignalId = whisperSignalId,
        whisperSignalVersion = whisperSignalVersion,
        deviceActionId = deviceActionId,
        recognisedAt = recognisedAt,
        confidenceHundredths = confidenceHundredths,
        antiReplayNonce = antiReplayNonce,
        signature = signature,
    )

    // -----------------------------------------------------------------------
    // Every bound field is actually bound
    // -----------------------------------------------------------------------

    @Test
    fun `changing any bound field changes the signed bytes`() {
        val baseline = statement()
        val variants = linkedMapOf(
            "context_id" to statement(contextId = "9f1c0c1e-0000-4000-8000-000000000002"),
            "organisation_id" to statement(organisationId = "other-org"),
            "site_id" to statement(siteId = "other-site"),
            "actor_user_id" to statement(actorUserId = "other-operative"),
            "device_id" to statement(deviceId = "9f1c0c1e-0000-4000-8000-0000000000df"),
            "key_id" to statement(keyId = "other-key"),
            "key_version" to statement(keyVersion = 2),
            "whisper_signal_id" to statement(whisperSignalId = "other-signal"),
            "whisper_signal_version" to statement(whisperSignalVersion = 2),
            "device_action_id" to statement(deviceActionId = "other-action"),
            "recognised_at" to statement(recognisedAt = "2026-03-01T12:00:01.000Z"),
            "confidence" to statement(confidenceHundredths = 86),
            "anti_replay_nonce" to statement(antiReplayNonce = "wp27-interop-nonce-0002"),
            "signature_profile" to statement(signatureProfile = "SOMETHING_ELSE"),
        )
        for (entry in variants) {
            assertNotEquals("${entry.key} is documented as bound but does not change the bytes", baseline, entry.value)
        }
        // And no two variants collide, which is what a delimiter-joined
        // statement would allow and canonical JSON does not.
        val all = variants.values.toMutableList()
        all.add(baseline)
        assertEquals("two different statements produced the same bytes", all.size, all.toSet().size)
    }

    /**
     * The domain is IN the bytes, so a v2 preimage cannot collide with a v1 one
     * or with any of the four WP-23..26 statements even if every other field
     * were identical.
     */
    @Test
    fun `the domain is bound and is distinct from every other statement this client makes`() {
        assertTrue(statement().contains("\"domain\":\"sentinel.whisper.device-action.v2\""))
        val domains = listOf(
            DeviceActionStatements.DOMAIN,
            DeviceStatements.POSSESSION_DOMAIN,
            DeviceStatements.REQUEST_PROOF_DOMAIN,
            DeviceStatements.ESTABLISHMENT_CHALLENGE_DOMAIN,
            DeviceStatements.OPERATION_ENVELOPE_DOMAIN,
        )
        assertEquals(domains.size, domains.toSet().size)
        // NOT v1's. WP-27 versions forward; it does not reinterpret the frozen
        // Milestone 2 domain.
        assertNotEquals("sentinel.whisper.device-action.v1", DeviceActionStatements.DOMAIN)
    }

    // -----------------------------------------------------------------------
    // What the client refuses to say (C11-04 / W21-05 / D23-05)
    // -----------------------------------------------------------------------

    /**
     * The ALGORITHM is the registry's answer for the resolved key, and this
     * client has no field for it.
     *
     * The check is on the claim NAMES and on the claim VALUES: a profile string
     * smuggled into some other field would be just as much a claim about the
     * algorithm as a field called `signature_profile`.
     */
    @Test
    fun `the claims name no algorithm, profile, curve, digest or key`() {
        val forbiddenNames = listOf(
            "signature_algorithm",
            "signature_profile",
            "claimed_signature_profile",
            "curve",
            "hash_algorithm",
            "digest_algorithm",
            "key_type",
            "public_key",
            "device_trust",
            "trust",
            "context_id",
            "organisation_id",
            "site_id",
            "actor_user_id",
            "device_id",
        )
        val violations = mutableListOf<String>()
        val built = claims()
        for (name in forbiddenNames) {
            if (built.containsKey(name)) violations.add("the claims carry '$name'")
        }
        for (entry in built) {
            val value = entry.value
            if (value is String && value.contains("P256")) violations.add("'${entry.key}' names the profile")
            if (value is String && value.contains("ECDSA")) violations.add("'${entry.key}' names the algorithm")
            if (value is String && value.contains("secp256")) violations.add("'${entry.key}' names the curve")
        }
        if (violations.isNotEmpty()) {
            fail("C11-04 — the device must not name the algorithm or an identity the server owns:\n" +
                violations.joinToString("\n"))
        }
    }

    /** Eleven fields, and the same eleven the server's `.strict()` parse admits. */
    @Test
    fun `the claim field set is exactly the eleven the contract declares`() {
        assertEquals(
            listOf(
                "anti_replay_nonce",
                "confidence",
                "device_action_id",
                "key_id",
                "key_version",
                "modality",
                "recognised_at",
                "schema_version",
                "signature",
                "whisper_signal_id",
                "whisper_signal_version",
            ),
            claims().keys.sorted(),
        )
    }

    /**
     * The statement excludes the signature; the claims carry it. Neither
     * inclusion is decorative: a statement that covered its own signature could
     * not be produced, and claims without one deliver nothing.
     */
    @Test
    fun `the signature is the output of the statement and the payload of the claims`() {
        assertFalse(statement().contains(signature))
        assertEquals(signature, claims()["signature"])
    }

    // -----------------------------------------------------------------------
    // The confidence field, which is the only non-integer in any statement
    // -----------------------------------------------------------------------

    @Test
    fun `confidence is emitted as a canonical JSON number, not a string`() {
        assertTrue(statement().contains("\"confidence\":0.87,"))
        assertFalse("a quoted confidence would be a different claim", statement().contains("\"confidence\":\""))
    }

    @Test
    fun `the whole hundredths range prints the digits a shortest-round-trip printer prints`() {
        assertEquals("0", CanonicalJson.JsonNumber.ofHundredths(0).text)
        assertEquals("0.01", CanonicalJson.JsonNumber.ofHundredths(1).text)
        assertEquals("0.05", CanonicalJson.JsonNumber.ofHundredths(5).text)
        assertEquals("0.1", CanonicalJson.JsonNumber.ofHundredths(10).text)
        assertEquals("0.5", CanonicalJson.JsonNumber.ofHundredths(50).text)
        assertEquals("0.87", CanonicalJson.JsonNumber.ofHundredths(87).text)
        assertEquals("0.9", CanonicalJson.JsonNumber.ofHundredths(90).text)
        assertEquals("0.99", CanonicalJson.JsonNumber.ofHundredths(99).text)
        assertEquals("1", CanonicalJson.JsonNumber.ofHundredths(100).text)
        // No trailing zero survives, and no value prints a redundant fraction —
        // both are what `JSON.stringify` does with the same double, and the two
        // sides must agree on the digits, not merely on the value.
        for (hundredths in 0..100) {
            val text = CanonicalJson.JsonNumber.ofHundredths(hundredths).text
            assertEquals("$hundredths / 100 round-trips", hundredths / 100.0, text.toDouble(), 0.0)
            assertFalse("$text carries a trailing zero", text.length > 1 && text.endsWith("0"))
        }
    }

    @Test
    fun `a confidence outside the expressible range is refused, never clamped`() {
        refuse("a negative confidence") { CanonicalJson.JsonNumber.ofHundredths(-1) }
        refuse("a confidence above one") { CanonicalJson.JsonNumber.ofHundredths(101) }
        refuse("a negative confidence in a statement") { statement(confidenceHundredths = -1) }
        refuse("a confidence above one in a statement") { statement(confidenceHundredths = 101) }
        refuse("a negative confidence in the claims") {
            DeviceActionStatements.claims(
                keyId = keyId,
                keyVersion = keyVersion,
                whisperSignalId = whisperSignalId,
                whisperSignalVersion = whisperSignalVersion,
                deviceActionId = deviceActionId,
                recognisedAt = recognisedAt,
                confidenceHundredths = -1,
                antiReplayNonce = antiReplayNonce,
                signature = signature,
            )
        }
    }

    // -----------------------------------------------------------------------
    // The gateway envelope this submission travels in
    // -----------------------------------------------------------------------

    /**
     * The kind fixes the target type, and the target is the OPERATIVE
     * THEMSELVES — the server resolves it from the persisted context, so there
     * is no target id in the route and none is sent.
     */
    @Test
    fun `DEVICE_ACTION maps to the target type the server fixes for it`() {
        assertEquals("DEVICE_ACTION_STATEMENT", DeviceStatements.TARGET_TYPE_FOR_KIND["DEVICE_ACTION"])
    }

    /**
     * The whole envelope, as bytes.
     *
     * Pinned rather than recomputed, so a change to the envelope builder, to the
     * claims, or to how a number is printed fails HERE — with a readable diff —
     * instead of on a handset as a signature that mysteriously does not verify.
     */
    @Test
    fun `the device-action envelope is the shape the server builds`() {
        val envelope = DeviceStatements.operationEnvelopeStatement(
            operationKind = "DEVICE_ACTION",
            organisationId = organisationId,
            siteId = siteId,
            actorUserId = actorUserId,
            deviceId = deviceId,
            targetId = actorUserId,
            semanticPayload = claims(),
        )
        // Written with escaped quotes rather than raw strings, exactly as
        // `DeviceStatementsTest` writes its own expected envelope: a raw string
        // whose content begins or ends with a quote is the one place Kotlin's
        // triple-quote lexing is worth not having an opinion about.
        assertEquals(
            "{\"actor_user_id\":\"wp27-interop-operative\"," +
                "\"device_id\":\"9f1c0c1e-0000-4000-8000-0000000000de\"," +
                "\"domain\":\"sentinel.wp25.device-gateway.operation-envelope.v1\"," +
                "\"operation_kind\":\"DEVICE_ACTION\",\"organisation_id\":\"wp27-interop-org\"," +
                "\"schema_version\":1," +
                "\"semantic_payload\":{\"anti_replay_nonce\":\"wp27-interop-nonce-0001\"," +
                "\"confidence\":0.87,\"device_action_id\":\"wp27-interop-action\"," +
                "\"key_id\":\"wp27-interop-key\",\"key_version\":1,\"modality\":\"DEVICE_ACTION\"," +
                "\"recognised_at\":\"2026-03-01T12:00:00.000Z\",\"schema_version\":2," +
                "\"signature\":\"$signature\"," +
                "\"whisper_signal_id\":\"wp27-interop-signal\",\"whisper_signal_version\":1}," +
                "\"site_id\":\"wp27-interop-site\",\"target_id\":\"wp27-interop-operative\"," +
                "\"target_type\":\"DEVICE_ACTION_STATEMENT\"}",
            envelope,
        )
        val digest = DeviceStatements.operationEnvelopeDigest(
            operationKind = "DEVICE_ACTION",
            organisationId = organisationId,
            siteId = siteId,
            actorUserId = actorUserId,
            deviceId = deviceId,
            targetId = actorUserId,
            semanticPayload = claims(),
        )
        assertEquals("839c65bea8caadc0a23c2dbc709eb103abfb477f93e4cb2c0e8936a5ee1a912e", digest)
        // The digest the proof carries is SHA-256 of those exact bytes, and of
        // nothing else — never of "whatever JSON arrived".
        assertEquals(CanonicalPublicKey.sha256HexUtf8(envelope), digest)
    }

    /**
     * The proof this operation is minted under is NOT the Field-operation one.
     *
     * `WHISPER_DEVICE_ACTION` is admitted for TRUSTED devices alone (W21-05), a
     * strictly narrower gate, and the purpose is inside the signed proof — so a
     * proof minted under the wider purpose is refused for this route rather than
     * accepted as near enough.
     */
    @Test
    fun `the device-action purpose is its own and is not the Field-operation one`() {
        assertEquals("WHISPER_DEVICE_ACTION", DeviceStatements.PURPOSE_WHISPER_DEVICE_ACTION)
        assertNotEquals(DeviceStatements.PURPOSE_FIELD_OPERATION, DeviceStatements.PURPOSE_WHISPER_DEVICE_ACTION)
        assertNotEquals(DeviceStatements.PURPOSE_RECONNECT_HANDSHAKE, DeviceStatements.PURPOSE_WHISPER_DEVICE_ACTION)
    }

    private fun refuse(what: String, block: () -> Unit) {
        try {
            block()
            fail("expected $what to be refused")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message != null)
        }
    }
}
