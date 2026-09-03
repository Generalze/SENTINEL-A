package com.sentinel.field.security

import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * WP-27 — THE INTEROPERABILITY ASSERTION. THIS IS THE POINT OF THE PASS.
 *
 * The server and this client hold TWO implementations of one canonicaliser.
 * That is unavoidable — the phone must produce the signed bytes before it can
 * sign them — and it is also the classic way two sides of a signature scheme
 * come to disagree about what was signed: silently, and only for the inputs
 * nobody thought to try.
 *
 * `services/core-api/src/modules/whisper-device-action/fixtures/`
 * `whisper-device-action-v2.interop.json` is the committed artefact both sides
 * assert against. The server's own `whisper-device-action.interop.spec.ts`
 * reads it and says, in its own words, that "a later Android test reads THIS
 * FILE and must reproduce `canonical_statement` character for character". This
 * is that test.
 *
 * THE FIXTURE IS READ WHERE IT IS COMMITTED. It is NOT copied into
 * `src/test/resources/`. A copy is a second artefact, and a second artefact
 * drifts — the server could correct its statement and this client would keep
 * passing against a stale snapshot of it, which is the exact failure the
 * fixture exists to prevent. The Android project lives in the same monorepo and
 * `android.yml` checks the whole repository out at the candidate SHA, so the
 * file is there; when it is not, this FAILS rather than skipping, because a
 * gate that cannot tell "found nothing" from "never ran" manufactures evidence.
 *
 * WHAT THIS PROVES, AND WHAT IT DOES NOT
 * --------------------------------------
 * PROVES: the bytes. Given the identity, the claims and the profile in the
 * fixture, `DeviceActionStatements` emits `canonical_statement` character for
 * character, and `CanonicalPublicKey.sha256HexUtf8` over those bytes equals
 * `canonical_statement_sha256_hex`.
 *
 * DOES NOT PROVE: the signature. ECDSA is randomised, so the recorded signature
 * is EVIDENCE, not a target — a conforming implementation produces a different
 * one over the same bytes and both verify. And the signing itself happens in
 * StrongBox, which no JVM test and no emulator can stand in for. What must
 * match byte for byte is the STATEMENT, and that is what is asserted here.
 * ============================================================================
 */
class DeviceActionStatementsInteropTest {

    private val fixture: JsonObject by lazy {
        Json.parseToJsonElement(fixtureFile().readText(Charsets.UTF_8)).jsonObject
    }

    private fun identity(): JsonObject = fixture.getValue("server_resolved_identity").jsonObject

    private fun claims(): JsonObject = fixture.getValue("client_claims").jsonObject

    private fun text(source: JsonObject, key: String): String = source.getValue(key).jsonPrimitive.content

    private fun number(source: JsonObject, key: String): Int = text(source, key).toInt()

    /**
     * The fixture's confidence, as the whole number of hundredths this client
     * can express.
     *
     * The equality is asserted rather than parsed loosely ON PURPOSE. If the
     * fixture ever carried a confidence that is not a whole hundredth, this
     * client could not reproduce its digits and the honest outcome is a failing
     * test here — not a quiet rounding that would sign a different claim.
     */
    private fun confidenceHundredths(): Int {
        assertEquals(
            "the fixture's confidence must be a whole number of hundredths",
            "0.87",
            text(claims(), "confidence"),
        )
        return 87
    }

    private fun statementFromFixture(): String = DeviceActionStatements.statement(
        contextId = text(identity(), "context_id"),
        organisationId = text(identity(), "organisation_id"),
        siteId = text(identity(), "site_id"),
        actorUserId = text(identity(), "actor_user_id"),
        deviceId = text(identity(), "device_id"),
        keyId = text(claims(), "key_id"),
        keyVersion = number(claims(), "key_version"),
        whisperSignalId = text(claims(), "whisper_signal_id"),
        whisperSignalVersion = number(claims(), "whisper_signal_version"),
        deviceActionId = text(claims(), "device_action_id"),
        recognisedAt = text(claims(), "recognised_at"),
        confidenceHundredths = confidenceHundredths(),
        antiReplayNonce = text(claims(), "anti_replay_nonce"),
        signatureProfile = fixture.getValue("server_resolved_signature_profile").jsonPrimitive.content,
    )

    // -----------------------------------------------------------------------
    // The bytes
    // -----------------------------------------------------------------------

    @Test
    fun `the canonical statement is byte-identical to the server's`() {
        assertEquals(
            "the Kotlin canonical statement must equal the committed server bytes exactly",
            text(fixture, "canonical_statement"),
            statementFromFixture(),
        )
    }

    @Test
    fun `the SHA-256 of those bytes is the fixture's recorded digest`() {
        assertEquals(
            text(fixture, "canonical_statement_sha256_hex"),
            CanonicalPublicKey.sha256HexUtf8(statementFromFixture()),
        )
        // The same value through the client's own named recipe, so the digest a
        // handset would log and the digest a server audit row carries cannot be
        // produced two different ways.
        assertEquals(
            text(fixture, "canonical_statement_sha256_hex"),
            DeviceActionStatements.fingerprint(
                contextId = text(identity(), "context_id"),
                organisationId = text(identity(), "organisation_id"),
                siteId = text(identity(), "site_id"),
                actorUserId = text(identity(), "actor_user_id"),
                deviceId = text(identity(), "device_id"),
                keyId = text(claims(), "key_id"),
                keyVersion = number(claims(), "key_version"),
                whisperSignalId = text(claims(), "whisper_signal_id"),
                whisperSignalVersion = number(claims(), "whisper_signal_version"),
                deviceActionId = text(claims(), "device_action_id"),
                recognisedAt = text(claims(), "recognised_at"),
                confidenceHundredths = confidenceHundredths(),
                antiReplayNonce = text(claims(), "anti_replay_nonce"),
                signatureProfile = fixture.getValue("server_resolved_signature_profile").jsonPrimitive.content,
            ),
        )
    }

    /**
     * The one non-integer in any Sentinel statement, printed the same on both
     * sides.
     *
     * This is the assertion that would catch the failure mode `CanonicalJson`
     * refuses `Double` to avoid: the VALUE agreeing while the DIGITS do not.
     */
    @Test
    fun `the confidence digits this client emits are the digits the server emitted`() {
        assertEquals("0.87", CanonicalJson.JsonNumber.ofHundredths(87).text)
        assertTrue(
            "the fixture's canonical statement must carry the same digits",
            text(fixture, "canonical_statement").contains("\"confidence\":0.87,"),
        )
    }

    // -----------------------------------------------------------------------
    // The shape agreements the bytes depend on
    // -----------------------------------------------------------------------

    @Test
    fun `the domain and the profile are the ones the fixture names`() {
        assertEquals(
            text(fixture.getValue("domains").jsonObject, "statement"),
            DeviceActionStatements.DOMAIN,
        )
        assertEquals(
            text(fixture, "server_resolved_signature_profile"),
            DeviceStatements.SIGNATURE_PROFILE,
        )
        assertEquals("DEVICE_ACTION", text(claims(), "modality"))
        assertEquals(DeviceActionStatements.MODALITY, text(claims(), "modality"))
        assertEquals(DeviceActionStatements.SCHEMA_VERSION, number(claims(), "schema_version"))
    }

    /**
     * The CLAIMS this client builds are the claims the fixture records — the
     * same eleven names, no more and no fewer.
     *
     * A client that sent a twelfth field would be refused by the server's
     * `.strict()` parse; a client that sent eleven DIFFERENT ones would be
     * refused too. Both are caught here rather than on a handset.
     */
    @Test
    fun `the client's claim field set is exactly the fixture's`() {
        val built = DeviceActionStatements.claims(
            keyId = text(claims(), "key_id"),
            keyVersion = number(claims(), "key_version"),
            whisperSignalId = text(claims(), "whisper_signal_id"),
            whisperSignalVersion = number(claims(), "whisper_signal_version"),
            deviceActionId = text(claims(), "device_action_id"),
            recognisedAt = text(claims(), "recognised_at"),
            confidenceHundredths = confidenceHundredths(),
            antiReplayNonce = text(claims(), "anti_replay_nonce"),
            signature = text(claims(), "signature"),
        )
        assertEquals(claims().keys.sorted(), built.keys.sorted())
    }

    /**
     * The statement's field set is the fixture's field set.
     *
     * Compared as SORTED KEY LISTS read out of the fixture's own canonical
     * string, so this fails on a field added, removed or renamed on either side
     * — including the ones a reader is most likely to think are harmless.
     */
    @Test
    fun `the statement's field set is exactly the fixture's`() {
        val expected = keysOfCanonicalObject(text(fixture, "canonical_statement"))
        val actual = keysOfCanonicalObject(statementFromFixture())
        assertEquals(expected, actual)
        assertEquals(17, actual.size)
        assertTrue("the statement must bind the server-resolved profile", actual.contains("signature_profile"))
        assertTrue("the statement must never carry the signature it produces", !actual.contains("signature"))
    }

    // -----------------------------------------------------------------------
    // Reading the committed fixture
    // -----------------------------------------------------------------------

    /**
     * The top-level keys of a canonical JSON object, sorted.
     *
     * It PARSES the string with the JSON reader rather than scanning it, so the
     * extraction cannot be subtly wrong about the thing the assertion above
     * depends on. Sorting is redundant for canonical bytes — the canonicaliser
     * already sorted them — and is applied anyway so a failure reads as "this
     * field set differs" rather than "these two orders differ".
     */
    private fun keysOfCanonicalObject(canonical: String): List<String> =
        Json.parseToJsonElement(canonical).jsonObject.keys.sorted()

    /**
     * The fixture, where the server committed it.
     *
     * Walks up from the test's working directory — the Android module — so the
     * same test passes whether it is run from the module or from the repository
     * root. It never falls back to a copy, and it never passes without reading
     * something.
     */
    private fun fixtureFile(): File {
        val relative =
            "services/core-api/src/modules/whisper-device-action/fixtures/whisper-device-action-v2.interop.json"
        var directory: File? = File(System.getProperty("user.dir")).absoluteFile
        var depth = 0
        while (directory != null && depth < 8) {
            val resolved = File(directory, relative)
            if (resolved.isFile) return resolved
            directory = directory.parentFile
            depth += 1
        }
        throw AssertionError(
            "the committed WP-27 interop fixture was not found at '$relative' from " +
                "${System.getProperty("user.dir")} or any of its parents; an interop test " +
                "must never pass without reading the artefact it interoperates with",
        )
    }

    @Test
    fun `the fixture is the one this test believes it is reading`() {
        assertEquals("sentinel.whisper.device-action.v2.interop.1", text(fixture, "fixture_id"))
        assertEquals(1, number(fixture, "fixture_version"))
        // The warning that the committed key is a test key must not be quietly
        // deleted, for the same reason the server's own spec asserts it.
        assertTrue(
            "the fixture must keep saying that its key material is a test key",
            text(fixture, "key_material_warning").contains("DETERMINISTIC TEST KEY"),
        )
        // The two exclusions the field-set assertion above depends on, read from
        // the fixture rather than restated here.
        val expected = fixture.getValue("expected").jsonObject
        assertEquals("true", text(expected, "signature_is_excluded_from_canonical_statement"))
        assertEquals("VERIFIED_STATEMENT", text(expected, "verification_outcome"))
    }
}
