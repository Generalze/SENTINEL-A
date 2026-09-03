package com.sentinel.field.net

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/**
 * ============================================================================
 * WP-27 — HOW THE DEVICE-ACTION SUBMISSION IS WIRED.
 *
 * WHY THIS IS A SOURCE TEST, STATED PLAINLY. `GatewaySession` takes a
 * `SentinelHttp` whose only constructor builds a real OkHttp client, so driving
 * `submitDeviceAction` from a unit test would mean either a network round trip
 * or restructuring production code to suit a test. This machine has no JDK,
 * Gradle or Android SDK — nothing here has been compiled locally and hosted CI
 * is the only verification — so restructuring working code to make a test
 * convenient is a poor trade. The BYTES, which are the part that has to be
 * exactly right, are proven behaviourally in
 * `DeviceActionStatementsInteropTest` and `DeviceActionStatementsTest`; what
 * remains is the wiring, and this asserts that structurally.
 *
 * It is a guard against a regression, and it is honest about being a guard
 * rather than a proof. COMMENTS ARE NOT STRIPPED, so it errs towards a false
 * alarm — a comment that quoted a profile name would fail it — never towards a
 * false clean.
 * ============================================================================
 */
class DeviceActionSubmissionSourceTest {

    private fun gatewaySource(): String {
        val file = File("src/main/kotlin/com/sentinel/field/net/GatewaySession.kt")
        assertTrue("expected to find GatewaySession.kt at ${file.absolutePath}", file.isFile)
        return file.readText()
    }

    /**
     * The body of ONE function, delimited by BALANCED BRACES — the same
     * extractor `UnreadableSuccessSourceTest` uses, and for the same reason: a
     * "read until the next `fun`" heuristic silently runs on into later
     * functions, and a test whose extraction is wrong reports on code it was
     * never asked about.
     */
    private fun functionBody(source: String, signature: String): String {
        val start = source.indexOf(signature)
        assertTrue("expected to find `$signature`", start >= 0)
        val open = source.indexOf('{', start + signature.length)
        assertTrue("expected an opening brace for `$signature`", open >= 0)
        var depth = 0
        var index = open
        while (index < source.length) {
            when (source[index]) {
                '{' -> depth += 1
                '}' -> {
                    depth -= 1
                    if (depth == 0) return source.substring(open, index + 1)
                }
            }
            index += 1
        }
        throw AssertionError("unbalanced braces reading `$signature`")
    }

    // -----------------------------------------------------------------------
    // The route, and the two signatures it carries
    // -----------------------------------------------------------------------

    @Test
    fun `the submission posts to the server's own device-action route`() {
        val body = functionBody(gatewaySource(), "fun submitDeviceAction")
        assertTrue(
            "the route must be the one device-gateway.controller.ts exposes",
            body.contains("\"\$GATEWAY/operations/device-action\""),
        )
        // The target is resolved by the SERVER from the persisted context, so
        // there is no target id in the path and none is sent.
        assertFalse("no id may be interpolated into the device-action path", body.contains("device-action/\$"))
    }

    @Test
    fun `the statement is signed by the hardware key and its signature becomes a claim`() {
        val body = functionBody(gatewaySource(), "fun submitDeviceAction")
        assertTrue(
            "the v2 statement must be signed through the StrongBox key manager",
            body.contains("keys.signCanonicalStatement(statement)"),
        )
        // ONE claims map, built once, so the digest the proof covers and the
        // body that is posted cannot drift apart.
        assertEquals(
            "the claims must be built exactly once",
            1,
            occurrences(body, "DeviceActionStatements.claims("),
        )
        assertTrue(
            "the envelope digest must be taken over that same map",
            body.contains("semanticPayload = claims"),
        )
        assertTrue("the posted body must be that same map", body.contains("jsonPayload(claims)"))
    }

    /**
     * `WHISPER_DEVICE_ACTION`, never `FIELD_OPERATION`.
     *
     * The purpose is inside the signed proof and its permitted trust is
     * `['TRUSTED']` alone (W21-05) — a strictly narrower gate than the Field
     * operations'. A proof minted under the wider purpose is refused here, so
     * getting this wrong is not a cosmetic slip.
     */
    @Test
    fun `the proof is minted under the device-action purpose alone`() {
        val body = functionBody(gatewaySource(), "fun submitDeviceAction")
        assertTrue(body.contains("DeviceStatements.PURPOSE_WHISPER_DEVICE_ACTION"))
        assertFalse(body.contains("PURPOSE_FIELD_OPERATION"))
        assertFalse(body.contains("PURPOSE_RECONNECT_HANDSHAKE"))
    }

    /**
     * C11-04 — the client names no algorithm anywhere on this path.
     *
     * The profile appears in the bytes that are SIGNED, because the server puts
     * it there; it must appear in nothing this method chooses or sends.
     */
    @Test
    fun `the submission names no algorithm, profile, curve or digest`() {
        val body = functionBody(gatewaySource(), "fun submitDeviceAction")
        val violations = mutableListOf<String>()
        for (forbidden in listOf("P256", "ECDSA", "SHA-", "secp", "prime256", "SIGNATURE_PROFILE", "signature_profile")) {
            if (body.contains(forbidden)) violations.add("submitDeviceAction names '$forbidden'")
        }
        if (violations.isNotEmpty()) {
            fail(violations.joinToString("\n"))
        }
    }

    // -----------------------------------------------------------------------
    // C18-R1 — an unproven outcome is reported as unproven
    // -----------------------------------------------------------------------

    /**
     * A device action spends a ONE-SHOT nonce, so a lost response is not a
     * refusal.
     *
     * The three older surfaces may treat every non-2xx as terminal — press the
     * button again and the same field state is sent. This one may not: the
     * server may have consumed the nonce and committed while the answer was
     * lost, and reporting that as a refusal would tell an operative that an
     * action which HAPPENED did not.
     */
    @Test
    fun `an unprovable device-action outcome is not classified as a refusal`() {
        val source = gatewaySource()
        assertTrue(
            "the one status that must not be read as a refusal has to be a named constant",
            source.contains("private const val COMPLETION_UNKNOWN = 409"),
        )
        val body = functionBody(source, "private fun submitUnprovable")
        assertTrue(
            "only an authoritative 4xx that is not the server's own 409 may be terminal",
            body.contains("answer.status in 400..499 && answer.status != COMPLETION_UNKNOWN"),
        )
        assertTrue(
            "a refusal may only be produced on that terminal branch",
            body.contains("if (terminal) return CeremonyStep.refused("),
        )
        assertTrue(
            "everything else must answer completionUnknown",
            body.contains("return CeremonyStep.completionUnknown(answer.status, answer.text)"),
        )
        assertTrue(
            "the device action must submit through that classifier",
            functionBody(source, "fun submitDeviceAction").contains("submitUnprovable("),
        )
    }

    /**
     * The three WP-25 surfaces are UNTOUCHED by this work package.
     *
     * Stated as an assertion rather than a promise: WP-27 added a fourth
     * surface, and it must not have quietly changed the classification of the
     * three that were already accepted.
     */
    @Test
    fun `the three older operations still go through the original submit path`() {
        val source = gatewaySource()
        for (surface in listOf("fun updateFieldState", "fun actOnAssignment", "fun acknowledgeMessage")) {
            assertTrue(
                "$surface must still submit through `operate`",
                functionBody(source, surface).contains("return operate("),
            )
        }
    }

    /**
     * The payload converter is explicit by type and throws on anything else.
     *
     * A `Double` here would re-enter the number-printing problem `CanonicalJson`
     * refuses `Double` to avoid: the value on the wire agreeing with the value
     * that was signed while the DIGITS do not.
     */
    @Test
    fun `the posted payload carries the digits that were signed`() {
        val body = functionBody(gatewaySource(), "private fun jsonPayload")
        assertTrue(
            "a canonical number must reach the wire through its own decimal text",
            body.contains("BigDecimal(value.text)"),
        )
        assertFalse("no floating-point value may be serialised here", body.contains("Double"))
        assertTrue("an unconvertible value must throw rather than be dropped", body.contains("else -> throw"))
    }

    private fun occurrences(text: String, needle: String): Int = text.split(needle).size - 1
}
