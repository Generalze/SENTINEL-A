package com.sentinel.field.net

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * C18-R1A — AN UNREADABLE SUCCESS IS "UNKNOWN", NOT AN ESCAPE.
 *
 * `classifySubmission` and `requestAttestationChallenge` both DOCUMENTED that a
 * 2xx they cannot read becomes `COMPLETION_UNKNOWN`, and neither did it: the
 * by-name readers throw when a field is missing, null or the wrong shape, so a
 * malformed success left the classifier by exception instead of being
 * classified. That is the same defect C18-R1 corrected one layer out — an
 * answer whose completion cannot be proved was being turned into something
 * other than "unknown" — and on the submit path it is the more dangerous half,
 * because the server may already have committed the enrollment request.
 *
 * WHY THIS IS A SOURCE TEST AND NOT A BEHAVIOURAL ONE.
 *
 * The behaviour is exercised in `ResponseReaderTest`, which proves the readers
 * throw on exactly these three shapes. What cannot be proven from here is the
 * WIRING: `EnrollmentCeremony` takes a `SentinelHttp` whose only constructor
 * builds a real OkHttp client, so driving `classifySubmission` from a unit test
 * would mean either a network round trip or restructuring production code to
 * suit a test. This machine has no JDK, Gradle or Android SDK — nothing here
 * has been compiled, and hosted CI is the only verification — so restructuring
 * working code to make a test convenient is a poor trade.
 *
 * So this asserts the property structurally: both extraction sites are wrapped,
 * and both wrappings answer `completionUnknown`. It is a real guard against the
 * defect returning, and it is honest about being a guard rather than a proof.
 */
class UnreadableSuccessSourceTest {

    private fun source(name: String): String {
        val file = File("src/main/kotlin/com/sentinel/field/net/$name")
        assertTrue("expected to find $name at ${file.absolutePath}", file.isFile)
        return file.readText()
    }

    /**
     * The body of ONE function, delimited by BALANCED BRACES.
     *
     * A "read until the next `fun`" heuristic is not good enough, and I proved
     * that before shipping it: `classifySubmission` is followed by comment
     * blocks and a `data class`, so a naive slice ran on into later functions
     * and picked up five `.text(` calls belonging to them. A test whose
     * extraction is wrong reports on code it was never asked about.
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

    /**
     * The index of the REAL `} catch (` handler, not the word "catch" wherever
     * it happens to appear. The production comment above the guarded block uses
     * the word in prose, and searching for it naively put the handler BEFORE
     * the `try` — which made every wrapped `.text(` look unwrapped. Caught by
     * simulating this test against the real file before shipping it.
     */
    private fun catchIndexOf(body: String, tryIndex: Int): Int {
        val index = body.indexOf("} catch (", tryIndex)
        assertTrue("expected a `} catch (` handler after the try", index >= 0)
        return index
    }

    @Test
    fun `the submit classifier wraps its success extraction and answers unknown`() {
        val body = functionBody(source("EnrollmentCeremony.kt"), "private fun classifySubmission")

        assertTrue(
            "classifySubmission must wrap the success-body extraction in try/catch",
            body.contains("try {") && body.contains("catch"),
        )
        // The catch must produce COMPLETION_UNKNOWN — not a refusal, and not a
        // rethrow. A refusal would tell the operative the request did not
        // happen, when it may well have.
        val afterCatch = body.substring(catchIndexOf(body, body.indexOf("try {")))
        assertTrue(
            "the catch on the success extraction must answer completionUnknown",
            afterCatch.contains("completionUnknown"),
        )
        assertTrue(
            "the catch must not turn an unreadable success into a refusal",
            !afterCatch.substringBefore("return CeremonyStep.ok").contains("refusal("),
        )
    }

    @Test
    fun `phase zero wraps its success extraction and answers unknown`() {
        val body = functionBody(source("EnrollmentCeremony.kt"), "fun requestAttestationChallenge")

        assertTrue(
            "requestAttestationChallenge must wrap its extraction in try/catch",
            body.contains("try {") && body.contains("catch"),
        )
        assertTrue(
            "the catch must answer completionUnknown",
            body.substring(catchIndexOf(body, body.indexOf("try {"))).contains("completionUnknown"),
        )
    }

    @Test
    fun `phase zero treats only an authoritative 4xx as terminal`() {
        // C18-R3. A transport failure (status 0) or a 5xx says nothing
        // authoritative about a grant that this phase only PROBES, so it must
        // not be classified as a refusal.
        val body = functionBody(source("EnrollmentCeremony.kt"), "fun requestAttestationChallenge")

        assertTrue(
            "phase 0 must gate its refusal on a 4xx status",
            body.contains("answer.status in 400..499"),
        )
        assertTrue(
            "phase 0 must answer completionUnknown for anything that is not an authoritative refusal",
            body.contains("else CeremonyStep.completionUnknown"),
        )
    }

    @Test
    fun `both readers that can throw are the ones that are wrapped`() {
        // Guards against a future field being read OUTSIDE the try, which would
        // silently reopen the escape.
        val source = source("EnrollmentCeremony.kt")
        for (signature in listOf("private fun classifySubmission", "fun requestAttestationChallenge")) {
            val body = functionBody(source, signature)
            val tryIndex = body.indexOf("try {")
            assertTrue("$signature: expected a try block", tryIndex >= 0)
            val catchIndex = catchIndexOf(body, tryIndex)
            val outsideTry = body.substring(0, tryIndex) + body.substring(catchIndex)
            assertEquals(
                "$signature: every `.text(` extraction must sit inside the wrapped block",
                0,
                Regex("""\.text\(""").findAll(outsideTry).count(),
            )
        }
    }
}
