package com.sentinel.field.net

import com.sentinel.field.store.OfflineEnqueueResult
import com.sentinel.field.store.OfflineOutbox
import com.sentinel.field.store.OfflineOutboxEntry
import com.sentinel.field.store.ProtectedFileStore
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * WHAT THIS CLIENT MAY CONCLUDE FROM ONE ANSWER, AND WHAT IT MAY THEREFORE
 * DISCARD.
 *
 * The classifier is a companion function over an explicit `SentinelHttp.Answer`
 * rather than a private method reached through the network, and that shape is
 * the reason this file exists at all. `UnreadableSuccessSourceTest` had to
 * assert the equivalent property STRUCTURALLY — by reading the source — because
 * `EnrollmentCeremony` could only be driven through a real OkHttp client. This
 * machine has no JDK, Gradle or Android SDK, and hosted CI is the only
 * verification, so a property that can be proven by execution rather than by
 * text is worth arranging for. Every branch below is executed.
 *
 * THE ASYMMETRY UNDER TEST, STATED ONCE: the server converges a duplicate
 * submission through its receipt machinery, so a repeated request costs one
 * repeated request. A dropped acknowledgement costs the acknowledgement, and
 * nobody finds out. Every ambiguous outcome therefore keeps the entry.
 * ============================================================================
 */
class OfflineSubmissionTest {

    private class FakeProtectedFile(var content: String? = null) : ProtectedFileStore {
        override fun read(): String? = content

        override fun write(text: String) {
            content = text
        }
    }

    private fun entryAt(id: String, sequence: Long): OfflineOutboxEntry = OfflineOutboxEntry(
        offlineOperationId = id,
        organisationId = "org-1",
        siteId = "site-1",
        actorUserId = "user-1",
        deviceId = "device-1",
        keyId = "key-1",
        keyVersion = 1,
        operationKind = OfflineEnvelope.KIND_MESSAGE_ACKNOWLEDGE,
        deviceSequence = sequence,
        idempotencyKey = id,
        payloadDigest = "a".repeat(64),
        policyLeaseId = "lease-1",
        nonce = "nonce-0123456789abcdef",
        createdAt = "2026-09-05T10:00:00Z",
        claimedSignatureProfile = "P256_ECDSA_SHA256",
        signature = "b".repeat(86),
        payloadJson = """{"message_id":"$id"}""",
    )

    /** A queue holding exactly one operation, ready to be answered about. */
    private fun queued(): Pair<OfflineOutbox, OfflineOutboxEntry> {
        val outbox = OfflineOutbox(FakeProtectedFile())
        val result: OfflineEnqueueResult = outbox.enqueue("op-a") { sequence -> entryAt("op-a", sequence) }
        return outbox to result.entry!!
    }

    private fun answer(status: Int, body: String?): SentinelHttp.Answer = SentinelHttp.Answer(
        status = status,
        body = body?.let { Json.parseToJsonElement(it).jsonObject },
        text = body ?: "",
    )

    private fun settle(status: Int, body: String?): Triple<OfflineOutbox, CeremonyStep<JsonObject>, OfflineOutboxEntry> {
        val (outbox, entry) = queued()
        val step = OfflineSubmission.settle(outbox, entry, answer(status, body))
        return Triple(outbox, step, entry)
    }

    // -----------------------------------------------------------------------
    // A proven terminal answer settles the entry
    // -----------------------------------------------------------------------

    @Test
    fun `a final applied receipt settles and removes the entry`() {
        val (outbox, step, _) = settle(200, """{"receipt":{"status":"APPLIED"}}""")
        assertTrue(step.isOk)
        assertEquals(0, outbox.size())
        assertNull(outbox.peekNext())
    }

    @Test
    fun `a final rejected receipt also settles the entry`() {
        // C10-08: a deterministic REJECTED consumes its queue position exactly
        // as an APPLIED does. The operation is finished; it simply did not
        // apply, and re-sending it would not change that.
        val (outbox, step, _) = settle(200, """{"receipt":{"status":"REJECTED"}}""")
        assertTrue(step.isOk)
        assertEquals(0, outbox.size())
    }

    @Test
    fun `a status at the top level is read when there is no receipt member`() {
        val (outbox, step, _) = settle(200, """{"status":"APPLIED"}""")
        assertTrue(step.isOk)
        assertEquals(0, outbox.size())
    }

    /**
     * AN AUTHORITATIVE 4xx IS TERMINAL. The server evaluated this exact
     * envelope and declined it — a lease that no longer covers the kind, a key
     * the registry has replaced, an actor who does not match. Re-sending it
     * cannot change any of those.
     */
    @Test
    fun `an authoritative 4xx removes the entry`() {
        for (status in listOf(400, 401, 403, 404, 422)) {
            val (outbox, entry) = queued()
            val step = OfflineSubmission.settle(outbox, entry, answer(status, """{"error":"refused"}"""))
            assertTrue("status $status should be a refusal", step.kind == CeremonyStep.Kind.REFUSED)
            assertEquals(status, step.status)
            assertEquals("status $status should have settled the entry", 0, outbox.size())
        }
    }

    // -----------------------------------------------------------------------
    // Everything unproven keeps the entry
    // -----------------------------------------------------------------------

    @Test
    fun `a transport failure leaves the entry queued`() {
        // `SentinelHttp` reports every transport failure as status 0, and that
        // bucket contains the case that matters most: the request arrived, the
        // server committed, and the RESPONSE was lost coming back.
        val (outbox, step, entry) = settle(0, null)
        assertTrue(step.isCompletionUnknown)
        assertEquals(1, outbox.size())
        assertEquals(entry.offlineOperationId, outbox.peekNext()!!.offlineOperationId)
        assertFalse(outbox.find("op-a")!!.isTerminal)
    }

    @Test
    fun `a 5xx leaves the entry queued`() {
        for (status in listOf(500, 502, 503)) {
            val (outbox, entry) = queued()
            val step = OfflineSubmission.settle(outbox, entry, answer(status, """{"error":"upstream"}"""))
            assertTrue("status $status must not be terminal", step.isCompletionUnknown)
            assertEquals(1, outbox.size())
        }
    }

    @Test
    fun `the server's own 409 is unknown and never a refusal`() {
        val (outbox, step, _) = settle(409, """{"error":"completion unknown"}""")
        assertTrue(step.isCompletionUnknown)
        assertFalse(step.kind == CeremonyStep.Kind.REFUSED)
        assertEquals(1, outbox.size())
    }

    /**
     * C18-R1A — THE EXTRACTION IS THE PART THAT CAN FAIL.
     *
     * A 2xx this client cannot read is UNKNOWN. Never a refusal, which would
     * tell the operative an operation did not happen when it may well have, and
     * never a rethrow, which would leave the classifier by exception rather
     * than being classified at all.
     */
    @Test
    fun `a success whose body cannot be read is unknown, not a refusal and not a throw`() {
        val unreadable = listOf(
            null,
            """{}""",
            """{"receipt":{}}""",
            """{"receipt":"APPLIED"}""",
            """{"status":7}""",
            """{"receipt":{"status":null}}""",
        )
        for (body in unreadable) {
            val (outbox, entry) = queued()
            val step = OfflineSubmission.settle(outbox, entry, answer(200, body))
            assertTrue("body $body must be unknown", step.isCompletionUnknown)
            assertFalse("body $body must not be a refusal", step.kind == CeremonyStep.Kind.REFUSED)
            assertEquals("body $body must leave the entry queued", 1, outbox.size())
            assertNotNull(outbox.peekNext())
        }
    }

    /**
     * A READABLE BUT NON-FINAL RECEIPT IS ALSO UNKNOWN.
     *
     * C10-08: only APPLIED and REJECTED consume a queue position. An entry
     * dropped on a RECEIVED would be an entry the server was still waiting to
     * be told about, and the position would be spent with nothing to fill it.
     */
    @Test
    fun `a receipt that is not final leaves the entry queued`() {
        for (status in listOf("RECEIVED", "APPLYING", "UNKNOWN")) {
            val (outbox, entry) = queued()
            val step = OfflineSubmission.settle(
                outbox,
                entry,
                answer(200, """{"receipt":{"status":"$status"}}"""),
            )
            assertTrue("receipt $status must not settle", step.isCompletionUnknown)
            assertTrue(step.detail.contains(status))
            assertEquals(1, outbox.size())
        }
    }

    @Test
    fun `the statuses that settle are exactly the two the cursor advances on`() {
        assertEquals(listOf("APPLIED", "REJECTED"), OfflineSubmission.RECEIPT_STATUSES_THAT_SETTLE)
    }

    // -----------------------------------------------------------------------
    // Retrying an unproven outcome keeps the same position
    // -----------------------------------------------------------------------

    /**
     * A retry re-sends THE SAME ENVELOPE — the same sequence, the same nonce,
     * the same signature. That is what lets the server recognise it as the same
     * one-shot slot carrying the same bytes and converge on the stored outcome
     * (C15-05) rather than committing a second effect. Re-signing on retry
     * would produce a new nonce and a new `created_at`, which is a DIFFERENT
     * operation as far as the server is concerned.
     */
    @Test
    fun `an unproven outcome leaves the exact same envelope queued for the next attempt`() {
        val (outbox, entry) = queued()
        OfflineSubmission.settle(outbox, entry, answer(0, null))
        OfflineSubmission.settle(outbox, entry, answer(503, """{"error":"upstream"}"""))

        val next = outbox.peekNext()!!
        assertEquals(entry.deviceSequence, next.deviceSequence)
        assertEquals(entry.nonce, next.nonce)
        assertEquals(entry.signature, next.signature)
        assertEquals(entry.createdAt, next.createdAt)
    }

    /**
     * The position is never re-issued, whichever way the entry left. The
     * counter does not rewind on a removal and does not rewind on a refusal.
     */
    @Test
    fun `settling an entry does not free its position for reuse`() {
        val outbox = OfflineOutbox(FakeProtectedFile())
        val first = outbox.enqueue("op-a") { sequence -> entryAt("op-a", sequence) }.entry!!
        OfflineSubmission.settle(outbox, first, answer(403, """{"error":"refused"}"""))

        val second = outbox.enqueue("op-b") { sequence -> entryAt("op-b", sequence) }.entry!!
        assertEquals(first.deviceSequence + 1, second.deviceSequence)
    }

    // -----------------------------------------------------------------------
    // The route
    // -----------------------------------------------------------------------

    @Test
    fun `the drain surface is the one the gateway exposes`() {
        assertEquals("/api/v1/device-gateway/operations/offline-queue", OfflineSubmission.PATH)
    }

    // -----------------------------------------------------------------------
    // Two structural guards the behaviour above cannot supply
    // -----------------------------------------------------------------------

    private fun source(name: String): String {
        val file = java.io.File("src/main/kotlin/com/sentinel/field/net/$name")
        assertTrue("expected to find $name at ${file.absolutePath}", file.isFile)
        return file.readText()
    }

    /**
     * The same file with whole-line comments dropped.
     *
     * The sources DISCUSS the shapes they must not emit, at length and on
     * purpose, so a scan that did not strip comments would fail on the prose
     * explaining why the prose is right.
     */
    private fun codeOf(name: String): String = source(name)
        .split("\n")
        .filter { !it.trim().startsWith("*") && !it.trim().startsWith("//") }
        .joinToString("\n")

    /**
     * `UnreadableSuccessSourceTest` and `DeviceActionSubmissionSourceTest` both
     * assert this same property, and it is worth a third statement: the ONE
     * status this client must not read as a refusal has to be a NAMED constant,
     * so that removing it is a deliberate act rather than an edit to a magic
     * number inside a comparison.
     */
    @Test
    fun `the status that must not be read as a refusal is a named constant`() {
        val code = source("OfflineSubmission.kt")
        assertTrue(code.contains("private const val COMPLETION_UNKNOWN = 409"))
        assertTrue(
            "only an authoritative 4xx that is not the server's own 409 may be terminal",
            code.contains("answer.status in 400..499 && answer.status != COMPLETION_UNKNOWN"),
        )
    }

    /**
     * `OFFLINE_SYNC`, never `FIELD_OPERATION`.
     *
     * The two admit the same trust states today, so choosing the familiar one
     * would change no behaviour and would be wrong anyway: the contract defines
     * a separate purpose for queue admission so that it can be tightened
     * without tightening live field operations, and the purpose is inside the
     * signed proof where it cannot be corrected in transit.
     */
    @Test
    fun `the queue proof is minted under the queue admission purpose alone`() {
        val code = source("OfflineSubmission.kt")
        assertTrue(code.contains("DeviceStatements.PURPOSE_OFFLINE_SYNC"))
        assertFalse(code.contains("PURPOSE_FIELD_OPERATION"))
        assertFalse(code.contains("PURPOSE_WHISPER_DEVICE_ACTION"))
        assertFalse(code.contains("PURPOSE_RECONNECT_HANDSHAKE"))
    }

    /**
     * THE BODY IS TWO MEMBERS, AND THIS IS THE GUARD THAT WOULD HAVE CAUGHT THE
     * SHAPE BEING WRONG.
     *
     * The gateway request body is `.strict()` (C17-06): it admits `proof`,
     * `payload` and three optional echoes, and an unknown top-level key is
     * REFUSED rather than discarded — because an unknown key is a value the
     * signature does not cover. An earlier draft of this client put `envelope`
     * and `trace_id` at the top level, which would have been refused
     * ENVELOPE_MALFORMED on every submission, always, not intermittently.
     *
     * The echoes are omitted deliberately. Each is equality-bound to something
     * the ROUTE and the SERVER already resolved, so sending one adds nothing
     * and is another value that has to keep agreeing.
     */
    @Test
    fun `the body carries only the two members the strict gateway schema admits`() {
        val code = codeOf("OfflineSubmission.kt")
        assertTrue(code.contains("put(\"proof\", proof)"))
        assertTrue(code.contains("put(\"payload\", OfflineEnvelope.submissionJson(entry))"))
        // The trace comes from the REQUEST; the server mints one when absent.
        assertFalse("no trace may travel inside a strict signed body", code.contains("trace_id"))
        assertFalse("the envelope is nested under payload, never top level", code.contains("put(\"envelope\""))
        for (echo in listOf("operation_kind", "target_type", "target_id")) {
            assertFalse("the optional echo '$echo' is deliberately not sent", code.contains("put(\"$echo\""))
        }
    }

    /**
     * The proof digest is the WP-25 GATEWAY envelope digest, never the offline
     * fingerprint.
     *
     * Two signatures, two preimages. The fingerprint is the identity of the
     * queued STATEMENT and is what the envelope's own signature covers; this
     * digest is the identity of THIS REQUEST. An earlier draft used the
     * fingerprint, which would have minted a proof over bytes the server never
     * reconstructs — and the answer would have been a signature failure naming
     * nothing anybody could act on.
     */
    @Test
    fun `the proof digest is the gateway envelope digest`() {
        val code = codeOf("OfflineSubmission.kt")
        assertTrue(code.contains("OfflineEnvelope.gatewayPayloadDigest("))
        assertFalse(code.contains("payloadDigest = OfflineEnvelope.fingerprint("))
    }

    /**
     * The entry is removed in EXACTLY ONE place, and it is the settling helper.
     *
     * The behavioural tests prove that the branches which exist today settle
     * correctly. They cannot prove anything about the branch somebody adds next
     * quarter, and a `remove(` that appeared on an unproven path would be
     * invisible to every assertion above until an operation went missing in the
     * field.
     */
    @Test
    fun `an entry is removed from exactly one place in the submission path`() {
        val code = codeOf("OfflineSubmission.kt")
        assertEquals(
            "outbox.remove( must appear once, inside settleInOutbox",
            1,
            code.split("outbox.remove(").size - 1,
        )
        assertTrue(code.contains("private fun settleInOutbox("))
    }
}
