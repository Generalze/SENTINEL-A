package com.sentinel.field.net

import com.sentinel.field.store.MalformedOutbox
import com.sentinel.field.store.OfflineEntryState
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
 * WHAT AN EDGE CAN AND CANNOT DO TO A QUEUED OPERATION.
 *
 * The classifier is a companion function over an explicit `SentinelHttp.Answer`
 * for the same reason `OfflineSubmission.settle` is: every branch is executed
 * here, on the JVM, with no transport and no Android runtime. This machine has
 * no JDK, Gradle or Android SDK and hosted CI is the only verification, so a
 * property that can be proven by execution rather than by reading source text
 * is worth arranging for.
 *
 * THE ONE PROPERTY EVERY TEST BELOW IS REALLY ABOUT: after ANY answer from an
 * Edge — a receipt, a 403, a 500, a timeout, a body full of nonsense — the
 * entry is still queued, at the same position, with the same signature, waiting
 * for central. D23-10: Edge may witness, Edge may not authorize, and an Edge
 * that could end a queued operation would be a box in a wiring closet that can
 * make a Field operative's acknowledgement disappear.
 * ============================================================================
 */
class EdgeSubmissionTest {

    /**
     * The same faithful double the outbox tests use: content is replaced whole,
     * which is what the Android implementation achieves by writing a staging
     * file and renaming it over the live one.
     */
    private class FakeProtectedFile(var content: String? = null) : ProtectedFileStore {
        override fun read(): String? = content

        override fun write(text: String) {
            content = text
        }
    }

    /** An Edge that answers whatever the test tells it to, and records what it was sent. */
    private class StubEdge(private val answer: SentinelHttp.Answer) : EdgeTransport {
        var sent: JsonObject? = null
        var calls = 0

        override fun submit(body: JsonObject): SentinelHttp.Answer {
            calls += 1
            sent = body
            return answer
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

    private fun queued(file: FakeProtectedFile = FakeProtectedFile()): Pair<OfflineOutbox, OfflineOutboxEntry> {
        val outbox = OfflineOutbox(file)
        val result = outbox.enqueue("op-a") { sequence -> entryAt("op-a", sequence) }
        return outbox to result.entry!!
    }

    /** A receipt about the entry the test is holding, so the fingerprint agrees. */
    private fun receiptFor(entry: OfflineOutboxEntry, position: String = "41"): String =
        """{"schema_version":1,"edge_id":"edge-17","edge_key_id":"edge-key-1","edge_key_version":2,""" +
            """"witnessed_operation_fingerprint":"${OfflineEnvelope.fingerprint(entry)}",""" +
            """"edge_trusted_time":"2026-09-05T10:00:05Z","edge_monotonic_position":$position,""" +
            """"claimed_edge_signature_profile":"P256_ECDSA_SHA256","edge_signature":"${"c".repeat(86)}"}"""

    private fun answer(status: Int, body: String?): SentinelHttp.Answer = SentinelHttp.Answer(
        status = status,
        body = body?.let { Json.parseToJsonElement(it).jsonObject },
        text = body ?: "",
    )

    // -----------------------------------------------------------------------
    // The receipt is persisted, and it survives a restart
    // -----------------------------------------------------------------------

    /**
     * THE POINT OF THE WHOLE PATH.
     *
     * The receipt is the only evidence of an independent clock that will ever
     * exist for this operation, and it exists on a LAN the handset may never
     * see again. It has to reach disk with the entry, and it has to still be
     * there after the process dies — which is what "a new `OfflineOutbox` over
     * the same bytes" models.
     */
    @Test
    fun `a receipt is stored with the entry and survives a restart`() {
        val file = FakeProtectedFile()
        val (outbox, entry) = queued(file)
        val witness = EdgeSubmission.record(outbox, entry, answer(200, """{"receipt":${receiptFor(entry)}}"""))

        assertTrue(witness.isWitnessed)
        assertNotNull(outbox.find("op-a")!!.edgeReceiptJson)

        val afterRestart = OfflineOutbox(FakeProtectedFile(file.content))
        val restored = afterRestart.find("op-a")!!
        assertEquals(outbox.find("op-a")!!.edgeReceiptJson, restored.edgeReceiptJson)
        val receipt = EdgeReceipt.fromStored(restored.edgeReceiptJson!!)!!
        assertEquals("edge-17", receipt.edgeId)
        assertEquals(OfflineEnvelope.fingerprint(entry), receipt.witnessedOperationFingerprint)
    }

    /** A receipt at the top level, for an Edge that does not nest it. */
    @Test
    fun `a receipt at the top level is read too`() {
        val (outbox, entry) = queued()
        assertTrue(EdgeSubmission.record(outbox, entry, answer(200, receiptFor(entry))).isWitnessed)
        assertNotNull(outbox.find("op-a")!!.edgeReceiptJson)
    }

    /**
     * A WITNESS IS NOT A COMPLETION. The entry stays queued, keeps its position
     * and is still what `peekNext` hands to the central path.
     */
    @Test
    fun `a witnessed entry is still queued for central`() {
        val (outbox, entry) = queued()
        EdgeSubmission.record(outbox, entry, answer(200, """{"receipt":${receiptFor(entry)}}"""))

        assertEquals(1, outbox.size())
        val next = outbox.peekNext()!!
        assertEquals(entry.offlineOperationId, next.offlineOperationId)
        assertEquals(entry.deviceSequence, next.deviceSequence)
        assertEquals(OfflineEntryState.QUEUED, next.state)
        assertEquals(entry.signature, next.signature)
        assertEquals(entry.nonce, next.nonce)
    }

    /**
     * THE FIRST WITNESS WINS.
     *
     * The receipt's value is an independent instant placing the operation
     * inside its lease. The first Edge to see the envelope saw it closest to
     * the moment the operative acted; a later receipt witnesses a strictly
     * later instant, which for a time-bounded kind is the one that can fall
     * outside the window. Overwriting would quietly destroy the evidence that
     * would have admitted the operation.
     */
    @Test
    fun `a second receipt does not displace the first`() {
        val (outbox, entry) = queued()
        EdgeSubmission.record(outbox, entry, answer(200, """{"receipt":${receiptFor(entry, position = "41")}}"""))
        val first = outbox.find("op-a")!!.edgeReceiptJson

        val again = outbox.find("op-a")!!
        val witness = EdgeSubmission.record(outbox, again, answer(200, """{"receipt":${receiptFor(entry, position = "99")}}"""))

        assertTrue("the entry does hold a witness either way", witness.isWitnessed)
        assertEquals("the stored receipt is the FIRST one", first, outbox.find("op-a")!!.edgeReceiptJson)
        assertEquals(41L, EdgeReceipt.fromStored(outbox.find("op-a")!!.edgeReceiptJson!!)!!.edgeMonotonicPosition)
    }

    /** An already-witnessed entry is not offered again, and nothing is sent. */
    @Test
    fun `an entry that already holds a witness is not re-offered`() {
        val (outbox, entry) = queued()
        EdgeSubmission.record(outbox, entry, answer(200, """{"receipt":${receiptFor(entry)}}"""))

        val edge = StubEdge(answer(200, """{"receipt":${receiptFor(entry, position = "99")}}"""))
        val witness = EdgeSubmission(edge, outbox).witness(outbox.find("op-a")!!)

        assertTrue(witness.isWitnessed)
        assertEquals("nothing may be sent for an entry already witnessed", 0, edge.calls)
    }

    @Test
    fun `a stored receipt that has been altered underneath the app refuses rather than re-witnessing`() {
        val (outbox, _) = queued()
        val broken = outbox.find("op-a")!!.copy(edgeReceiptJson = """{"edge_id":"edge-17"}""")
        try {
            EdgeSubmission(StubEdge(answer(0, null)), outbox).witness(broken)
            throw AssertionError("expected an unreadable stored receipt to be refused")
        } catch (expected: MalformedOutbox) {
            assertTrue(expected.message!!.contains("op-a"))
        }
    }

    // -----------------------------------------------------------------------
    // Every unknown-shaped answer leaves the entry queued and unwitnessed
    // -----------------------------------------------------------------------

    /**
     * THE BRANCH THAT DOES NOT EXIST.
     *
     * `OfflineSubmission` treats an authoritative 4xx as terminal because
     * CENTRAL evaluated the envelope. An Edge 4xx is a fact about that Edge's
     * ingress — out of disk, no trusted-time anchor, a site it is not
     * authorised for — and none of those is a fact about whether the operative's
     * acknowledgement happened.
     */
    @Test
    fun `no Edge answer of any status settles or removes the entry`() {
        val statuses = listOf(0, 400, 401, 403, 404, 409, 422, 500, 502, 503)
        for (status in statuses) {
            val (outbox, entry) = queued()
            val witness = EdgeSubmission.record(outbox, entry, answer(status, """{"error":"no"}"""))

            assertFalse("status $status must not witness", witness.isWitnessed)
            assertEquals("status $status must leave the entry queued", 1, outbox.size())
            assertNotNull("status $status must leave it drainable", outbox.peekNext())
            assertFalse("status $status must not settle it", outbox.find("op-a")!!.isTerminal)
            assertNull("status $status must store no receipt", outbox.find("op-a")!!.edgeReceiptJson)
        }
    }

    @Test
    fun `a transport failure with no body is not witnessed and is not a throw`() {
        val (outbox, entry) = queued()
        val witness = EdgeSubmission.record(outbox, entry, answer(0, null))
        assertFalse(witness.isWitnessed)
        assertEquals(0, witness.status)
        assertEquals(1, outbox.size())
    }

    /**
     * C18-R1A, one layer down: the EXTRACTION is the part that can fail, and a
     * receipt that cannot be read is UNKNOWN rather than anything else.
     */
    @Test
    fun `a success this client cannot read stores nothing and keeps the entry`() {
        val unreadable = listOf(
            null,
            "{}",
            """{"receipt":{}}""",
            """{"receipt":"APPLIED"}""",
            """{"receipt":{"edge_id":"edge-17"}}""",
            """{"receipt":{"schema_version":2}}""",
        )
        for (body in unreadable) {
            val (outbox, entry) = queued()
            val witness = EdgeSubmission.record(outbox, entry, answer(200, body))
            assertFalse("body $body must not witness", witness.isWitnessed)
            assertEquals("body $body must leave the entry queued", 1, outbox.size())
            assertNull("body $body must store no receipt", outbox.find("op-a")!!.edgeReceiptJson)
        }
    }

    /**
     * A RECEIPT ABOUT SOMEBODY ELSE'S OPERATION IS NOT THIS ENTRY'S WITNESS.
     *
     * Central performs the same comparison and refuses
     * WITNESS_FINGERPRINT_MISMATCH; doing it here means a confused or hostile
     * Edge cannot make one entry carry another entry's clock, and the wrong
     * receipt is never written to disk in the first place.
     */
    @Test
    fun `a receipt about another operation is refused and stored nowhere`() {
        val (outbox, entry) = queued()
        val other = entryAt("op-b", 99L)
        val witness = EdgeSubmission.record(outbox, entry, answer(200, """{"receipt":${receiptFor(other)}}"""))

        assertFalse(witness.isWitnessed)
        assertNull(outbox.find("op-a")!!.edgeReceiptJson)
        assertEquals(1, outbox.size())
    }

    /** D23-10, at the classifier: a receipt that tries to authorise is not a receipt. */
    @Test
    fun `a receipt carrying an authorisation field witnesses nothing`() {
        val (outbox, entry) = queued()
        val forged = receiptFor(entry).dropLast(1) + ""","approval":"granted"}"""
        val witness = EdgeSubmission.record(outbox, entry, answer(200, """{"receipt":$forged}"""))

        assertFalse(witness.isWitnessed)
        assertNull(outbox.find("op-a")!!.edgeReceiptJson)
    }

    // -----------------------------------------------------------------------
    // The wire body
    // -----------------------------------------------------------------------

    /**
     * THE BYTES EDGE SEES ARE THE BYTES CENTRAL SEES.
     *
     * Two members, `envelope` and `payload`, built by the very same
     * `OfflineEnvelope.submissionJson` the central path posts and the request
     * proof digests. A leaner Edge-specific body would be a second definition
     * of what a queued operation is, and the receipt would then witness bytes
     * central never verifies.
     */
    @Test
    fun `the body posted to the Edge is the same two members central receives`() {
        val (outbox, entry) = queued()
        val edge = StubEdge(answer(0, null))
        EdgeSubmission(edge, outbox).witness(entry)

        val sent = edge.sent!!
        assertEquals(setOf("envelope", "payload"), sent.keys)
        assertEquals(OfflineEnvelope.submissionJson(entry), sent)
        assertEquals(17, (sent["envelope"] as JsonObject).keys.size)
        // No proof and no session material: Edge authorises nothing, so there
        // is nothing for it to authenticate.
        assertFalse(sent.keys.contains("proof"))
    }

    @Test
    fun `witnessNext takes the oldest position first and answers null on an empty queue`() {
        val outbox = OfflineOutbox(FakeProtectedFile())
        val edge = StubEdge(answer(0, null))
        assertNull(EdgeSubmission(edge, outbox).witnessNext())

        outbox.enqueue("op-a") { sequence -> entryAt("op-a", sequence) }
        outbox.enqueue("op-b") { sequence -> entryAt("op-b", sequence) }
        EdgeSubmission(edge, outbox).witnessNext()
        assertEquals("op-a", (edge.sent!!["envelope"] as JsonObject)["offline_operation_id"].toString().trim('"'))
    }

    // -----------------------------------------------------------------------
    // Sequencing is untouched by anything on this path
    // -----------------------------------------------------------------------

    /**
     * A GAP IS NOT A DELAY; IT IS A STALL. Whatever an Edge says, the counter
     * moves only when an operation is enqueued, and positions stay contiguous
     * across the new path.
     */
    @Test
    fun `witnessing allocates nothing and keeps the sequence contiguous`() {
        val outbox = OfflineOutbox(FakeProtectedFile())
        val a = outbox.enqueue("op-a") { sequence -> entryAt("op-a", sequence) }.entry!!
        val before = outbox.nextDeviceSequence()

        EdgeSubmission.record(outbox, a, answer(200, """{"receipt":${receiptFor(a)}}"""))
        EdgeSubmission.record(outbox, a, answer(503, """{"error":"upstream"}"""))
        assertEquals("no Edge answer may move the counter", before, outbox.nextDeviceSequence())

        val b = outbox.enqueue("op-b") { sequence -> entryAt("op-b", sequence) }.entry!!
        val c = outbox.enqueue("op-c") { sequence -> entryAt("op-c", sequence) }.entry!!
        assertEquals(a.deviceSequence + 1, b.deviceSequence)
        assertEquals(b.deviceSequence + 1, c.deviceSequence)
    }

    /**
     * The witness rides along with the entry it belongs to and with no other.
     *
     * A queue holding three operations, one of them witnessed, must come back
     * from disk with exactly that one witnessed — this is the property a
     * per-entry local field has and a side table would not.
     */
    @Test
    fun `a witness attaches to one entry only, across a restart`() {
        val file = FakeProtectedFile()
        val outbox = OfflineOutbox(file)
        outbox.enqueue("op-a") { sequence -> entryAt("op-a", sequence) }
        val b = outbox.enqueue("op-b") { sequence -> entryAt("op-b", sequence) }.entry!!
        outbox.enqueue("op-c") { sequence -> entryAt("op-c", sequence) }
        EdgeSubmission.record(outbox, b, answer(200, """{"receipt":${receiptFor(b)}}"""))

        val afterRestart = OfflineOutbox(FakeProtectedFile(file.content))
        assertNull(afterRestart.find("op-a")!!.edgeReceiptJson)
        assertNotNull(afterRestart.find("op-b")!!.edgeReceiptJson)
        assertNull(afterRestart.find("op-c")!!.edgeReceiptJson)
        assertEquals(3, afterRestart.size())
    }

    // -----------------------------------------------------------------------
    // The transport that does not exist
    // -----------------------------------------------------------------------

    /**
     * There is no Edge on this platform yet, and the client says so honestly
     * rather than opening a connection it cannot authenticate.
     *
     * `EdgeTransport` explains what is missing: nothing distributes an Edge
     * address or a pinned TLS trust anchor to a handset. The stand-in answers
     * status 0 — the same "no answer arrived" every transport failure produces
     * — so the entry stays queued and drains to central with no witness, which
     * for a stale-tolerant kind is admissible and for a time-bounded one is a
     * VISIBLE refusal at NO_TRUSTWORTHY_TIME_WITNESS.
     */
    @Test
    fun `the unconfigured transport answers no-answer and never fabricates a receipt`() {
        val (outbox, entry) = queued()
        val witness = EdgeSubmission(EdgeTransport.NotConfigured, outbox).witness(entry)

        assertFalse(witness.isWitnessed)
        assertEquals(0, witness.status)
        assertNull(witness.receipt)
        assertEquals(1, outbox.size())
        assertNull(outbox.find("op-a")!!.edgeReceiptJson)
    }

    // -----------------------------------------------------------------------
    // One structural guard the behaviour above cannot supply
    // -----------------------------------------------------------------------

    private fun codeOf(name: String): String = java.io.File("src/main/kotlin/com/sentinel/field/net/$name")
        .readText()
        .split("\n")
        .filter { !it.trim().startsWith("*") && !it.trim().startsWith("//") }
        .joinToString("\n")

    /**
     * EDGE MAY NOT END A QUEUED OPERATION, as a source fact.
     *
     * The behavioural tests prove the branches that exist today never settle an
     * entry. They cannot prove anything about the branch somebody adds next
     * quarter, and a `remove(` on the Edge path would be invisible to every
     * assertion above until an operation went missing in the field. This is the
     * same guard `OfflineSubmissionTest` places on the central path, pointed the
     * other way: there it must appear exactly once, here it must not appear at
     * all.
     */
    @Test
    fun `the Edge path contains no way to settle, remove or count against an entry`() {
        val code = codeOf("EdgeSubmission.kt")
        for (forbidden in listOf("outbox.remove(", "markTerminal(", "markAttempt(", "OfflineEntryState")) {
            assertFalse(
                "the Edge path must not contain '$forbidden' — only central ends an operation",
                code.contains(forbidden),
            )
        }
        assertTrue(
            "the only write the Edge path may make is filing the receipt",
            code.contains("outbox.recordEdgeReceipt("),
        )
    }

    /**
     * No permissive transport, in either file, ever.
     *
     * A permissive `TrustManager` in a security product is a defect even behind
     * a flag: it makes every receipt this device collects a receipt anyone on
     * the site LAN can mint, and the flag outlives the sprint that added it.
     */
    @Test
    fun `nothing on the Edge path weakens TLS`() {
        for (name in listOf("EdgeTransport.kt", "EdgeSubmission.kt", "EdgeReceipt.kt")) {
            val code = codeOf(name)
            for (forbidden in listOf(
                "X509TrustManager",
                "TrustManager",
                "hostnameVerifier",
                "HostnameVerifier",
                "sslSocketFactory",
                "checkServerTrusted",
                "ALLOW_ALL",
            )) {
                assertFalse("$name must not contain '$forbidden'", code.contains(forbidden))
            }
        }
    }
}
