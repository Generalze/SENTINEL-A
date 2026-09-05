package com.sentinel.field.store

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * THE QUEUE, AND ABOVE ALL THE SEQUENCE.
 *
 * `OfflineOutbox` is pure Kotlin over a `ProtectedFileStore` for exactly this
 * reason: the RULES — how a position is allocated, what may be enqueued, what
 * may be removed — are the part worth testing, and they can be executed on the
 * JVM. The Android half, the encrypted file the bytes land in, is
 * `EncryptedOutboxFile`, which holds no policy and can only be exercised on a
 * device.
 *
 * SO BE CLEAR ABOUT WHAT THIS FILE PROVES AND WHAT IT DOES NOT. It proves
 * contiguous allocation, survival across a restart, duplicate refusal, bounded
 * depth, and that a failed write changes nothing. It proves NOTHING about
 * whether the bytes are encrypted at rest, and nothing about whether a real
 * rename is atomic on a real filesystem — those are properties of
 * `EncryptedFile` and of the platform, established on hardware, and no JVM test
 * can stand in for either.
 * ============================================================================
 */
class OfflineOutboxTest {

    /**
     * The test double, and it is a deliberately FAITHFUL one.
     *
     * It replaces its whole content in one step and only AFTER the failure
     * check, which is what the Android implementation achieves by writing a
     * staging file and renaming it over the live one. A fake that mutated its
     * content and then threw would be modelling the very defect the real
     * implementation exists to prevent, and every atomicity assertion below
     * would be meaningless.
     */
    private class FakeProtectedFile(var content: String? = null) : ProtectedFileStore {
        var failNextWrite = false
        var writes = 0

        override fun read(): String? = content

        override fun write(text: String) {
            writes += 1
            if (failNextWrite) {
                failNextWrite = false
                throw IOException("the simulated write failed")
            }
            content = text
        }
    }

    private fun outbox(file: FakeProtectedFile, maxDepth: Int = OfflineOutbox.DEFAULT_MAX_DEPTH) =
        OfflineOutbox(file, maxDepth)

    /**
     * A minimal entry at a given position. The fields are the envelope fields;
     * none of them is exercised here beyond the sequence, because what the
     * signed bytes look like is `OfflineEnvelopeTest`'s job.
     */
    private fun entryAt(id: String, sequence: Long): OfflineOutboxEntry = OfflineOutboxEntry(
        offlineOperationId = id,
        organisationId = "org-1",
        siteId = "site-1",
        actorUserId = "user-1",
        deviceId = "device-1",
        keyId = "key-1",
        keyVersion = 1,
        operationKind = "INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE",
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

    private fun enqueue(subject: OfflineOutbox, id: String): OfflineEnqueueResult =
        subject.enqueue(id) { sequence -> entryAt(id, sequence) }

    // -----------------------------------------------------------------------
    // Contiguous allocation
    // -----------------------------------------------------------------------

    @Test
    fun `a queue that has never been written is empty and starts at zero`() {
        val subject = outbox(FakeProtectedFile())
        assertEquals(0, subject.size())
        assertEquals(OfflineOutbox.FIRST_DEVICE_SEQUENCE, subject.nextDeviceSequence())
        assertNull(subject.peekNext())
    }

    @Test
    fun `sequences are allocated contiguously from zero`() {
        val subject = outbox(FakeProtectedFile())
        assertEquals(0L, enqueue(subject, "op-a").entry!!.deviceSequence)
        assertEquals(1L, enqueue(subject, "op-b").entry!!.deviceSequence)
        assertEquals(2L, enqueue(subject, "op-c").entry!!.deviceSequence)
        assertEquals(3L, subject.nextDeviceSequence())
        assertEquals(listOf(0L, 1L, 2L), subject.list().map { it.deviceSequence })
    }

    /**
     * ========================================================================
     * THE RESTART TEST. THIS IS THE ONE THAT MATTERS.
     * ========================================================================
     *
     * A second `OfflineOutbox` over the same file is exactly what happens when
     * the process is killed and the app is opened again: no in-memory state
     * survives, only the document. The counter must come back from the
     * document, and it must not be re-derived from the entries — which is why
     * this drains the queue COMPLETELY first. A queue with no entries in it is
     * the case where `max(entry) + 1` answers zero and quietly re-issues every
     * position the server has already settled.
     */
    @Test
    fun `the sequence survives a restart with an empty queue and is never reused`() {
        val file = FakeProtectedFile()
        val before = outbox(file)
        enqueue(before, "op-a")
        enqueue(before, "op-b")
        enqueue(before, "op-c")
        // Every entry settled and removed, exactly as a successful drain leaves
        // things. The queue is now empty.
        before.remove("op-a")
        before.remove("op-b")
        before.remove("op-c")
        assertEquals(0, before.size())

        val after = outbox(file)
        assertEquals(3L, after.nextDeviceSequence())
        assertEquals(3L, enqueue(after, "op-d").entry!!.deviceSequence)
    }

    @Test
    fun `a restart mid-queue continues the sequence without a gap`() {
        val file = FakeProtectedFile()
        val before = outbox(file)
        enqueue(before, "op-a")
        enqueue(before, "op-b")
        before.remove("op-a")

        val after = outbox(file)
        assertEquals(2L, enqueue(after, "op-c").entry!!.deviceSequence)
        assertEquals(listOf(1L, 2L), after.list().map { it.deviceSequence })
    }

    @Test
    fun `no position is ever handed out twice across many restarts`() {
        val file = FakeProtectedFile()
        val allocated = mutableListOf<Long>()
        for (index in 0 until 12) {
            val subject = outbox(file)
            val result = enqueue(subject, "op-$index")
            allocated.add(result.entry!!.deviceSequence)
            // Settle every second one, so the queue is sometimes empty and
            // sometimes not when the next restart reads it.
            if (index % 2 == 0) subject.remove("op-$index")
        }
        assertEquals((0L until 12L).toList(), allocated)
        assertEquals(allocated.size, allocated.toSet().size)
    }

    // -----------------------------------------------------------------------
    // Refusals, and the rule that a refusal allocates nothing
    // -----------------------------------------------------------------------

    @Test
    fun `enqueue refuses a duplicate operation id and allocates no position`() {
        val subject = outbox(FakeProtectedFile())
        enqueue(subject, "op-a")
        val again = enqueue(subject, "op-a")

        assertEquals(OfflineEnqueueOutcome.DUPLICATE_OPERATION_ID, again.outcome)
        assertNull(again.entry)
        assertFalse(again.isQueued)
        assertEquals(1, subject.size())
        // No hole: the next position is still the one after the single entry.
        assertEquals(1L, subject.nextDeviceSequence())
    }

    /**
     * A FULL QUEUE REFUSES. It does not evict.
     *
     * Evicting the oldest would silently destroy an acknowledgement the
     * operative already made and already believes was recorded, and would burn
     * its sequence position on the way out. Refusing the new one is visible and
     * recoverable.
     */
    @Test
    fun `a full queue refuses the new operation and keeps every old one`() {
        val subject = outbox(FakeProtectedFile(), maxDepth = 3)
        enqueue(subject, "op-a")
        enqueue(subject, "op-b")
        enqueue(subject, "op-c")

        val refused = enqueue(subject, "op-d")

        assertEquals(OfflineEnqueueOutcome.QUEUE_FULL, refused.outcome)
        assertNull(refused.entry)
        assertEquals(3, subject.size())
        assertEquals(listOf("op-a", "op-b", "op-c"), subject.list().map { it.offlineOperationId })
        // The refusal happened BEFORE the draw, so no position was burnt.
        assertEquals(3L, subject.nextDeviceSequence())
    }

    @Test
    fun `a builder that throws leaves the queue and the counter untouched`() {
        val subject = outbox(FakeProtectedFile())
        enqueue(subject, "op-a")
        try {
            subject.enqueue("op-b") { throw IllegalStateException("the signer failed") }
            throw AssertionError("expected the builder failure to propagate")
        } catch (expected: IllegalStateException) {
            assertEquals("the signer failed", expected.message)
        }
        assertEquals(1, subject.size())
        assertEquals(1L, subject.nextDeviceSequence())
    }

    /**
     * An entry whose stored sequence differs from the one it was given is an
     * envelope whose signature covers a different position, and the refusal
     * that comes back names nothing anybody could act on. Refused here instead.
     */
    @Test
    fun `an entry that ignores the allocated position is refused`() {
        val subject = outbox(FakeProtectedFile())
        try {
            subject.enqueue("op-a") { entryAt("op-a", 99L) }
            throw AssertionError("expected the mismatched sequence to be refused")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("99"))
        }
        assertEquals(0, subject.size())
        assertEquals(0L, subject.nextDeviceSequence())
    }

    @Test
    fun `an entry built under another operation id is refused`() {
        val subject = outbox(FakeProtectedFile())
        try {
            subject.enqueue("op-a") { sequence -> entryAt("op-b", sequence) }
            throw AssertionError("expected the mismatched operation id to be refused")
        } catch (expected: IllegalArgumentException) {
            assertTrue(expected.message!!.contains("op-b"))
        }
        assertEquals(0, subject.size())
    }

    // -----------------------------------------------------------------------
    // A failed write changes nothing
    // -----------------------------------------------------------------------

    /**
     * THE PREVIOUS QUEUE IS STILL READABLE, AND THE COUNTER HAS NOT MOVED.
     *
     * The defect this closes is the ugliest one available here: a position
     * allocated in memory, a write that failed, and the next allocation handing
     * out the same position again because memory had already moved on. The
     * outbox holds no in-memory copy at all, so there is nothing to be ahead of
     * disk.
     */
    @Test
    fun `a failed write leaves the previous queue readable and the counter unmoved`() {
        val file = FakeProtectedFile()
        val subject = outbox(file)
        enqueue(subject, "op-a")
        val documentBefore = file.content

        file.failNextWrite = true
        try {
            enqueue(subject, "op-b")
            throw AssertionError("expected the write failure to propagate")
        } catch (expected: IOException) {
            assertEquals("the simulated write failed", expected.message)
        }

        assertEquals(documentBefore, file.content)
        assertEquals(1, subject.size())
        assertEquals(listOf("op-a"), subject.list().map { it.offlineOperationId })
        assertEquals(1L, subject.nextDeviceSequence())
        // And the position that failed to persist is handed out again — which
        // is correct, because nothing was ever written under it.
        assertEquals(1L, enqueue(subject, "op-b").entry!!.deviceSequence)
    }

    @Test
    fun `a failed removal leaves the entry in the queue`() {
        val file = FakeProtectedFile()
        val subject = outbox(file)
        enqueue(subject, "op-a")

        file.failNextWrite = true
        try {
            subject.remove("op-a")
            throw AssertionError("expected the write failure to propagate")
        } catch (expected: IOException) {
            assertEquals("the simulated write failed", expected.message)
        }
        assertEquals(1, subject.size())
        assertNotNull(subject.peekNext())
    }

    // -----------------------------------------------------------------------
    // Order, attempts and settling
    // -----------------------------------------------------------------------

    @Test
    fun `peekNext answers the oldest position, not the oldest insertion`() {
        val subject = outbox(FakeProtectedFile())
        enqueue(subject, "op-a")
        enqueue(subject, "op-b")
        assertEquals("op-a", subject.peekNext()!!.offlineOperationId)
        subject.remove("op-a")
        assertEquals("op-b", subject.peekNext()!!.offlineOperationId)
    }

    @Test
    fun `markAttempt records the count and the instant it was given`() {
        val subject = outbox(FakeProtectedFile())
        enqueue(subject, "op-a")

        assertTrue(subject.markAttempt("op-a", "2026-09-05T11:00:00Z"))
        assertTrue(subject.markAttempt("op-a", "2026-09-05T11:05:00Z"))

        val entry = subject.find("op-a")!!
        assertEquals(2, entry.attemptCount)
        assertEquals("2026-09-05T11:05:00Z", entry.lastAttemptAt)
        assertFalse(subject.markAttempt("op-nothing", "2026-09-05T11:05:00Z"))
    }

    /**
     * TERMINAL IS THE SAFE MIDPOINT. If the process dies between marking and
     * removing, what survives is an entry `peekNext` skips — never one that is
     * sent a second time.
     */
    @Test
    fun `a terminal entry is skipped by peek and still counted by the queue`() {
        val subject = outbox(FakeProtectedFile())
        enqueue(subject, "op-a")
        enqueue(subject, "op-b")

        assertTrue(subject.markTerminal("op-a"))

        assertEquals("op-b", subject.peekNext()!!.offlineOperationId)
        assertEquals(2, subject.size())
        assertTrue(subject.find("op-a")!!.isTerminal)
    }

    @Test
    fun `remove drops the entry and never rewinds the counter`() {
        val subject = outbox(FakeProtectedFile())
        enqueue(subject, "op-a")
        enqueue(subject, "op-b")

        assertTrue(subject.remove("op-b"))
        assertFalse(subject.remove("op-b"))
        assertEquals(1, subject.size())
        assertEquals(2L, subject.nextDeviceSequence())
    }

    // -----------------------------------------------------------------------
    // An unreadable queue refuses to become an empty one
    // -----------------------------------------------------------------------

    /**
     * THE TEMPTING RECOVERY IS THE CATASTROPHIC ONE. Answering "empty queue,
     * sequence zero" to a corrupted document would silently re-issue every
     * position the device had already spent. Refusing to operate is
     * recoverable, because somebody finds out.
     */
    @Test
    fun `an unreadable document throws rather than restarting the count`() {
        for (broken in listOf("not json at all", "[]", """{"schema_version":1}""", """{"schema_version":2,"next_device_sequence":0,"entries":[]}""")) {
            val subject = outbox(FakeProtectedFile(broken))
            try {
                subject.load()
                throw AssertionError("expected '$broken' to be refused")
            } catch (expected: MalformedOutbox) {
                assertTrue(expected.message!!.isNotBlank())
            }
        }
    }

    @Test
    fun `a blank document is an empty queue, which is not the same as a broken one`() {
        assertEquals(0, outbox(FakeProtectedFile("")).size())
        assertEquals(0, outbox(FakeProtectedFile(null)).size())
    }

    /**
     * An entry at or beyond the counter means the counter has moved BACKWARDS,
     * which is the exact condition that leads to a re-used position. It is
     * refused on the way in rather than allowed to produce a duplicate envelope
     * later.
     */
    @Test
    fun `a stored entry at or beyond the counter is refused`() {
        val file = FakeProtectedFile()
        val subject = outbox(file)
        enqueue(subject, "op-a")
        enqueue(subject, "op-b")
        // Wind the persisted counter back underneath the queue.
        val tampered = file.content!!.replace("\"next_device_sequence\":2", "\"next_device_sequence\":1")
        try {
            outbox(FakeProtectedFile(tampered)).load()
            throw AssertionError("expected a rewound counter to be refused")
        } catch (expected: MalformedOutbox) {
            assertTrue(expected.message!!.contains("beyond"))
        }
    }

    @Test
    fun `a repeated operation id in the stored document is refused`() {
        val file = FakeProtectedFile()
        val subject = outbox(file)
        enqueue(subject, "op-a")
        val one = file.content!!
        // Two entries with the same id would make every by-id operation
        // ambiguous, so the document is refused rather than half-honoured.
        val duplicated = one.replace(
            "\"entries\":[",
            "\"entries\":[" + one.substringAfter("\"entries\":[").substringBeforeLast("]}") + ",",
        )
        try {
            outbox(FakeProtectedFile(duplicated)).load()
            throw AssertionError("expected a repeated operation id to be refused")
        } catch (expected: MalformedOutbox) {
            assertTrue(expected.message!!.contains("op-a"))
        }
    }
}
