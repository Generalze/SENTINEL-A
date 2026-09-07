package com.sentinel.field.store

import java.time.Instant
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * WHAT A DISCONNECTED DEVICE STILL REFUSES, AND WHAT EVERY REFUSAL COSTS.
 *
 * Two properties, asserted on every path:
 *
 *   1. THE REFUSAL HAPPENS. A device whose cached lease does not cover the work
 *      declines it, rather than queueing it and letting the operative believe
 *      for the rest of a shift that it was recorded. A degraded client that
 *      quietly allows everything has stopped being part of the control.
 *
 *   2. THE REFUSAL COSTS NO POSITION. `device_sequence` is inside the device's
 *      signature and the server cursor refuses to step over a position it has
 *      not seen, so a hole is not a delay — it is a stall, and everything
 *      queued behind it waits for an operation that will never arrive. Every
 *      test below reads `nextDeviceSequence` on both sides of the refusal.
 *
 * A `QUEUED` OUTCOME HERE IS NOT A PREDICTION. The cache may refuse and may
 * never permit: central re-resolves the lease by id from its own record and
 * judges the operation against that, so nothing this class allows is thereby
 * admissible.
 * ============================================================================
 */
class OfflineQueueAdmissionTest {

    private class FakeProtectedFile(var content: String? = null) : ProtectedFileStore {
        override fun read(): String? = content

        override fun write(text: String) {
            content = text
        }
    }

    private val kind = "INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE"
    private val now: Instant = Instant.parse("2026-09-05T10:00:00Z")

    private fun lease(
        scope: List<String> = listOf(kind),
        actorUserId: String = "user-1",
        deviceId: String = "device-1",
        siteId: String = "site-1",
        organisationId: String = "org-1",
        issuedAt: String = "2026-09-05T08:00:00Z",
        expiresAt: String = "2026-09-05T14:00:00Z",
    ): PolicyLease = PolicyLease(
        leaseId = "lease-1",
        organisationId = organisationId,
        siteId = siteId,
        deviceId = deviceId,
        actorUserId = actorUserId,
        authorityBasisId = "basis-1",
        scope = scope,
        issuedAt = issuedAt,
        expiresAt = expiresAt,
    )

    private fun entryAt(id: String, leaseId: String, sequence: Long): OfflineOutboxEntry = OfflineOutboxEntry(
        offlineOperationId = id,
        organisationId = "org-1",
        siteId = "site-1",
        actorUserId = "user-1",
        deviceId = "device-1",
        keyId = "key-1",
        keyVersion = 1,
        operationKind = kind,
        deviceSequence = sequence,
        idempotencyKey = id,
        payloadDigest = "a".repeat(64),
        policyLeaseId = leaseId,
        nonce = "nonce-0123456789abcdef",
        createdAt = "2026-09-05T10:00:00Z",
        claimedSignatureProfile = "P256_ECDSA_SHA256",
        signature = "b".repeat(86),
        payloadJson = """{"message_id":"$id"}""",
    )

    /**
     * Offers one operation, and records whether the builder ran.
     *
     * The builder running is the observable proxy for a position having been
     * DRAWN: `OfflineOutbox.enqueue` allocates and then hands the number to the
     * builder, so a refusal that reached the builder is a refusal that spent
     * something.
     */
    private class Offered(
        val result: LocalAdmission,
        val builderRuns: Int,
        val sequenceBefore: Long,
        val sequenceAfter: Long,
    )

    private fun offer(
        subject: OfflineQueueAdmission,
        outbox: OfflineOutbox,
        id: String = "op-a",
        operationKind: String = kind,
        actorUserId: String = "user-1",
        deviceId: String = "device-1",
        siteId: String = "site-1",
        organisationId: String = "org-1",
        cached: PolicyLease? = lease(),
        at: Instant = now,
    ): Offered {
        var runs = 0
        val before = outbox.nextDeviceSequence()
        val result = subject.offer(
            offlineOperationId = id,
            operationKind = operationKind,
            organisationId = organisationId,
            siteId = siteId,
            actorUserId = actorUserId,
            deviceId = deviceId,
            lease = cached,
            now = at,
        ) { granted, sequence ->
            runs += 1
            entryAt(id, granted.leaseId, sequence)
        }
        return Offered(result, runs, before, outbox.nextDeviceSequence())
    }

    private fun subject(file: FakeProtectedFile = FakeProtectedFile(), maxDepth: Int = 4) =
        OfflineOutbox(file, maxDepth).let { it to OfflineQueueAdmission(it) }

    // -----------------------------------------------------------------------
    // The happy path, stated so the refusals mean something
    // -----------------------------------------------------------------------

    @Test
    fun `an operation the cached lease covers is queued at the next position`() {
        val (outbox, admission) = subject()
        val offered = offer(admission, outbox)

        assertTrue(offered.result.isQueued)
        assertEquals(LocalAdmissionOutcome.QUEUED, offered.result.outcome)
        assertEquals(OfflineOutbox.FIRST_DEVICE_SEQUENCE, offered.result.entry!!.deviceSequence)
        assertEquals(offered.sequenceBefore + 1, offered.sequenceAfter)
        assertEquals(1, offered.builderRuns)
    }

    /**
     * The builder is handed THE LEASE THIS CLASS CHECKED, so `policy_lease_id`
     * inside the signed bytes cannot end up naming a different one.
     */
    @Test
    fun `the builder signs against the lease that was checked`() {
        val (outbox, admission) = subject()
        val offered = offer(admission, outbox, cached = lease())
        assertEquals("lease-1", offered.result.entry!!.policyLeaseId)
    }

    // -----------------------------------------------------------------------
    // The lease refusals, and none of them draws a position
    // -----------------------------------------------------------------------

    private fun assertRefusedWithoutAllocating(offered: Offered, expected: LocalAdmissionOutcome) {
        assertEquals(expected, offered.result.outcome)
        assertFalse(offered.result.isQueued)
        assertNull(offered.result.entry)
        assertTrue("a local refusal must allocate nothing", offered.result.outcome.allocatedNothing)
        assertEquals(
            "a local refusal must not move the sequence counter",
            offered.sequenceBefore,
            offered.sequenceAfter,
        )
        assertEquals("a local refusal must never reach the signing builder", 0, offered.builderRuns)
    }

    @Test
    fun `no cached lease refuses and allocates nothing`() {
        val (outbox, admission) = subject()
        assertRefusedWithoutAllocating(
            offer(admission, outbox, cached = null),
            LocalAdmissionOutcome.NO_CACHED_LEASE,
        )
    }

    @Test
    fun `a kind outside the cached scope refuses and allocates nothing`() {
        val (outbox, admission) = subject()
        assertRefusedWithoutAllocating(
            offer(admission, outbox, operationKind = "FIELD_ASSIGNMENT_ACCEPT"),
            LocalAdmissionOutcome.LEASE_SCOPE_MISMATCH,
        )
        assertRefusedWithoutAllocating(
            offer(admission, outbox, cached = lease(scope = listOf("FIELD_STATE_UPDATE"))),
            LocalAdmissionOutcome.LEASE_SCOPE_MISMATCH,
        )
    }

    /**
     * Expiry is EXCLUSIVE, as it is server-side: at the expiry instant the
     * lease is over.
     */
    @Test
    fun `an expired lease refuses and allocates nothing`() {
        val (outbox, admission) = subject()
        assertRefusedWithoutAllocating(
            offer(admission, outbox, at = Instant.parse("2026-09-05T14:00:00Z")),
            LocalAdmissionOutcome.LEASE_EXPIRED,
        )
        assertRefusedWithoutAllocating(
            offer(admission, outbox, at = Instant.parse("2026-09-06T00:00:00Z")),
            LocalAdmissionOutcome.LEASE_EXPIRED,
        )
    }

    @Test
    fun `a lease that has not started refuses and allocates nothing`() {
        val (outbox, admission) = subject()
        assertRefusedWithoutAllocating(
            offer(admission, outbox, at = Instant.parse("2026-09-05T07:59:59Z")),
            LocalAdmissionOutcome.LEASE_NOT_YET_VALID,
        )
    }

    /**
     * FAIL-CLOSED ON AN INSTANT NOBODY CAN READ, mirroring C15-07: the server
     * answers TIME_NOT_AUTHORITATIVE for an instant it cannot parse, and that
     * is not VALID either.
     */
    @Test
    fun `an unreadable lease window refuses and allocates nothing`() {
        val (outbox, admission) = subject()
        assertRefusedWithoutAllocating(
            offer(admission, outbox, cached = lease(expiresAt = "whenever")),
            LocalAdmissionOutcome.LEASE_WINDOW_UNREADABLE,
        )
    }

    /**
     * C15-06 AND THE SHARED HANDSET. Operative A causes a lease to be issued,
     * the device passes to operative B at shift change, and B — who holds
     * nothing — must not be able to ride A's cached authority.
     */
    @Test
    fun `a lease naming another actor refuses and allocates nothing`() {
        val (outbox, admission) = subject()
        assertRefusedWithoutAllocating(
            offer(admission, outbox, actorUserId = "user-2"),
            LocalAdmissionOutcome.LEASE_ACTOR_MISMATCH,
        )
    }

    @Test
    fun `a lease for another device, site or tenant refuses and allocates nothing`() {
        val (outbox, admission) = subject()
        assertRefusedWithoutAllocating(
            offer(admission, outbox, deviceId = "device-2"),
            LocalAdmissionOutcome.LEASE_IDENTITY_MISMATCH,
        )
        assertRefusedWithoutAllocating(
            offer(admission, outbox, siteId = "site-2"),
            LocalAdmissionOutcome.LEASE_IDENTITY_MISMATCH,
        )
        assertRefusedWithoutAllocating(
            offer(admission, outbox, organisationId = "org-2"),
            LocalAdmissionOutcome.LEASE_IDENTITY_MISMATCH,
        )
    }

    // -----------------------------------------------------------------------
    // The queue's own refusals, which also allocate nothing
    // -----------------------------------------------------------------------

    /**
     * Refused rather than re-signed under a second position, which would
     * present the server with two envelopes for one act the operative
     * performed once.
     */
    @Test
    fun `a duplicate operation id refuses and allocates nothing`() {
        val (outbox, admission) = subject()
        assertTrue(offer(admission, outbox, id = "op-a").result.isQueued)
        assertRefusedWithoutAllocating(
            offer(admission, outbox, id = "op-a"),
            LocalAdmissionOutcome.DUPLICATE_OPERATION_ID,
        )
    }

    /**
     * A full queue REFUSES and does not evict. Losing a queued acknowledgement
     * silently is strictly worse than refusing to take a new one.
     */
    @Test
    fun `a full queue refuses, evicts nothing and allocates nothing`() {
        val (outbox, admission) = subject(maxDepth = 2)
        assertTrue(offer(admission, outbox, id = "op-a").result.isQueued)
        assertTrue(offer(admission, outbox, id = "op-b").result.isQueued)

        assertRefusedWithoutAllocating(
            offer(admission, outbox, id = "op-c"),
            LocalAdmissionOutcome.QUEUE_FULL,
        )
        assertEquals("nothing may be evicted to make room", 2, outbox.size())
        assertEquals("op-a", outbox.peekNext()!!.offlineOperationId)
    }

    // -----------------------------------------------------------------------
    // Contiguity across a mixture of refusals and successes
    // -----------------------------------------------------------------------

    /**
     * A GAP IS NOT A DELAY; IT IS A STALL. Refusals interleaved with successes
     * must leave the accepted operations at consecutive positions, because the
     * server cursor will not step over one that never arrives.
     */
    @Test
    fun `refusals between successes leave the positions contiguous`() {
        val (outbox, admission) = subject(maxDepth = 8)
        val a = offer(admission, outbox, id = "op-a").result.entry!!
        offer(admission, outbox, id = "op-x", cached = null)
        offer(admission, outbox, id = "op-y", operationKind = "FIELD_STATE_UPDATE")
        offer(admission, outbox, id = "op-a")
        val b = offer(admission, outbox, id = "op-b").result.entry!!
        offer(admission, outbox, id = "op-z", at = Instant.parse("2026-09-06T00:00:00Z"))
        val c = offer(admission, outbox, id = "op-c").result.entry!!

        assertEquals(a.deviceSequence + 1, b.deviceSequence)
        assertEquals(b.deviceSequence + 1, c.deviceSequence)
        assertEquals(3, outbox.size())
        assertEquals(c.deviceSequence + 1, outbox.nextDeviceSequence())
    }

    /**
     * The counter is PERSISTED, not derived, so a queue that drained completely
     * does not re-issue positions it has already spent — and the admission path
     * does not change that.
     */
    @Test
    fun `a drained queue does not re-issue a position through this path`() {
        val file = FakeProtectedFile()
        val outbox = OfflineOutbox(file, 4)
        val admission = OfflineQueueAdmission(outbox)
        val a = offer(admission, outbox, id = "op-a").result.entry!!
        outbox.markTerminal("op-a")
        outbox.remove("op-a")
        assertEquals(0, outbox.size())

        val afterRestart = OfflineOutbox(FakeProtectedFile(file.content), 4)
        val b = offer(OfflineQueueAdmission(afterRestart), afterRestart, id = "op-b").result.entry!!
        assertEquals(a.deviceSequence + 1, b.deviceSequence)
    }

    // -----------------------------------------------------------------------
    // The vocabulary
    // -----------------------------------------------------------------------

    @Test
    fun `every outcome but QUEUED allocated nothing`() {
        for (outcome in LocalAdmissionOutcome.values()) {
            assertEquals(outcome != LocalAdmissionOutcome.QUEUED, outcome.allocatedNothing)
        }
    }

    /**
     * The queue's three refusals map across explicitly, so a new
     * `OfflineEnqueueOutcome` cannot arrive here unexamined.
     */
    @Test
    fun `the queue outcomes map one for one`() {
        assertEquals(LocalAdmissionOutcome.QUEUED, OfflineQueueAdmission.from(OfflineEnqueueOutcome.QUEUED))
        assertEquals(
            LocalAdmissionOutcome.DUPLICATE_OPERATION_ID,
            OfflineQueueAdmission.from(OfflineEnqueueOutcome.DUPLICATE_OPERATION_ID),
        )
        assertEquals(LocalAdmissionOutcome.QUEUE_FULL, OfflineQueueAdmission.from(OfflineEnqueueOutcome.QUEUE_FULL))
        assertEquals(
            LocalAdmissionOutcome.SEQUENCE_EXHAUSTED,
            OfflineQueueAdmission.from(OfflineEnqueueOutcome.SEQUENCE_EXHAUSTED),
        )
        assertEquals(4, OfflineEnqueueOutcome.values().size)
    }

    /**
     * A refusal is safe to show and safe to log: each outcome describes a rule
     * this device applied to itself, and none discloses anything about the
     * lease beyond the fact that it did not cover this act.
     */
    @Test
    fun `describe names the outcome and never the payload`() {
        val (outbox, admission) = subject()
        val refused = offer(admission, outbox, cached = null).result.describe()
        assertTrue(refused.contains("NO_CACHED_LEASE"))

        val queued = offer(admission, outbox).result.describe()
        assertTrue(queued.contains("QUEUED"))
        assertFalse(queued.contains("message_id"))
    }
}
