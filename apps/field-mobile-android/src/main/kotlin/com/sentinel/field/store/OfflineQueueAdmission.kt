package com.sentinel.field.store

import java.time.Instant

/**
 * ============================================================================
 * WHAT A DISCONNECTED DEVICE STILL REFUSES.
 *
 * Every check below runs with no network, against the CACHED policy lease, and
 * every one of them can only ever say NO. That asymmetry is stated once in
 * [PolicyLease] and it governs this whole file: THE CACHE MAY REFUSE, AND IT MAY
 * NEVER PERMIT. A [LocalAdmissionOutcome.QUEUED] here means "this client found
 * no local reason to refuse" and absolutely nothing else — central re-resolves
 * the lease by id from its own record, judges it against its own instants and
 * its own receipt clock, and that is the judgement that decides.
 *
 * ============================================================================
 * WHY THE REFUSALS MATTER AS MUCH AS THE SUCCESSES
 * ============================================================================
 *
 * The tempting shape for a disconnected client is to queue everything and let
 * central sort it out on reconnect. It is tempting because it never blocks an
 * operative, and it is wrong for two separate reasons.
 *
 * THE FIRST IS THAT IT STOPS ENFORCING. A device whose cached lease does not
 * cover a kind, or has expired, is a device that has no current authority for
 * that work. Queueing it anyway means the operative is told it was recorded,
 * works on that basis for the rest of a shift, and finds out hours later — if
 * anybody looks — that none of it was admissible. A degraded client that
 * quietly allows everything has not degraded gracefully; it has stopped being
 * part of the control.
 *
 * THE SECOND IS THAT A REFUSAL HERE IS FREE AND A REFUSAL LATER IS NOT.
 * `device_sequence` is inside the device's signature and the server cursor
 * refuses to step over a position it has not seen, so every operation queued
 * behind an inadmissible one waits for an answer about work that was never
 * going to be admitted. Refusing BEFORE the draw costs nothing and tells the
 * operative something true at the moment they can still act on it.
 *
 * ============================================================================
 * NOTHING IS ALLOCATED THAT IS NOT ENQUEUED
 * ============================================================================
 *
 * Every lease check happens before [OfflineOutbox.enqueue] is called at all,
 * and `enqueue` performs its own three refusals — duplicate id, full queue,
 * exhausted space — BEFORE it draws a position and before it invokes the
 * builder. So no refusal on any path through this class can leave a hole in the
 * sequence, and `OfflineQueueAdmissionTest` asserts exactly that by reading
 * `nextDeviceSequence` on both sides of every refusal.
 *
 * The builder receives the LEASE as well as the position, and that is
 * deliberate: `policy_lease_id` is inside the signed bytes (C14-04), so the
 * operation names the authority it acted under. Handing the caller the very
 * lease this class checked closes the gap in which a caller could check one
 * lease and sign another.
 *
 * NO CLOCK IS READ HERE. [Instant] comes in as a parameter, so the whole class
 * is executable on the JVM with no Android runtime — the same discipline
 * `OfflineOutbox.markAttempt` and `RetrySchedule` follow, and for the same
 * reason: this machine has no SDK and hosted CI is the only verification, so a
 * rule that can be proven by execution is worth arranging for.
 * ============================================================================
 */
class OfflineQueueAdmission(private val outbox: OfflineOutbox) {

    /**
     * Offers one operation to the queue.
     *
     * The order of the checks is the order of the argument: the LEASE first,
     * because a lease that does not cover this work makes every queue question
     * irrelevant, and because a refusal that named "queue full" for an
     * operation the device had no authority for would be true and useless.
     *
     * [lease] is passed in rather than read from a [PolicyLeaseCache] here, so
     * that this class has no store dependency beyond the outbox and so a caller
     * cannot end up checking one copy and signing against another. A null lease
     * is [LocalAdmissionOutcome.NO_CACHED_LEASE] — the honest answer for a
     * device that has never been issued one, or whose cached copy was partial
     * and therefore read back as no lease at all.
     */
    fun offer(
        offlineOperationId: String,
        operationKind: String,
        organisationId: String,
        siteId: String,
        actorUserId: String,
        deviceId: String,
        lease: PolicyLease?,
        now: Instant,
        build: (PolicyLease, Long) -> OfflineOutboxEntry,
    ): LocalAdmission {
        // Bound to a non-null local rather than leaning on a smart cast. The
        // cast would be legal, and the local is free: nothing in this project
        // is compiled on the author's machine, so a shape whose correctness
        // depends on inference is a shape that can fail in a way nobody sees
        // until the runner does. `CeremonyStep` states the same rule for the
        // same reason.
        val granted: PolicyLease = lease
            ?: return LocalAdmission(LocalAdmissionOutcome.NO_CACHED_LEASE, null)

        // C15-06 AND THE SHARED HANDSET. The lease names the ACTOR whose
        // authority justified it, and on a device that passes between shifts
        // this is the load-bearing check: operative A causes a lease to be
        // issued, the handset changes hands, and operative B — who holds
        // nothing — must not be able to ride A's cached authority. The server
        // refuses LEASE_ACTOR_MISMATCH, and a client that queued one anyway
        // would be a client that told B their work was recorded.
        if (granted.actorUserId != actorUserId) {
            return LocalAdmission(LocalAdmissionOutcome.LEASE_ACTOR_MISMATCH, null)
        }

        // A lease is issued TO one device identity, at one site, in one tenancy.
        // It is not a site-wide permit and it is not portable between them.
        if (granted.organisationId != organisationId ||
            granted.siteId != siteId ||
            granted.deviceId != deviceId
        ) {
            return LocalAdmission(LocalAdmissionOutcome.LEASE_IDENTITY_MISMATCH, null)
        }

        // The scope is an ALLOWLIST, never a hint. A kind that is not named is
        // not covered, and there is no wildcard to widen it with.
        if (!granted.permits(operationKind)) {
            return LocalAdmission(LocalAdmissionOutcome.LEASE_SCOPE_MISMATCH, null)
        }

        // The window, judged against a clock this platform does not trust —
        // which is why every branch of it REFUSES and none of it permits. See
        // `PolicyLease.standingAt` for why the two failure directions are told
        // apart locally and collapsed centrally.
        val outcome = when (granted.standingAt(now)) {
            LeaseStanding.IN_FORCE -> null
            LeaseStanding.NOT_YET_VALID -> LocalAdmissionOutcome.LEASE_NOT_YET_VALID
            LeaseStanding.EXPIRED -> LocalAdmissionOutcome.LEASE_EXPIRED
            LeaseStanding.WINDOW_UNREADABLE -> LocalAdmissionOutcome.LEASE_WINDOW_UNREADABLE
        }
        if (outcome != null) return LocalAdmission(outcome, null)

        // Only now is the queue asked, and `enqueue` runs its own refusals
        // before it draws a position. Nothing above this line has touched the
        // counter, and nothing below it can leave a hole.
        val result = outbox.enqueue(offlineOperationId) { sequence -> build(granted, sequence) }
        return LocalAdmission(from(result.outcome), result.entry)
    }

    companion object {
        /**
         * The queue's own three refusals, restated in this vocabulary.
         *
         * Mapped explicitly rather than passed through, because the two enums
         * answer different questions — one is about the queue, one is about
         * whether this device may do this work at all — and a `when` with no
         * `else` fails the build when either gains a member. A silent
         * pass-through would let a new queue outcome arrive here unexamined.
         */
        internal fun from(outcome: OfflineEnqueueOutcome): LocalAdmissionOutcome = when (outcome) {
            OfflineEnqueueOutcome.QUEUED -> LocalAdmissionOutcome.QUEUED
            OfflineEnqueueOutcome.DUPLICATE_OPERATION_ID -> LocalAdmissionOutcome.DUPLICATE_OPERATION_ID
            OfflineEnqueueOutcome.QUEUE_FULL -> LocalAdmissionOutcome.QUEUE_FULL
            OfflineEnqueueOutcome.SEQUENCE_EXHAUSTED -> LocalAdmissionOutcome.SEQUENCE_EXHAUSTED
        }
    }
}

/**
 * Why a disconnected client did or did not take an operation.
 *
 * Named after the SERVER's refusals wherever the same fact exists on both sides
 * — `LEASE_SCOPE_MISMATCH`, `LEASE_ACTOR_MISMATCH`, `LEASE_IDENTITY_MISMATCH`
 * are `DeviceOfflineAdmissibilityRefusalSchema` members, quoted rather than
 * invented — so that a support conversation about a local refusal and a
 * conversation about a central one use one vocabulary.
 *
 * THE ONE PLACE THIS VOCABULARY IS WIDER THAN THE SERVER'S is the window.
 * Central answers a single `LEASE_NOT_IN_FORCE`, and it is right to: a refusal
 * that distinguished "too early" from "too late" is an oracle about lease
 * windows offered to whoever holds the handset. Locally there is no such
 * concern and the two have different remedies — an expired lease means
 * reconnect and be issued another, a not-yet-valid one means this device's
 * clock disagrees with the server that stamped it — so they are told apart
 * here and never sent anywhere.
 */
enum class LocalAdmissionOutcome {
    /** No local reason to refuse. NOT a prediction that central will accept it. */
    QUEUED,

    /** There is no cached lease, or the cached copy was partial and read back as none. */
    NO_CACHED_LEASE,

    /** C15-06. The lease names another actor; a shared handset does not share authority. */
    LEASE_ACTOR_MISMATCH,

    /** The lease belongs to another tenant, another site, or another device. */
    LEASE_IDENTITY_MISMATCH,

    /** The cached scope does not name this operation kind. */
    LEASE_SCOPE_MISMATCH,

    /** The device clock is before the instant the server says the lease began. */
    LEASE_NOT_YET_VALID,

    /** The device clock is at or past the expiry. Expiry is exclusive. */
    LEASE_EXPIRED,

    /** An instant on the cached lease does not parse. Fail-closed, exactly as C15-07 does. */
    LEASE_WINDOW_UNREADABLE,

    /** The same operation is already queued. Nothing was allocated, nothing re-signed. */
    DUPLICATE_OPERATION_ID,

    /** The bound is reached. Nothing was allocated, and nothing was evicted. */
    QUEUE_FULL,

    /** The per-device sequence space is exhausted. Refused rather than wrapped. */
    SEQUENCE_EXHAUSTED;

    /**
     * True when NO SEQUENCE POSITION WAS SPENT.
     *
     * Every member except [QUEUED], and it is stated as a property rather than
     * left for each caller to work out, because "did that refusal cost us a
     * position?" is the question the whole sequencing contract turns on and it
     * should have exactly one answer in the codebase.
     */
    val allocatedNothing: Boolean get() = this != QUEUED
}

/** The outcome, and the entry when there is one. */
data class LocalAdmission(
    val outcome: LocalAdmissionOutcome,
    val entry: OfflineOutboxEntry?,
) {
    val isQueued: Boolean get() = outcome == LocalAdmissionOutcome.QUEUED

    /**
     * A one-line rendering for the log and for the operative-facing message.
     *
     * The outcome name is safe to show: each one describes a rule this device
     * applied to itself, and none of them discloses anything about the lease
     * beyond the fact that it did not cover this act.
     */
    fun describe(): String {
        val queued = entry ?: return "refused locally: $outcome"
        return "$outcome: ${queued.describe()}"
    }
}
