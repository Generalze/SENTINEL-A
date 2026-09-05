package com.sentinel.field.store

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * ============================================================================
 * THE DURABLE OFFLINE QUEUE — THE POLICY HALF.
 *
 * Pure Kotlin over a [ProtectedFileStore], so that the RULES — how a sequence
 * is allocated, what may be enqueued, what may be removed and when — live in
 * code the JVM unit tests can execute, not in code only a handset can run. The
 * Android half, the encrypted file the bytes land in, is [EncryptedOutboxFile],
 * which contains no policy whatsoever. This is the same split
 * [ClientStateStore] and [EncryptedClientState] use, for the same reason.
 *
 * ============================================================================
 * THE PROPERTY EVERYTHING ELSE IN THIS FILE EXISTS TO SERVE
 * ============================================================================
 *
 * `device_sequence` IS CONTIGUOUS, PER-DEVICE, AND IS NEVER RESET.
 *
 * WP-20 gave the server a per-device cursor, and C10-08 gave that cursor its
 * rule: a receipt that is APPLIED or REJECTED consumes its position, and an
 * UNKNOWN one never does — "an operation that died mid-flight is retried into
 * convergence, not skipped past". The cursor therefore refuses to step over a
 * position it has not seen. A GAP IS NOT A DELAY; IT IS A STALL. Everything the
 * device queues after the gap waits behind an operation that will never arrive,
 * and the only way out is a new device identity (C10-03 is explicit that a
 * device needing a fresh sequence namespace requires a NEW authenticated device
 * identity, never a reset — there is no reset endpoint, on purpose).
 *
 * So this class owns the allocation, and it owns it under three rules:
 *
 *   1. THE COUNTER IS PERSISTED, NOT DERIVED. `next_device_sequence` is stored
 *      in the document. It is emphatically NOT computed as `max(entry) + 1`,
 *      because entries are REMOVED once the server settles them: a queue that
 *      has fully drained holds no entries at all, and a derived counter would
 *      restart at zero and re-use every position it had already spent. That is
 *      the restart defect, and it is silent — the device sends a perfectly
 *      valid envelope for a position the server settled hours ago.
 *
 *   2. THE COUNTER AND THE ENTRY ARE WRITTEN TOGETHER, OR NEITHER IS. They live
 *      in ONE document, replaced whole by one atomic write. A crash cannot land
 *      the increment without the entry (a burnt position, a permanent gap) or
 *      the entry without the increment (two entries, one position).
 *
 *   3. NOTHING IS ALLOCATED THAT IS NOT ENQUEUED. There is no public
 *      `allocate()`. A sequence is drawn inside [enqueue], and every refusal —
 *      duplicate id, full queue — happens BEFORE the draw, so a refused enqueue
 *      cannot leave a hole behind it. If the caller supplied builder throws,
 *      nothing is written and the counter is untouched.
 *
 * A COROLLARY WORTH STATING PLAINLY: once a position is allocated, the only
 * legitimate way for it to leave this queue is a PROVEN TERMINAL ANSWER from
 * the server about that exact envelope. Discarding a queued entry for any local
 * reason — too many attempts, too old, the operative closed the screen — burns
 * its position and stalls the cursor behind it. There is no code path here that
 * does it, and adding one is a change to the sequencing contract rather than a
 * housekeeping improvement.
 *
 * WHY THIS CLASS HOLDS NO IN-MEMORY COPY OF THE QUEUE
 * ---------------------------------------------------
 * Every operation reads the document, computes the next one, and writes it.
 * There is no cached list and no cached counter. That is deliberately more
 * work than caching, and it buys the property the cache would break: A FAILED
 * WRITE LEAVES NOTHING AHEAD OF DISK. The defect it prevents is exact and it is
 * the ugliest one available here — a sequence allocated in RAM, a write that
 * failed, and the next allocation handing out the same position again because
 * memory had already moved on. The queue is bounded, so the cost of re-reading
 * it is bounded too.
 *
 * WHY THE DEPTH IS BOUNDED, AND WHY A FULL QUEUE REFUSES
 * -----------------------------------------------------
 * An unbounded queue on a handset is an unbounded encrypted file, and the first
 * thing it breaks is the write it is in the middle of. When the queue is full,
 * [enqueue] REFUSES the new operation and says so. It does not evict the oldest.
 * Evicting the oldest would silently destroy an acknowledgement an operative
 * already made and already believes was recorded, and would burn its sequence
 * position on the way out; refusing a new one is visible, is recoverable, and
 * tells the operative something true. Losing a queued acknowledgement silently
 * is strictly worse than refusing to take a new one.
 *
 * WHAT IS NOT HERE. No scheduler, no background thread, no timer. This class
 * stores and orders; something else decides when to drain it, and
 * `RetrySchedule` tells that something how long to wait.
 * ============================================================================
 */
class OfflineOutbox(
    private val file: ProtectedFileStore,
    /** The bound. See the class comment for why a full queue refuses. */
    private val maxDepth: Int = DEFAULT_MAX_DEPTH,
) {

    companion object {

        /** The stored document format. A different version is refused, never guessed at. */
        const val SCHEMA_VERSION = 1

        /** C10-03: per-device queues begin here, and there is no endpoint that resets one. */
        const val FIRST_DEVICE_SEQUENCE = 0L

        /**
         * `MAX_OFFLINE_DEVICE_SEQUENCE` from `packages/contracts/src/field-offline.ts`.
         *
         * The server bound exists to keep a sequence inside JS safe-integer
         * arithmetic. It is repeated here so that an allocation which the server
         * could not represent is refused on the device, where it can be
         * explained, rather than becoming an unreadable refusal later.
         */
        const val MAX_DEVICE_SEQUENCE = 9_007_199_254_740_991L

        /**
         * Deep enough for a long shift with no coverage, small enough that the
         * whole document is rewritten cheaply on every operation.
         */
        const val DEFAULT_MAX_DEPTH = 256

        const val FIELD_SCHEMA_VERSION = "schema_version"
        const val FIELD_NEXT_DEVICE_SEQUENCE = "next_device_sequence"
        const val FIELD_ENTRIES = "entries"
    }

    /**
     * The whole queue at one instant: the counter, and the entries.
     *
     * Returned by [load] as one value rather than through two accessors,
     * because reading the counter and the entries separately is the shape in
     * which they can disagree.
     */
    data class Snapshot(
        val nextDeviceSequence: Long,
        val entries: List<OfflineOutboxEntry>,
    )

    // -----------------------------------------------------------------------
    // Reading
    // -----------------------------------------------------------------------

    /**
     * The stored queue.
     *
     * AN UNREADABLE DOCUMENT THROWS. It does not answer "empty queue, sequence
     * zero", which is the tempting recovery and the catastrophic one: a
     * corrupted or truncated file would silently reset the counter and re-issue
     * every position the device had already spent. Refusing to operate is
     * recoverable — the operative reports it, the device is re-enrolled under a
     * new identity, and the sequence namespace starts honestly. Quietly
     * restarting the count is not recoverable, because nobody finds out.
     *
     * A document that has NEVER been written is a different fact from one that
     * cannot be read, and only the former is an empty queue.
     */
    fun load(): Snapshot {
        val text = file.read()
        if (text == null || text.isBlank()) {
            return Snapshot(FIRST_DEVICE_SEQUENCE, emptyList())
        }
        val root = try {
            Json.parseToJsonElement(text)
        } catch (error: Exception) {
            throw MalformedOutbox("the stored queue is not JSON: ${error.javaClass.simpleName}")
        }
        val document = root as? JsonObject
            ?: throw MalformedOutbox("the stored queue is not a JSON object")

        val version = document.requiredLong(FIELD_SCHEMA_VERSION)
        if (version != SCHEMA_VERSION.toLong()) {
            throw MalformedOutbox("the stored queue is schema version $version, not $SCHEMA_VERSION")
        }

        val next = document.requiredLong(FIELD_NEXT_DEVICE_SEQUENCE)
        if (next < FIRST_DEVICE_SEQUENCE || next > MAX_DEVICE_SEQUENCE) {
            throw MalformedOutbox("the stored next sequence $next is outside the permitted range")
        }

        val array = document[FIELD_ENTRIES] as? JsonArray
            ?: throw MalformedOutbox("the stored queue has no entries array")
        val entries = ArrayList<OfflineOutboxEntry>(array.size)
        for (element in array) {
            val entryObject = element as? JsonObject
                ?: throw MalformedOutbox("a stored queue entry is not a JSON object")
            entries.add(OfflineOutboxEntry.fromJson(entryObject))
        }

        // Two integrity rules, checked on the way in rather than trusted.
        //
        // A repeated operation id would make every by-id operation below
        // ambiguous. An entry at or beyond the counter means the counter has
        // moved BACKWARDS at some point, which is the precise condition that
        // leads to a re-used position — so it is refused here, loudly, rather
        // than allowed to produce a duplicate envelope later.
        val seen = HashSet<String>(entries.size)
        for (entry in entries) {
            if (!seen.add(entry.offlineOperationId)) {
                throw MalformedOutbox("the stored queue repeats ${entry.offlineOperationId}")
            }
            if (entry.deviceSequence >= next) {
                throw MalformedOutbox(
                    "a stored entry holds sequence ${entry.deviceSequence}, at or beyond the next sequence $next",
                )
            }
        }
        return Snapshot(next, entries)
    }

    /** Everything currently queued, oldest position first. */
    fun list(): List<OfflineOutboxEntry> = load().entries.sortedBy { it.deviceSequence }

    /** How many entries the queue holds, terminal ones included. */
    fun size(): Int = load().entries.size

    /** The position the NEXT enqueue will take. Never decreases. */
    fun nextDeviceSequence(): Long = load().nextDeviceSequence

    /**
     * The oldest entry the server has not settled, by SEQUENCE.
     *
     * By sequence and not by insertion order or by `created_at`: the sequence is
     * the order the server cursor expects, and `created_at` is a client clock
     * this platform does not trust for anything.
     */
    fun peekNext(): OfflineOutboxEntry? =
        load().entries
            .filter { it.state == OfflineEntryState.QUEUED }
            .minByOrNull { it.deviceSequence }

    /** One entry by id, or null. */
    fun find(offlineOperationId: String): OfflineOutboxEntry? =
        load().entries.firstOrNull { it.offlineOperationId == offlineOperationId }

    // -----------------------------------------------------------------------
    // Writing
    // -----------------------------------------------------------------------

    /**
     * Appends one operation, allocating its sequence.
     *
     * THE BUILDER RECEIVES THE ALLOCATED SEQUENCE, and that is the whole reason
     * this takes a lambda rather than a finished entry. The sequence is inside
     * the signed bytes, so the caller cannot sign before the outbox has decided
     * the position, and the outbox cannot decide the position before it has
     * checked that the operation is one it will accept. Handing the number to
     * the builder closes the loop in one step: allocate, build and sign, and
     * persist, with no window in which a number is spent but nothing was
     * written.
     *
     * The refusals happen FIRST, before the draw, so neither one leaves a hole:
     *
     *   DUPLICATE_OPERATION_ID  the same operation is already queued. Refused
     *                           rather than re-signed under a second position,
     *                           which would present the server with two
     *                           envelopes for one act.
     *
     *   QUEUE_FULL              the bound is reached. Refused rather than
     *                           evicting the oldest — see the class comment.
     *
     * If [build] throws, or returns an entry that does not carry the position it
     * was given, NOTHING is written. The verification is not ceremony: an entry
     * whose stored sequence differs from the one in its signed statement is an
     * envelope the server refuses with a signature failure, which is the least
     * diagnosable refusal there is.
     */
    fun enqueue(offlineOperationId: String, build: (Long) -> OfflineOutboxEntry): OfflineEnqueueResult {
        val snapshot = load()

        if (snapshot.entries.any { it.offlineOperationId == offlineOperationId }) {
            return OfflineEnqueueResult(OfflineEnqueueOutcome.DUPLICATE_OPERATION_ID, null)
        }
        if (snapshot.entries.size >= maxDepth) {
            return OfflineEnqueueResult(OfflineEnqueueOutcome.QUEUE_FULL, null)
        }

        val allocated = snapshot.nextDeviceSequence
        if (allocated >= MAX_DEVICE_SEQUENCE) {
            return OfflineEnqueueResult(OfflineEnqueueOutcome.SEQUENCE_EXHAUSTED, null)
        }

        val entry = build(allocated)
        require(entry.offlineOperationId == offlineOperationId) {
            "the built entry is ${entry.offlineOperationId}, not the $offlineOperationId that was checked"
        }
        require(entry.deviceSequence == allocated) {
            "the built entry holds sequence ${entry.deviceSequence}, not the allocated $allocated"
        }

        persist(Snapshot(allocated + 1, snapshot.entries + entry))
        return OfflineEnqueueResult(OfflineEnqueueOutcome.QUEUED, entry)
    }

    /**
     * Records that this entry has just been handed to the transport.
     *
     * Called BEFORE the request goes out, not after the answer comes back. An
     * attempt that was made but not recorded is an attempt the backoff cannot
     * see, so a device that crashed mid-request would come back and hammer the
     * same operation with no delay at all.
     *
     * [at] is passed in rather than read from a clock here, so this class stays
     * clock-free and fully testable on the JVM. The value is local telemetry: it
     * is never signed, never sent and never compared against server time.
     */
    fun markAttempt(offlineOperationId: String, at: String): Boolean =
        mutate(offlineOperationId) { entry ->
            entry.copy(attemptCount = entry.attemptCount + 1, lastAttemptAt = at)
        }

    /**
     * Records that the SERVER answered terminally about this envelope.
     *
     * Recorded as its own write, before [remove], and the two-step is the point:
     * if the process dies between them, what survives is an entry marked
     * TERMINAL, which [peekNext] skips. The alternative ordering — remove first
     * — has no such safe midpoint, and the alternative of doing both in one
     * write has no midpoint at all but loses the record if the removal is what
     * fails.
     */
    fun markTerminal(offlineOperationId: String): Boolean =
        mutate(offlineOperationId) { entry -> entry.copy(state = OfflineEntryState.TERMINAL) }

    /**
     * Drops one entry.
     *
     * THE ONLY LEGITIMATE CALLER IS A PROVEN TERMINAL ANSWER. `OfflineSubmission`
     * calls this after a final receipt or an authoritative 4xx, and nowhere
     * else. Removing an entry on an UNKNOWN outcome destroys an operation the
     * server may already have applied, or may still be waiting for; the server
     * converges a duplicate submission through its receipt machinery, so a
     * duplicate costs one repeated request, while a dropped acknowledgement is
     * gone forever. The two mistakes are not comparable.
     *
     * The sequence counter is NOT rewound. It never is. A removed entry has been
     * settled, so its position is spent.
     */
    fun remove(offlineOperationId: String): Boolean {
        val snapshot = load()
        val remaining = snapshot.entries.filter { it.offlineOperationId != offlineOperationId }
        if (remaining.size == snapshot.entries.size) return false
        persist(Snapshot(snapshot.nextDeviceSequence, remaining))
        return true
    }

    // -----------------------------------------------------------------------
    // The one mutator and the one writer
    // -----------------------------------------------------------------------

    private fun mutate(offlineOperationId: String, change: (OfflineOutboxEntry) -> OfflineOutboxEntry): Boolean {
        val snapshot = load()
        var found = false
        val updated = snapshot.entries.map { entry ->
            if (entry.offlineOperationId == offlineOperationId) {
                found = true
                change(entry)
            } else {
                entry
            }
        }
        if (!found) return false
        persist(Snapshot(snapshot.nextDeviceSequence, updated))
        return true
    }

    /**
     * The ONLY writer.
     *
     * It re-checks the invariants it is about to persist, even though every
     * caller above constructed the snapshot correctly, because the cost of the
     * check is nothing and the thing it prevents is a counter that has moved
     * backwards reaching disk — from where it would be read back as truth.
     */
    private fun persist(snapshot: Snapshot) {
        for (entry in snapshot.entries) {
            if (entry.deviceSequence >= snapshot.nextDeviceSequence) {
                throw MalformedOutbox(
                    "refusing to persist entry sequence ${entry.deviceSequence} " +
                        "at or beyond the next sequence ${snapshot.nextDeviceSequence}",
                )
            }
        }
        val document = buildJsonObject {
            put(FIELD_SCHEMA_VERSION, SCHEMA_VERSION)
            put(FIELD_NEXT_DEVICE_SEQUENCE, snapshot.nextDeviceSequence)
            put(
                FIELD_ENTRIES,
                buildJsonArray {
                    for (entry in snapshot.entries.sortedBy { it.deviceSequence }) add(entry.toJson())
                },
            )
        }
        file.write(document.toString())
    }
}

/** Why an enqueue did or did not take. */
enum class OfflineEnqueueOutcome {
    QUEUED,

    /** The same operation is already queued. Nothing was allocated. */
    DUPLICATE_OPERATION_ID,

    /** The bound is reached. Nothing was allocated, and nothing was evicted. */
    QUEUE_FULL,

    /**
     * The per-device sequence space is exhausted.
     *
     * Unreachable in practice and refused anyway, because the alternative is
     * wrapping — and a wrapped sequence re-uses positions the server settled.
     */
    SEQUENCE_EXHAUSTED,
}

/** The outcome, and the entry when there is one. */
data class OfflineEnqueueResult(
    val outcome: OfflineEnqueueOutcome,
    val entry: OfflineOutboxEntry?,
) {
    val isQueued: Boolean get() = outcome == OfflineEnqueueOutcome.QUEUED
}

/**
 * The stored queue cannot be read as a queue.
 *
 * An `IllegalStateException` rather than a checked failure, and never something
 * a caller can quietly treat as "empty". See [OfflineOutbox.load] for why
 * refusing to operate is the recoverable outcome and silently restarting the
 * count is not.
 */
class MalformedOutbox(message: String) : IllegalStateException(message)
