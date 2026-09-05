package com.sentinel.field.net

/**
 * ============================================================================
 * HOW LONG TO WAIT BEFORE TRYING A QUEUED OPERATION AGAIN.
 *
 * Until WP-29 this client had no retry at all, deliberately: `SentinelHttp`
 * sets `retryOnConnectionFailure(false)` so that a request either happened or
 * did not, with no invisible second attempt underneath a single signed proof.
 * That stays true. This file does not retry anything and does not repeat any
 * request — it answers ONE arithmetic question for a caller that has already
 * decided, on its own, to try again, and the caller mints a fresh proof and a
 * fresh nonce when it does.
 *
 * WHY IT IS A PURE FUNCTION IN ITS OWN FILE
 * -----------------------------------------
 * No clock, no timer, no thread, no `WorkManager`, no scheduler, no new
 * dependency. Attempts in, milliseconds out. Everything about a backoff that
 * can be WRONG — an overflow at attempt 40, a ceiling that is not a ceiling, a
 * jitter that makes the delay go backwards — is arithmetic, and arithmetic is
 * exactly what a JVM unit test on a machine with no Android SDK can settle.
 * Bind this to a clock and none of it is testable here, which is the whole
 * budget this project has.
 *
 * THE SHAPE
 * ---------
 *   * EXPONENTIAL, doubling from [BASE_DELAY_MS], because a device that has
 *     just lost coverage is usually going to stay lost for a while and a fixed
 *     one-second poll is a battery complaint with a network bill attached.
 *
 *   * BOUNDED at [MAX_BASE_DELAY_MS]. Unbounded doubling reaches hours, and an
 *     operative who walks back into coverage should not wait an hour for a
 *     queue that would drain in a second.
 *
 *   * JITTERED, upward, by up to a quarter. Every handset that lost the same
 *     access point rejoins at the same instant, and a fleet retrying in lockstep
 *     turns a recovered network into a thundering herd. The fraction is supplied
 *     BY THE CALLER rather than drawn here, so this stays deterministic and
 *     therefore testable; `kotlin.random.Random.nextDouble()` is the intended
 *     source at the call site.
 *
 * THE CEILING IS ON THE DELAY, NOT ON THE NUMBER OF ATTEMPTS, AND THAT IS THE
 * RULE THAT MATTERS
 * ----------------------------------------------------------------------------
 * There is no `MAX_ATTEMPTS` here and there must not be one. A cap on attempts
 * is a rule that eventually DISCARDS a queued operation — an acknowledgement an
 * operative already made — because a network stayed down longer than somebody
 * guessed. That would also burn its sequence position and stall the per-device
 * cursor behind it. The delay saturates; the operation does not expire. Only
 * the server ends a queued operation, and it ends it by answering.
 * ============================================================================
 */
object RetrySchedule {

    /** The wait after the first failed attempt. */
    const val BASE_DELAY_MS = 2_000L

    /** The ceiling on the exponential part, before jitter. Four minutes. */
    const val MAX_BASE_DELAY_MS = 240_000L

    /** Jitter adds at most `base / 4`. */
    const val JITTER_DIVISOR = 4L

    /**
     * The hard ceiling on anything this function can return: five minutes.
     *
     * Stated as the ceiling PLUS its jitter rather than as a separate clamp, so
     * that jitter survives at saturation. A clamp applied after the fact would
     * make every attempt past the ceiling return the same number to the
     * millisecond, which removes the spread exactly where a recovering network
     * needs it most.
     */
    const val MAX_DELAY_MS = MAX_BASE_DELAY_MS + MAX_BASE_DELAY_MS / JITTER_DIVISOR

    /**
     * How long to wait before attempt number `attemptCount + 1`.
     *
     * [attemptCount] is the number of attempts ALREADY made and not settled, so
     * it is at least 1: there is no delay before the first attempt, and asking
     * for one is a bug in the caller rather than a number to invent. [jitter] is
     * a fraction in `0.0 .. 1.0`; out of range is REFUSED rather than clamped,
     * because a clamp silently turns a caller arithmetic error into a schedule
     * nobody chose.
     *
     * MONOTONIC: for any fixed jitter, the delay never decreases as the attempt
     * count rises. It cannot, because the base only doubles or saturates and the
     * jitter is a fixed fraction of the base.
     *
     * BOUNDED: the result is never above [MAX_DELAY_MS] and never below
     * [BASE_DELAY_MS].
     *
     * The doubling is a LOOP that stops at the ceiling rather than a shift by
     * `attemptCount - 1`. A shift overflows `Long` somewhere past attempt 63 and
     * comes back NEGATIVE, and a negative delay is a tight retry loop — which is
     * the exact opposite of what a backoff is for, arriving precisely when the
     * network has been down longest.
     */
    fun delayMillis(attemptCount: Int, jitter: Double): Long {
        require(attemptCount >= 1) {
            "there is no delay before the first attempt; attemptCount was $attemptCount"
        }
        require(jitter >= 0.0 && jitter <= 1.0) {
            "the jitter fraction must be 0.0..1.0, not $jitter"
        }
        var base = BASE_DELAY_MS
        var doublings = attemptCount - 1
        while (doublings > 0 && base < MAX_BASE_DELAY_MS) {
            base *= 2
            doublings -= 1
        }
        if (base > MAX_BASE_DELAY_MS) base = MAX_BASE_DELAY_MS
        val spread = base / JITTER_DIVISOR
        return base + (spread.toDouble() * jitter).toLong()
    }

    /**
     * Whether enough time has passed to try this entry again.
     *
     * The caller supplies BOTH the attempt count and the elapsed time, so this
     * object still reads no clock. That is not fastidiousness: a scheduler that
     * read the wall clock here would be untestable on this machine, and the
     * caller already knows when it last tried because the outbox recorded it.
     *
     * An entry that has never been attempted is DUE IMMEDIATELY — [attemptCount]
     * of zero answers true without consulting anything else.
     */
    fun isDue(attemptCount: Int, elapsedSinceLastAttemptMs: Long, jitter: Double): Boolean {
        if (attemptCount <= 0) return true
        return elapsedSinceLastAttemptMs >= delayMillis(attemptCount, jitter)
    }
}
