package com.sentinel.field.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * THE BACKOFF, WHICH IS ARITHMETIC AND THEREFORE PROVABLE HERE.
 *
 * `RetrySchedule` reads no clock, holds no state and starts no thread
 * precisely so that this file can settle every part of it that can be wrong:
 * the ceiling, the monotonicity, the overflow, and the refusal to invent a
 * delay for an attempt that has not happened.
 *
 * The one thing asserted most emphatically is the NEGATIVE-DELAY case. A shift
 * by `attemptCount - 1` overflows `Long` past attempt 63 and comes back
 * negative, and a negative delay is a tight retry loop that arrives precisely
 * when the network has been down longest. The loop in the implementation
 * cannot do it, and this proves it cannot rather than trusting that it does not.
 * ============================================================================
 */
class RetryScheduleTest {

    @Test
    fun `the first wait is the base delay`() {
        assertEquals(RetrySchedule.BASE_DELAY_MS, RetrySchedule.delayMillis(1, 0.0))
    }

    @Test
    fun `the delay doubles until it reaches the ceiling`() {
        assertEquals(2_000L, RetrySchedule.delayMillis(1, 0.0))
        assertEquals(4_000L, RetrySchedule.delayMillis(2, 0.0))
        assertEquals(8_000L, RetrySchedule.delayMillis(3, 0.0))
        assertEquals(16_000L, RetrySchedule.delayMillis(4, 0.0))
        assertEquals(RetrySchedule.MAX_BASE_DELAY_MS, RetrySchedule.delayMillis(40, 0.0))
    }

    @Test
    fun `the delay is monotonic for any fixed jitter`() {
        for (jitter in listOf(0.0, 0.25, 0.5, 0.75, 1.0)) {
            var previous = 0L
            for (attempt in 1..200) {
                val delay = RetrySchedule.delayMillis(attempt, jitter)
                assertTrue(
                    "attempt $attempt with jitter $jitter went backwards: $delay after $previous",
                    delay >= previous,
                )
                previous = delay
            }
        }
    }

    @Test
    fun `the delay is bounded above and below, at every attempt and every jitter`() {
        for (attempt in listOf(1, 2, 5, 17, 62, 63, 64, 100, 1_000, Int.MAX_VALUE)) {
            for (jitter in listOf(0.0, 0.01, 0.5, 0.99, 1.0)) {
                val delay = RetrySchedule.delayMillis(attempt, jitter)
                assertTrue(
                    "attempt $attempt jitter $jitter produced $delay, below the base",
                    delay >= RetrySchedule.BASE_DELAY_MS,
                )
                assertTrue(
                    "attempt $attempt jitter $jitter produced $delay, above the ceiling",
                    delay <= RetrySchedule.MAX_DELAY_MS,
                )
            }
        }
    }

    /**
     * The exact case a shift would get wrong. At attempt 64 a
     * `BASE shl (attemptCount - 1)` is long past overflow.
     */
    @Test
    fun `a very high attempt count saturates rather than overflowing`() {
        for (attempt in listOf(62, 63, 64, 65, 1_000_000, Int.MAX_VALUE)) {
            val delay = RetrySchedule.delayMillis(attempt, 0.0)
            assertEquals(RetrySchedule.MAX_BASE_DELAY_MS, delay)
            assertTrue("attempt $attempt produced a negative delay", delay > 0L)
        }
    }

    /**
     * Jitter is upward only and at most a quarter, so it can never push one
     * attempt past the next — which is what keeps the schedule monotonic even
     * when the fraction differs between two draws.
     */
    @Test
    fun `jitter adds at most a quarter and never subtracts`() {
        for (attempt in 1..20) {
            val floor = RetrySchedule.delayMillis(attempt, 0.0)
            val ceiling = RetrySchedule.delayMillis(attempt, 1.0)
            assertTrue(ceiling >= floor)
            assertEquals(floor + floor / RetrySchedule.JITTER_DIVISOR, ceiling)
        }
    }

    @Test
    fun `a fully jittered attempt never reaches the next unjittered one`() {
        // Below the ceiling the base doubles, and a quarter is less than a
        // double, so no draw at attempt n can land past attempt n + 1.
        for (attempt in 1..6) {
            assertTrue(
                RetrySchedule.delayMillis(attempt, 1.0) <= RetrySchedule.delayMillis(attempt + 1, 0.0),
            )
        }
    }

    @Test
    fun `the ceiling keeps its jitter rather than collapsing to one value`() {
        val saturatedFloor = RetrySchedule.delayMillis(100, 0.0)
        val saturatedCeiling = RetrySchedule.delayMillis(100, 1.0)
        assertTrue(saturatedCeiling > saturatedFloor)
        assertEquals(RetrySchedule.MAX_DELAY_MS, saturatedCeiling)
    }

    // -----------------------------------------------------------------------
    // Refusals
    // -----------------------------------------------------------------------

    @Test
    fun `there is no delay before the first attempt and asking for one is refused`() {
        for (attempt in listOf(0, -1, Int.MIN_VALUE)) {
            try {
                RetrySchedule.delayMillis(attempt, 0.0)
                throw AssertionError("expected attempt $attempt to be refused")
            } catch (expected: IllegalArgumentException) {
                assertTrue(expected.message!!.contains("attemptCount"))
            }
        }
    }

    /**
     * Out of range is REFUSED rather than clamped. A clamp turns a caller
     * arithmetic error into a schedule nobody chose, silently.
     */
    @Test
    fun `a jitter fraction outside zero to one is refused rather than clamped`() {
        for (jitter in listOf(-0.0001, 1.0001, 2.0, Double.NaN)) {
            try {
                RetrySchedule.delayMillis(3, jitter)
                throw AssertionError("expected jitter $jitter to be refused")
            } catch (expected: IllegalArgumentException) {
                assertTrue(expected.message!!.contains("jitter"))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Due-ness
    // -----------------------------------------------------------------------

    @Test
    fun `an entry that has never been attempted is due immediately`() {
        assertTrue(RetrySchedule.isDue(0, 0L, 0.0))
    }

    @Test
    fun `an entry is due once the elapsed time reaches its delay`() {
        val delay = RetrySchedule.delayMillis(3, 0.0)
        assertFalse(RetrySchedule.isDue(3, delay - 1, 0.0))
        assertTrue(RetrySchedule.isDue(3, delay, 0.0))
        assertTrue(RetrySchedule.isDue(3, delay + 1, 0.0))
    }
}
