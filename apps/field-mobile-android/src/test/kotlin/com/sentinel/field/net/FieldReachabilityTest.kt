package com.sentinel.field.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * ============================================================================
 * THE THREE STATES A FIELD HANDSET CAN BE IN, AND THE ONE RULE THAT DECIDES
 * THEM.
 *
 * Arithmetic in, a state out, with no clock and no scheduler — the same shape
 * `RetryScheduleTest` exercises and for the same reason: everything about
 * reachability that can be WRONG is a comparison, and a comparison is exactly
 * what a JVM unit test on a machine with no Android SDK can settle.
 * ============================================================================
 */
class FieldReachabilityTest {

    private fun answer(status: Int): SentinelHttp.Answer =
        SentinelHttp.Answer(status = status, body = null, text = "")

    // -----------------------------------------------------------------------
    // What "reached" means
    // -----------------------------------------------------------------------

    /**
     * A 403 IS REACHED, AND THAT IS THE ASSERTION WORTH HAVING.
     *
     * The question is "can I get bytes to central right now", not "will central
     * accept them". A client that reported itself offline because an
     * operative's authority had been withdrawn would be lying at precisely the
     * moment somebody would believe it.
     */
    @Test
    fun `any answered status counts as reached`() {
        for (status in listOf(200, 201, 204, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503)) {
            assertTrue("status $status means a host answered", FieldReachability.reached(answer(status)))
        }
    }

    /**
     * Status 0 is `SentinelHttp`'s single report for every transport failure —
     * connect refused, DNS gone, timeout, an unparseable base URL — and it is
     * the only value that means no answer arrived.
     */
    @Test
    fun `only status zero is unreached`() {
        assertFalse(FieldReachability.reached(answer(0)))
        assertFalse(FieldReachability.reached(SentinelHttp.Reply(0, null, "")))
        assertTrue(FieldReachability.reached(SentinelHttp.Reply(500, null, "")))
    }

    // -----------------------------------------------------------------------
    // The three states
    // -----------------------------------------------------------------------

    @Test
    fun `central reachable is CENTRAL whatever the Edge did`() {
        assertEquals(Reachability.CENTRAL, FieldReachability.of(centralReached = true, edgeReached = true))
        assertEquals(Reachability.CENTRAL, FieldReachability.of(centralReached = true, edgeReached = false))
    }

    /**
     * THE INTERESTING STATE. The operative can still work, the queue still
     * grows, local refusals still bite, and the one thing that is available —
     * an independent clock — is available NOW and will not be later.
     */
    @Test
    fun `central unreachable and an Edge answering is EDGE_ONLY`() {
        assertEquals(Reachability.EDGE_ONLY, FieldReachability.of(centralReached = false, edgeReached = true))
    }

    /**
     * NOT AN ERROR STATE. A handset out of coverage with no Edge on the LAN is
     * the ordinary condition the whole offline path exists for.
     */
    @Test
    fun `neither answering is NONE`() {
        assertEquals(Reachability.NONE, FieldReachability.of(centralReached = false, edgeReached = false))
    }

    @Test
    fun `the state is derived from the answers themselves the same way`() {
        assertEquals(Reachability.CENTRAL, FieldReachability.of(answer(503), answer(0)))
        assertEquals(Reachability.EDGE_ONLY, FieldReachability.of(answer(0), answer(200)))
        assertEquals(Reachability.NONE, FieldReachability.of(answer(0), answer(0)))
    }

    /**
     * A PROBE NOBODY MADE IS NOT A SUCCESS.
     *
     * Null is "not attempted", and it is treated as "did not answer" — the
     * fail-closed direction. Understating what the device can do costs nothing;
     * reporting CENTRAL on the strength of a request nobody made would send a
     * caller to drain a queue into a network that is not there.
     */
    @Test
    fun `an unattempted probe is not a reachable one`() {
        assertEquals(Reachability.NONE, FieldReachability.of(null, null))
        assertEquals(Reachability.EDGE_ONLY, FieldReachability.of(null, answer(200)))
        assertEquals(Reachability.CENTRAL, FieldReachability.of(answer(200), null))
    }

    @Test
    fun `only CENTRAL says central is reachable`() {
        assertFalse(Reachability.CENTRAL.isCentralUnreachable)
        assertTrue(Reachability.EDGE_ONLY.isCentralUnreachable)
        assertTrue(Reachability.NONE.isCentralUnreachable)
    }

    /**
     * Three members, pinned.
     *
     * A fourth would be a state some caller has to handle and every existing
     * caller silently would not, so adding one is a visible act rather than an
     * afternoon's convenience.
     */
    @Test
    fun `there are exactly three states`() {
        assertEquals(
            listOf(Reachability.CENTRAL, Reachability.EDGE_ONLY, Reachability.NONE),
            Reachability.values().toList(),
        )
    }
}
