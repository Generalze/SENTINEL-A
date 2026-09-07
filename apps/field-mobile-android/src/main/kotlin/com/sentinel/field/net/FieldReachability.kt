package com.sentinel.field.net

/**
 * ============================================================================
 * WHICH OF THE TWO PARTIES THIS DEVICE CAN CURRENTLY REACH.
 *
 * A pure function over answers the CALLER already has. No clock, no timer, no
 * thread, no `WorkManager`, no scheduler, no new dependency — the same shape
 * and the same reasoning as [RetrySchedule], which answers one arithmetic
 * question for a caller that has already decided to act.
 *
 * WHY THE CALLER DRIVES, STATED PLAINLY. A reachability monitor that polled on
 * its own would need a background executor, would need to decide how often to
 * probe, and would be untestable on a machine with no Android SDK — which is
 * the whole budget this project has. It would also be lying most of the time:
 * "reachable" has a shelf life of about one request on a handset walking around
 * a site, so the only honest reading is the one taken from the last real
 * exchange. So this object holds NO STATE. The caller submits, and passes what
 * came back through here to decide what to tell the operative.
 *
 * ============================================================================
 * WHAT "REACHED" MEANS, AND WHAT IT EMPHATICALLY DOES NOT
 * ============================================================================
 *
 * [reached] is true when a HOST ANSWERED — any status at all, including a 500,
 * a 403 and a 409. `SentinelHttp` reports every transport failure as status 0
 * and nothing else does, so status 0 is the one and only evidence available
 * here that no answer arrived.
 *
 * That means a 403 counts as REACHED, and it should: the question this file
 * answers is "can I get bytes to central right now", not "will central accept
 * them". Conflating the two would produce a client that reports itself offline
 * because an operative's authority was withdrawn — which is exactly the moment
 * the answer needs to be true and exactly the moment somebody would trust it.
 *
 * AND NOTHING HERE IS AUTHORITY. Reachability is a fact about a network. It
 * does not widen a policy lease, does not admit an operation, does not settle a
 * queue entry and must never appear in a condition that decides any of those.
 * The one thing it is for is telling a human what state their handset is in,
 * and letting the caller choose which of the two conversations to have next.
 * ============================================================================
 */
enum class Reachability {

    /**
     * Central answered. The queue can be drained to the only party that can
     * finish an operation, and a witness is no longer the point.
     */
    CENTRAL,

    /**
     * Central did not answer and a site Edge did.
     *
     * THE INTERESTING STATE, and the reason this enum exists. The operative can
     * still work, the queue still grows, local refusals still bite, and the one
     * thing that is available — an independent clock — is available NOW and will
     * not be later. `EdgeSubmission` is what to do about it.
     */
    EDGE_ONLY,

    /**
     * Neither answered.
     *
     * NOT AN ERROR STATE. A handset out of coverage with no Edge on the LAN is
     * the ordinary condition the whole offline path was built for: operations
     * queue, they keep their positions, and they wait. Nothing is discarded and
     * nothing expires — see `RetrySchedule` for why there is no attempt cap.
     */
    NONE;

    /** True when the only party that can finish an operation is out of reach. */
    val isCentralUnreachable: Boolean get() = this != CENTRAL
}

/**
 * The classifier. Two booleans in, one state out.
 *
 * Kept as an object with a named function rather than as a constructor on the
 * enum so that the [reached] rule — the part that is easy to get subtly wrong —
 * has one home and one test.
 */
object FieldReachability {

    /**
     * True when a host answered at all.
     *
     * Status 0 is `SentinelHttp`'s report for every transport failure, and it
     * is the only value that means "no answer arrived". Everything else, up to
     * and including a 503, means bytes crossed the network in both directions.
     */
    fun reached(answer: SentinelHttp.Answer): Boolean = answer.status != 0

    /** [reached] for a read, which carries a different answer type and the same rule. */
    fun reached(reply: SentinelHttp.Reply): Boolean = reply.status != 0

    /**
     * The state, from the two facts the caller holds.
     *
     * CENTRAL WINS WHENEVER IT ANSWERED, whatever the Edge did. The Edge is a
     * fallback for evidence, never a substitute for the party that decides: a
     * device that can reach central has no use for a witness it can no longer
     * do anything with, and reporting EDGE_ONLY while central is up would send
     * a caller down the wrong path.
     */
    fun of(centralReached: Boolean, edgeReached: Boolean): Reachability = when {
        centralReached -> Reachability.CENTRAL
        edgeReached -> Reachability.EDGE_ONLY
        else -> Reachability.NONE
    }

    /**
     * The same state, from the two answers themselves.
     *
     * A null is "not attempted", which is treated exactly as "did not answer".
     * That is the fail-closed direction: a caller that probed neither is told
     * NONE, which understates what the device can do and costs nothing, rather
     * than being told CENTRAL on the strength of a request nobody made.
     */
    fun of(central: SentinelHttp.Answer?, edge: SentinelHttp.Answer?): Reachability = of(
        centralReached = central != null && reached(central),
        edgeReached = edge != null && reached(edge),
    )
}
