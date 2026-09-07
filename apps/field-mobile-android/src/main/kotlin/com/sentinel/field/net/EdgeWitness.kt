package com.sentinel.field.net

/**
 * ============================================================================
 * THE RESULT OF OFFERING ONE QUEUED OPERATION TO A SITE EDGE.
 *
 * TWO OUTCOMES, AND THERE CANNOT BE A THIRD. That is the entire reason this is
 * its own type rather than another [CeremonyStep].
 *
 *   WITNESSED       an Edge returned a receipt this client could read, about
 *                   THIS entry, and the entry now holds it.
 *
 *   NOT_WITNESSED   everything else, without exception: no Edge configured, a
 *                   transport failure, a 4xx, a 5xx, a 409, a 2xx whose body
 *                   will not parse, a receipt that is not a receipt, and a
 *                   receipt about some other operation.
 *
 * ============================================================================
 * WHY THERE IS NO `REFUSED`, AND WHY THAT ABSENCE IS THE POINT
 * ============================================================================
 *
 * [CeremonyStep] is the right shape for talking to CENTRAL, and it carries a
 * `REFUSED` because central can genuinely end an operation: it holds the lease
 * record, the device registry, the replay store and the receipt clock, and when
 * it declines an envelope the envelope is finished.
 *
 * EDGE HOLDS NONE OF THAT AND MAY END NOTHING (D23-10). An Edge answering 400
 * is an Edge saying something about its own ingress — it is out of disk, it
 * does not like the shape, it has no trusted-time anchor, it has been handed a
 * site it is not authorised for. NOT ONE OF THOSE IS A FACT ABOUT WHETHER THE
 * OPERATION HAPPENED, and the operative's acknowledgement is exactly as real
 * after it as before. If this type could express a refusal, then sooner or
 * later a caller would branch on it and drop a queue entry, and the visible
 * behaviour would be: a Field operation vanishing because of a box in a wiring
 * closet, with nothing in central to show it ever existed. That is the failure
 * D23-10 exists to make impossible, and the way to make it impossible in code
 * is to leave out the constructor.
 *
 * So `NOT_WITNESSED` deliberately flattens every unhappy path into one, and the
 * one thing every member of it has in common is the only thing that matters:
 * THE ENTRY IS STILL QUEUED, unchanged, at the same position, with the same
 * signature, waiting for central.
 *
 * WHY IT IS A PLAIN CLASS WITH A `kind` rather than a sealed hierarchy: the
 * same reason [CeremonyStep] gives. Nothing here is compiled on the author's
 * machine, hosted CI is the only verification, and a shape whose correctness
 * depends on generic smart-cast inference is a shape that can fail to compile
 * in a way nobody sees until the runner does.
 * ============================================================================
 */
class EdgeWitness private constructor(
    val kind: Kind,
    /** The receipt now stored against the entry, on [Kind.WITNESSED] only. */
    val receipt: EdgeReceipt?,
    /** The HTTP status, or 0 when no answer arrived — or when nothing was sent. */
    val status: Int,
    /** For a human reading a log. Never an authorisation or a control input. */
    val detail: String,
) {

    enum class Kind { WITNESSED, NOT_WITNESSED }

    /**
     * True when this entry holds an Edge witness.
     *
     * IT IS NOT A PERMISSION AND IT IS NOT A COMPLETION. An operation that has
     * been witnessed has not been submitted, accepted, applied or acknowledged
     * by anybody: it is queued, exactly as it was, now carrying evidence about
     * when it was seen. A caller that treated this as "done" would be a caller
     * that stops draining the queue to central, which is the only place the
     * operation can actually take effect.
     */
    val isWitnessed: Boolean get() = kind == Kind.WITNESSED

    fun describe(): String = when (kind) {
        Kind.WITNESSED -> "witnessed: ${receipt?.describe() ?: "-"}"
        Kind.NOT_WITNESSED -> "not witnessed ($status): $detail"
    }

    companion object {
        fun witnessed(receipt: EdgeReceipt, detail: String): EdgeWitness =
            EdgeWitness(Kind.WITNESSED, receipt, 200, detail)

        /**
         * [status] is the Edge's own status where there was one, and 0 where no
         * answer arrived at all — including the case where no Edge is
         * configured on this device, which is the ordinary state today. See
         * [EdgeTransport].
         */
        fun notWitnessed(status: Int, detail: String): EdgeWitness =
            EdgeWitness(Kind.NOT_WITNESSED, null, status, detail)
    }
}
