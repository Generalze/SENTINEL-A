package com.sentinel.field.net

import com.sentinel.field.store.MalformedOutbox
import com.sentinel.field.store.OfflineOutbox
import com.sentinel.field.store.OfflineOutboxEntry
import kotlinx.serialization.json.JsonObject

/**
 * ============================================================================
 * OFFERING ONE QUEUED OPERATION TO A SITE EDGE, SO THAT SOMETHING OTHER THAN
 * THIS HANDSET'S CLOCK CAN SAY WHEN IT HAPPENED.
 *
 * The sibling of [OfflineSubmission] and NOT a replacement for it. They do
 * different things to the same entry and only one of them can finish it:
 *
 *   [OfflineSubmission]  submits to CENTRAL, through the WP-25 gateway, with a
 *                        fresh request proof and the human session. Central can
 *                        APPLY the operation, REJECT it, or leave the answer
 *                        unproven — and a proven terminal answer is the only
 *                        thing that removes an entry from the queue.
 *
 *   this class           offers the same bytes to a site EDGE, with no proof
 *                        and no session, and asks for one thing back: a
 *                        witness. Nothing it can receive ends the operation,
 *                        and the entry is queued for central afterwards exactly
 *                        as it was before.
 *
 * ============================================================================
 * WHY THE DEVICE BOTHERS
 * ============================================================================
 *
 * C14-04 admits a queued operation on TWO things: the policy lease it names
 * inside its signature, and a trustworthy instant placing the operation inside
 * that lease. `created_at` cannot be that instant — it is signed, and it is
 * signed as TELEMETRY (D23-12), precisely because a device controls its own
 * clock and a compromised one would simply backdate. So for every operation
 * kind that is not stale-tolerant, the question "when did this happen?" has
 * exactly one admissible answer: an independent witness. An Edge on the site
 * LAN is the only witness that exists while the WAN is down.
 *
 * The receipt is therefore collected AT THE SITE, WHILE THE SITE IS REACHABLE,
 * and carried home in the queue. Collecting it later is not the same thing and
 * usually not possible: the operative walks away from the LAN, and the
 * independent clock that could have vouched for the moment is gone.
 *
 * ============================================================================
 * THE WIRE BODY: TWO MEMBERS, AND THEY ARE THE SAME TWO CENTRAL RECEIVES
 * ============================================================================
 *
 *     {
 *       "envelope": the C14-04 offline envelope, seventeen members, signed in
 *                   StrongBox when the operative pressed the button,
 *       "payload":  the semantic body that envelope's `payload_digest` covers
 *     }
 *
 * IT IS [OfflineEnvelope.submissionJson] VERBATIM — the identical builder the
 * central path uses, not a copy and not an Edge-specific variant. That is the
 * single most important decision in this file and it is worth being explicit
 * about why.
 *
 * A weaker "Edge submission" type is the obvious convenience: Edge does not
 * need the payload to witness the operation, only the fingerprint, so a leaner
 * body would work. It would also be a SECOND definition of what a queued
 * operation is. The moment it exists, the device signs one thing and shows Edge
 * another, and the receipt witnesses bytes that are not the bytes central
 * verifies — so `witnessed_operation_fingerprint` would be computed from a
 * different preimage, central would refuse WITNESS_FINGERPRINT_MISMATCH, and
 * the diagnosis would be a digest disagreement between two structures that were
 * both "correct". `edge-runtime.ts` makes the same ruling on the Edge side and
 * gives the same reason: the runtime's receipt type IS the contract's receipt
 * type, and a parallel one "would start life identical and would drift the
 * first time a runtime author needed just one more field".
 *
 * There is no request proof and no session header. Edge authorises nothing, so
 * there is nothing for it to authenticate — see [EdgeTransport] for the whole
 * argument, and for why the transport itself does not exist yet.
 *
 * ============================================================================
 * CLASSIFICATION: THE SAME DISCIPLINE, WITH ONE BRANCH DELETED
 * ============================================================================
 *
 * [OfflineSubmission] has three outcomes because central has three things it
 * can say. This class has two, because Edge has one:
 *
 *   a 2xx with a READABLE receipt about THIS entry   witnessed. Stored.
 *   a 2xx with a receipt about another operation     NOT witnessed.
 *   a 2xx with a body this client cannot read        NOT witnessed.
 *   a 4xx                                            NOT witnessed.
 *   a 409, a 5xx, a transport failure, no Edge       NOT witnessed.
 *
 * AND IN EVERY ONE OF THOSE, INCLUDING THE FIRST, THE ENTRY STAYS QUEUED. There
 * is no `remove(`, no `markTerminal(` and no `markAttempt(` anywhere in this
 * file, and their absence is asserted by `EdgeSubmissionTest`:
 *
 *   * NO REMOVAL, because Edge may not end an operation (D23-10). A 4xx from
 *     an Edge is a fact about that Edge's ingress, never about whether the
 *     operative's acknowledgement happened.
 *
 *   * NO ATTEMPT COUNTING, because `attemptCount` drives `RetrySchedule`, and
 *     that backoff exists to protect CENTRAL from a fleet reconnecting in
 *     lockstep. Charging a failed Edge probe against it would make a handset
 *     that spent an afternoon beside a broken Edge wait four minutes between
 *     submissions to a central it never tried. The two conversations have
 *     different failure modes and must not share a counter.
 * ============================================================================
 */
class EdgeSubmission(
    /** The seam, and today the only implementation is [EdgeTransport.NotConfigured]. */
    private val edge: EdgeTransport,
    private val outbox: OfflineOutbox,
) {

    companion object {

        /**
         * The classifier, and the ONLY place a receipt is filed.
         *
         * A companion function over an explicit [answer] rather than a private
         * method reached through the network, for the reason
         * `OfflineSubmission.settle` gives: this is the part that has to be
         * exactly right, and this way every branch of it is executed by a JVM
         * unit test with no transport, no Android runtime and no production
         * code restructured to suit a test.
         */
        internal fun record(
            outbox: OfflineOutbox,
            entry: OfflineOutboxEntry,
            answer: SentinelHttp.Answer,
        ): EdgeWitness {
            if (!answer.ok) {
                // EVERY non-2xx, WITHOUT A TERMINAL BRANCH. There is deliberately
                // no `answer.status in 400..499` here, and its absence is the
                // difference between this classifier and the central one. Edge
                // cannot evaluate an operation, so an Edge 4xx is not an
                // authoritative refusal of anything — and a branch that treated
                // it as one would be the branch through which a site LAN
                // deletes Field work.
                return EdgeWitness.notWitnessed(answer.status, answer.text)
            }

            val body = answer.body
                ?: return EdgeWitness.notWitnessed(
                    answer.status,
                    "the Edge succeeded and the body could not be read as JSON",
                )

            // C18-R1A: THE EXTRACTION IS THE PART THAT CAN FAIL. `fromWire`
            // answers null rather than throwing, and the call is wrapped anyway,
            // because the reader somebody edits next quarter is not this reader
            // and an exception escaping here would leave the classifier by
            // exception instead of being classified.
            val receipt = try {
                receiptOrNull(body)
            } catch (error: Exception) {
                null
            }
            if (receipt == null) {
                return EdgeWitness.notWitnessed(
                    answer.status,
                    "the Edge succeeded and returned nothing this client can read as a receipt",
                )
            }

            // THE RECEIPT MUST BE ABOUT THIS ENTRY.
            //
            // `deviceOfflineOperationFingerprint` of the queued statement is
            // what an Edge witnesses, and it is computable here because the
            // device holds every field of its own signed statement. Central
            // performs this same comparison against ITS resolved profile and
            // refuses WITNESS_FINGERPRINT_MISMATCH; doing it here means a
            // receipt filed against the wrong operation is never stored in the
            // first place, and a confused or hostile Edge cannot make one entry
            // carry another entry's clock.
            //
            // THE CHECK MAY ONLY REFUSE. Agreement proves nothing — this
            // fingerprint is computed over the profile this device CLAIMS
            // (C15-01), and if that claim is wrong the envelope is refused
            // centrally on its own account. A disagreement is still worth
            // acting on: whichever side is wrong, filing the receipt here would
            // store evidence about something else.
            val expected = OfflineEnvelope.fingerprint(entry)
            if (receipt.witnessedOperationFingerprint != expected) {
                return EdgeWitness.notWitnessed(
                    answer.status,
                    "the Edge witnessed ${receipt.witnessedOperationFingerprint}, " +
                        "which is not ${entry.offlineOperationId}",
                )
            }

            // The FIRST witness wins: `recordEdgeReceipt` declines to overwrite
            // one, and answers false when it does. That false is not a failure
            // — the entry holds a witness either way, which is what
            // [EdgeWitness.isWitnessed] means — so it is deliberately not
            // branched on here. See `OfflineOutbox.recordEdgeReceipt` for why a
            // later receipt must not displace an earlier one.
            outbox.recordEdgeReceipt(entry.offlineOperationId, receipt.canonicalJson())
            return EdgeWitness.witnessed(receipt, "the Edge witnessed this operation")
        }

        /**
         * The receipt object, read out BY NAME, or null.
         *
         * Looked for on a `receipt` member and then at the top level — the two
         * shapes a receipt-bearing answer takes across this platform, and the
         * same order `OfflineSubmission.receiptStatusOrNull` looks in. Neither
         * is guessed at destructively: an answer carrying neither reads as
         * null, which is NOT_WITNESSED, which leaves the entry exactly as it
         * was. The failure direction of a wrong guess here is a missing witness
         * — never a dropped operation.
         */
        internal fun receiptOrNull(body: JsonObject): EdgeReceipt? {
            val nested = body["receipt"] as? JsonObject
            if (nested != null) return EdgeReceipt.fromWire(nested)
            return EdgeReceipt.fromWire(body)
        }
    }

    /**
     * Offers the oldest unsettled entry to the Edge, or answers null when there
     * is nothing queued.
     *
     * The same `peekNext` the central path uses, so the two drain in the same
     * order — by SEQUENCE, which is the order central's cursor expects.
     */
    fun witnessNext(): EdgeWitness? {
        val entry = outbox.peekNext() ?: return null
        return witness(entry)
    }

    /**
     * Offers one specific entry.
     *
     * AN ENTRY THAT ALREADY HOLDS A WITNESS IS NOT OFFERED AGAIN, and nothing
     * is sent. Re-offering could only produce a receipt witnessing a LATER
     * instant, which `OfflineOutbox.recordEdgeReceipt` would decline anyway;
     * not sending it also means a queue that has been fully witnessed stops
     * talking to the Edge, which is the behaviour an operator would expect from
     * something with no scheduler behind it.
     *
     * A stored receipt that no longer parses is a [MalformedOutbox] rather than a
     * silent re-witness: the stored copy is the one that travels to central, so if it
     * has been altered underneath this application the honest thing is to stop,
     * exactly as `OfflineEnvelope.submission` stops on a payload that fails its
     * round trip.
     */
    fun witness(entry: OfflineOutboxEntry): EdgeWitness {
        val stored = entry.edgeReceiptJson
        if (stored != null) {
            val existing = EdgeReceipt.fromStored(stored)
                ?: throw MalformedOutbox(
                    "the stored Edge receipt for ${entry.offlineOperationId} is no longer readable",
                )
            return EdgeWitness.witnessed(existing, "this operation was already witnessed")
        }
        // `submissionJson` serialises the SAME `{ envelope, payload }` object
        // the central path posts and the request proof digests, so what Edge
        // witnesses and what central verifies cannot drift apart.
        val answer = edge.submit(OfflineEnvelope.submissionJson(entry))
        return record(outbox, entry, answer)
    }
}
