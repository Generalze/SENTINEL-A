package com.sentinel.field.net

import com.sentinel.field.security.ClientNonce
import com.sentinel.field.security.DeviceStatements
import com.sentinel.field.store.OfflineOutbox
import com.sentinel.field.store.OfflineOutboxEntry
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * ============================================================================
 * DRAINING THE OFFLINE QUEUE THROUGH THE WP-25 GATEWAY.
 *
 * One queued operation, one request, one classification. There is no loop here
 * and no scheduler: the caller drives, `RetrySchedule` says how long to wait
 * between goes, and this class does exactly one crossing per call so that every
 * outcome is attributable to one envelope.
 *
 * THE BODY, AND WHY IT HAS TWO MEMBERS AND NOT FOUR
 * -------------------------------------------------
 *     {
 *       "proof":   a FRESH WP-25 DeviceRequestProof, minted now
 *       "payload": { "envelope": the C14-04 offline envelope, signed WHEN IT
 *                                WAS QUEUED,
 *                    "payload":  the semantic body that envelope digest covers }
 *     }
 *
 * THE NESTING IS NOT COSMETIC, and an earlier draft of this client got it
 * wrong. The gateway request body is `.strict()` (C17-06) and admits exactly
 * `proof`, `payload` and three optional echoes; the SEMANTIC PAYLOAD is what
 * lives under `payload`, and for this kind the semantic payload IS the pair
 * `{ envelope, payload }`. A body with `envelope` at the top level is refused
 * ENVELOPE_MALFORMED on every single submission — not intermittently, not on
 * an edge case, but always — because an unknown top-level key is a value the
 * signature does not cover and the schema will not accept one.
 *
 * THE THREE ECHOES ARE OMITTED. `operation_kind`, `target_type` and `target_id`
 * may be sent, and each is equality-bound to what the ROUTE and the SERVER
 * already resolved, so a disagreement is a refusal rather than an override.
 * They add nothing and each is another value that has to keep agreeing, so this
 * client sends none of them — the same choice it makes on the other surfaces.
 *
 * THERE IS NO `trace_id` IN THE BODY. The server takes the trace from the
 * REQUEST and mints one when there is none. Sending it here would be an unknown
 * top-level key, which is to say a refusal. It is also the honest arrangement:
 * a trace is non-semantic and a legitimate retry may carry a fresh one (C10-04),
 * so it has no business inside a strict body next to signed material.
 *
 * TWO SIGNATURES OVER TWO DIFFERENT THINGS, MADE AT TWO DIFFERENT TIMES, AND
 * THAT IS THE ENTIRE POINT OF THE OFFLINE PATH. The ENVELOPE was signed hours
 * ago, disconnected, and it is what proves the operation happened under a named
 * lease with a named actor on a named device — it is never re-signed here,
 * because re-signing would mean a second `created_at` and a second nonce for one
 * act the operative performed once. The PROOF is minted at this instant, over a
 * fresh one-shot nonce, and it authenticates THIS REQUEST inside a live context
 * belonging to a live human session. Neither substitutes for the other: the
 * proof says who is speaking now, the envelope says what was done then.
 *
 * TWO SIGNATURES ALSO MEANS TWO PREIMAGES, AND THEY ARE NOT INTERCHANGEABLE.
 * The proof `payload_digest` is the WP-25 GATEWAY ENVELOPE DIGEST over the
 * canonical operation envelope for kind `OFFLINE_QUEUE_SUBMIT`, whose
 * `target_id` is the QUEUED OPERATION'S OWN ID and whose semantic payload is the
 * `{ envelope, payload }` pair above — see `OfflineEnvelope.gatewayPayloadDigest`.
 * It is NOT `deviceOfflineOperationFingerprint`, which is the identity of the
 * queued STATEMENT and is what the envelope own signature covers. An earlier
 * draft used the fingerprint here; it would have produced a proof over bytes
 * the server never reconstructs, and the answer would have been a signature
 * failure naming nothing anybody could act on.
 *
 * `target_id` being the queued operation, rather than the operative, is what
 * binds the freshly proved request to the SPECIFIC statement it carries. The
 * server refuses a disagreement between its outer target and the inner signed
 * `offline_operation_id`, and this is the client half of that agreement.
 *
 * ============================================================================
 * THE RULE THAT GOVERNS EVERY BRANCH BELOW
 * ============================================================================
 *
 * AN ENTRY LEAVES THE QUEUE ONLY ON A PROVEN TERMINAL ANSWER.
 *
 * This is C18-R1 applied to the one place where the cost of getting it wrong is
 * permanent. The server converges duplicates through its receipt machinery —
 * C15-05 exists precisely because "a queue that reconnects and re-sends is the
 * NORMAL case", and a byte-identical retry converges on the stored outcome
 * rather than committing a second effect. So a duplicate submission costs one
 * repeated request. A DROPPED ACKNOWLEDGEMENT COSTS THE ACKNOWLEDGEMENT, and
 * nobody finds out: the operative saw it queue, the queue is now empty, and the
 * incident record says the message was never acknowledged. The two mistakes are
 * not comparable, so every ambiguous outcome keeps the entry.
 *
 *   a 2xx with a FINAL receipt          settled. Removed.
 *   a 2xx with a non-final receipt      UNKNOWN. Stays queued. C10-08: only
 *                                       APPLIED and REJECTED consume a queue
 *                                       position; RECEIVED, APPLYING and
 *                                       UNKNOWN do not, and an entry this
 *                                       client dropped on a RECEIVED would be
 *                                       an entry the server was still waiting
 *                                       to be told about.
 *   a 2xx this client cannot read       UNKNOWN. Never a refusal, and never a
 *                                       rethrow — the extraction is the part
 *                                       that can fail, and C18-R1A is the
 *                                       correction that says so.
 *   a 4xx other than 409                REFUSED, and terminal. The server
 *                                       evaluated THIS envelope and declined it.
 *   409                                 UNKNOWN, said by the server itself.
 *   5xx                                 UNKNOWN. The server may have failed
 *                                       after committing.
 *   status 0 (transport)                UNKNOWN. `SentinelHttp` reports every
 *                                       transport failure as 0, and that bucket
 *                                       contains the case that matters most —
 *                                       the request arrived, the server
 *                                       committed, and the RESPONSE was lost.
 *
 * A ROTATED KEY IS NOT A SPECIAL CASE AND IS NOT CHECKED FOR HERE. An envelope
 * signed under a key version the registry has since replaced is refused
 * DEVICE_KEY_NOT_USABLE — the server admits a rotated key for verifying history
 * but not for authorising NEW work, and an offline operation being reconciled
 * has not been applied yet. That is an authoritative 4xx, so the entry is
 * settled and removed. A local pre-check would only be this client guessing at
 * a judgement the registry owns.
 * ============================================================================
 */
class OfflineSubmission(
    private val http: SentinelHttp,
    /**
     * The proof minter. `OfflineSubmission` does not build its own: there is
     * exactly ONE `DeviceRequestProof` construction site in this client, and a
     * second one is how two of them come to disagree about a field.
     */
    private val gateway: GatewaySession,
    private val outbox: OfflineOutbox,
) {

    companion object {

        /** The WP-29A drain surface. */
        const val PATH = "/api/v1/device-gateway/operations/offline-queue"

        /**
         * The server's own "I cannot yet say what your submission produced".
         *
         * Named as a constant, exactly as `EnrollmentCeremony` and
         * `GatewaySession` name theirs, so that the one status this client must
         * NOT read as a refusal is something somebody has to delete on purpose
         * rather than a magic number inside a comparison.
         */
        private const val COMPLETION_UNKNOWN = 409

        /**
         * `OFFLINE_CURSOR_ADVANCING_STATUSES` from
         * `packages/contracts/src/field-offline.ts`, quoted rather than invented.
         *
         * C10-08: "APPLIED and deterministic REJECTED advance the cursor; UNKNOWN
         * never does — an operation that died mid-flight is retried into
         * convergence, not skipped past". A receipt in any other state has not
         * consumed its queue position, so this client has not finished with it
         * either.
         */
        val RECEIPT_STATUSES_THAT_SETTLE: List<String> = listOf("APPLIED", "REJECTED")

        /**
         * The classifier, and the ONLY place an entry is settled.
         *
         * A companion function over an explicit [answer] rather than a private
         * method reached through the network: this is the part that has to be
         * exactly right, and this way `OfflineSubmissionTest` can execute every
         * branch of it on the JVM with no transport, no Android runtime and no
         * restructuring of production code to suit a test.
         *
         * The outbox writes are allowed to throw out of here. If marking an
         * entry terminal fails because the disk did, the answer this returns is
         * lost and the entry stays queued — which retries, which converges. The
         * inverse ordering, where the answer is returned and the queue is not
         * updated, is the one that loses things.
         */
        internal fun settle(
            outbox: OfflineOutbox,
            entry: OfflineOutboxEntry,
            answer: SentinelHttp.Answer,
        ): CeremonyStep<JsonObject> {
            if (answer.ok) {
                val body = answer.body
                    ?: return CeremonyStep.completionUnknown(
                        answer.status,
                        "the server succeeded and the body could not be read as JSON",
                    )
                // C18-R1A: THE EXTRACTION IS THE PART THAT CAN FAIL. A reader
                // that threw here would leave the classifier by exception rather
                // than being classified, which is the same defect one layer out:
                // an outcome that cannot be proven being turned into something
                // other than "unknown". It answers null instead, and the wrapper
                // catches anything a future reader might throw.
                val status = try {
                    receiptStatusOrNull(body)
                } catch (error: Exception) {
                    null
                }
                if (status == null) {
                    return CeremonyStep.completionUnknown(
                        answer.status,
                        "the server succeeded and named no readable receipt status",
                    )
                }
                if (!RECEIPT_STATUSES_THAT_SETTLE.contains(status)) {
                    // A real, readable answer that is NOT final. The server has
                    // the operation and has not finished with it, so neither has
                    // this queue.
                    return CeremonyStep.completionUnknown(answer.status, "the receipt is not final: $status")
                }
                settleInOutbox(outbox, entry)
                return CeremonyStep.ok(body)
            }

            if (answer.status in 400..499 && answer.status != COMPLETION_UNKNOWN) {
                // AUTHORITATIVE. The server evaluated this exact envelope and
                // declined it. The position is spent either way — the sequence
                // counter never rewinds — so the entry is settled and removed.
                settleInOutbox(outbox, entry)
                return CeremonyStep.refused(answer.status, answer.text)
            }

            // 409, every 5xx, and every transport failure. The entry stays
            // exactly where it is, with its attempt recorded.
            return CeremonyStep.completionUnknown(answer.status, answer.text)
        }

        /**
         * TERMINAL FIRST, THEN REMOVED, IN TWO WRITES.
         *
         * The two-step has a safe midpoint and the alternatives do not. Die
         * between them and what survives is an entry marked TERMINAL, which
         * `peekNext` skips — so the operation is never re-sent, and a later pass
         * can clear it. Remove first and the midpoint is an entry that is gone
         * with nothing recorded; do both in one write and there is no midpoint,
         * but a failure loses the record of an answer the server has already
         * given.
         */
        private fun settleInOutbox(outbox: OfflineOutbox, entry: OfflineOutboxEntry) {
            outbox.markTerminal(entry.offlineOperationId)
            outbox.remove(entry.offlineOperationId)
        }

        /**
         * The receipt status, read out BY NAME and BY TYPE, or null.
         *
         * The status is looked for on a `receipt` member and then at the top
         * level, because those are the two shapes a receipt-bearing answer takes
         * across this platform, and neither is guessed at destructively: an
         * answer carrying neither reads as null, which is UNKNOWN, which keeps
         * the entry. The failure direction of a wrong guess here is a repeated
         * submission that converges — never a dropped operation.
         */
        internal fun receiptStatusOrNull(body: JsonObject): String? {
            val receipt = body["receipt"] as? JsonObject
            return stringOrNull(receipt, "status") ?: stringOrNull(body, "status")
        }

        private fun stringOrNull(source: JsonObject?, key: String): String? {
            if (source == null) return null
            val primitive = source[key] as? JsonPrimitive ?: return null
            if (!primitive.isString) return null
            return primitive.content
        }
    }

    /**
     * Submits the oldest unsettled entry, or answers null when there is nothing
     * queued.
     *
     * The attempt is RECORDED BEFORE THE REQUEST GOES OUT. An attempt made but
     * not recorded is invisible to the backoff, so a device that died mid-request
     * would come back and hammer the same operation with no delay — which is the
     * behaviour a backoff exists to prevent, arriving exactly when the network
     * is least able to take it.
     *
     * [siteId] comes from the ENTRY and not from the caller: the operation
     * belongs to the site it was queued at, and the proof must be minted for
     * that site or it does not describe the operation it is carrying.
     */
    fun submitNext(
        sessionUserId: String,
        context: GatewaySession.DeviceContext,
    ): CeremonyStep<JsonObject>? {
        val entry = outbox.peekNext() ?: return null
        return submit(sessionUserId, context, entry)
    }

    /** Submits one specific entry. */
    fun submit(
        sessionUserId: String,
        context: GatewaySession.DeviceContext,
        entry: OfflineOutboxEntry,
    ): CeremonyStep<JsonObject> {
        outbox.markAttempt(entry.offlineOperationId, ClientNonce.nowIso())

        val proof = gateway.signProof(
            // The LIVE context authenticates the request. Its key id and version
            // are the ones in force now, which is not necessarily the pair the
            // envelope was signed under — and that difference is a fact for the
            // server to judge, not one for this client to hide.
            contextId = context.contextId,
            organisationId = context.organisationId,
            siteId = entry.siteId,
            actorUserId = context.actorUserId,
            deviceId = context.deviceId,
            keyId = context.keyId,
            keyVersion = context.keyVersion,
            // NOT `FIELD_OPERATION`. `DEVICE_QUEUE_ADMISSION_PURPOSE` is the
            // frozen purpose for queued work, and the purpose lives inside the
            // signed proof — a proof minted under one purpose is refused for
            // another, so this is not a label.
            purpose = DeviceStatements.PURPOSE_OFFLINE_SYNC,
            // The WP-25 gateway envelope digest for `OFFLINE_QUEUE_SUBMIT`,
            // targeting the QUEUED OPERATION and covering the same
            // `{ envelope, payload }` object the body carries. Not the offline
            // fingerprint: that is the queued statement own identity, and the
            // envelope signature already covers it.
            payloadDigest = OfflineEnvelope.gatewayPayloadDigest(
                entry = entry,
                organisationId = context.organisationId,
                siteId = entry.siteId,
                actorUserId = context.actorUserId,
                deviceId = context.deviceId,
            ),
        )

        val answer = http.post(
            PATH,
            sessionUserId,
            buildJsonObject {
                // TWO MEMBERS. The strict gateway body admits `proof`, `payload`
                // and three optional echoes, and nothing else; the echoes are
                // omitted and the trace comes from the request, not from here.
                //
                // `submissionJson` serialises the SAME map the digest above was
                // taken over, so the two cannot drift.
                put("proof", proof)
                put("payload", OfflineEnvelope.submissionJson(entry))
            },
        )
        return settle(outbox, entry, answer)
    }
}
