package com.sentinel.field.net

import kotlinx.serialization.json.JsonObject

/**
 * ============================================================================
 * THE ONE WAY A QUEUED OPERATION REACHES A SITE EDGE — AND THE PLACE THIS WORK
 * PACKAGE STOPS.
 *
 * A single method over a single request, and NO PRODUCTION IMPLEMENTATION IN
 * THIS APPLICATION. That is not an omission to be tidied up later; it is the
 * honest state of the platform, and the rest of this comment says exactly what
 * is missing and who would have to supply it.
 *
 * ============================================================================
 * WHY THERE IS NO IMPLEMENTATION: THIS DEVICE CANNOT TELL A SITE EDGE FROM
 * ANYTHING ELSE ON THE LAN
 * ============================================================================
 *
 * To talk to an Edge, a handset needs two facts it does not have:
 *
 *   1. WHICH EDGE. There is no field anywhere on the wire that names one. The
 *      device context response (`POST /api/v1/device-gateway/contexts`) returns
 *      `{ context, policy_lease }` and neither carries an Edge id, a host, a
 *      port or a service name; `DevicePolicyLeaseSchema` has nine members and
 *      none of them is an endpoint; `EdgeIdentityContextSchema` is what an EDGE
 *      knows about ITSELF and is never sent to a device.
 *
 *   2. WHICH KEY TO TRUST FOR IT. `EdgeRegistryKeyRecord` holds the Edge's
 *      RECEIPT-SIGNING key and lives at central, where it is used at
 *      reconciliation. It is not a TLS identity, it is not published to
 *      devices, and it would be the wrong thing anyway: a receipt-signing key
 *      and a transport identity are different keys with different lifecycles,
 *      and conflating them is how one compromise becomes two.
 *
 * WITHOUT THE SECOND FACT, THE ONLY WAYS TO OPEN THE CONNECTION ARE ALL
 * DEFECTS, and they are worth naming so that nobody re-derives one:
 *
 *   * A permissive `TrustManager` — accepting any certificate, or any
 *     certificate for a name we did not verify. In a security product this is a
 *     defect even behind a flag, even in a debug build, even "temporarily": it
 *     makes every receipt this device collects a receipt anyone on the site LAN
 *     can mint, and the flag outlives the sprint that added it.
 *
 *   * TRUST ON FIRST USE. The first connection is exactly the one an attacker
 *     is present for — a handset joining a site network it has never joined
 *     before, which is the normal case for a relief operative on a new site.
 *     TOFU pins the attacker and then defends that pin faithfully.
 *
 *   * The system trust store plus a hostname. A publicly-issued certificate for
 *     `edge.site-17.example` proves somebody controls that name, which on a
 *     site LAN with local DNS is not the question anyone meant to ask.
 *
 * SO THIS SUBLANE IS STOPPED, DELIBERATELY, RATHER THAN GUESSED AT. Everything
 * else in the Edge path is built and tested: the body, the receipt reader, the
 * classification, the persistence and the local refusals. What is missing is
 * one seam, and it is small:
 *
 *   THE SMALLEST MISSING SEAM. Central already issues a device context and,
 *   with it, a policy lease, over the authenticated session — the one channel
 *   this device has that is authenticated in both directions and already
 *   carries site-scoped material. That response would need to carry, for each
 *   site the context authorises, the Edge's ADDRESS and a PINNED TRUST ANCHOR
 *   for its TLS identity (an SPKI digest is enough, and is a digest rather than
 *   a key, so it discloses nothing). Central is the party that can supply it,
 *   because central already runs the Edge enrolment ceremony
 *   (`edge-enrolment.ts`) and therefore already knows which Edges exist, at
 *   which site, and whether each is still trusted. Nothing new has to be
 *   distributed to the handset out of band, no new channel has to exist, and
 *   the anchor expires when the context does — so a suspended Edge stops being
 *   reachable at the next context issuance rather than never.
 *
 *   That is a change to a shared contract and to central's context service,
 *   which are other lanes' files, so it is reported and not written here.
 *
 * ============================================================================
 * WHAT THIS INTERFACE DOES AND DOES NOT CARRY
 * ============================================================================
 *
 * The ENDPOINT IS INSIDE THE IMPLEMENTATION, not a parameter. There is no path
 * constant and no base URL on this seam, because this client does not know
 * either and inventing one would put a guess in the middle of code that is
 * otherwise exact — and a guessed path is the kind of thing that is later read
 * as a decision.
 *
 * THERE IS NO SESSION HEADER AND NO REQUEST PROOF. `SentinelHttp` attaches the
 * human session to everything it sends, because every central surface is
 * authenticated by the human (D25-01: there is no credential a DEVICE may hold
 * and present as authority). Edge is not such a surface. It authorises nothing,
 * so there is nothing for it to authenticate; handing it the operative's
 * identity would disclose who is on shift to a box on a site LAN, in exchange
 * for nothing at all. What Edge receives is the same `{ envelope, payload }`
 * pair central receives, and what it can say about it is bounded by
 * [EdgeReceipt].
 * ============================================================================
 */
interface EdgeTransport {

    /**
     * Posts one `{ envelope, payload }` pair to the site Edge over TLS and
     * returns whatever came back.
     *
     * The implementation MUST NOT throw. A [SentinelHttp.Answer] with status 0
     * is how "no answer arrived" is reported everywhere else in this client,
     * and the classifier depends on it: a thrown exception here would leave
     * `EdgeSubmission` by exception rather than being classified, which is the
     * C18-R1A defect one layer down.
     *
     * It MUST validate the TLS identity of the Edge against a trust anchor it
     * was given out of band. An implementation that cannot do that must not
     * exist — [NotConfigured] is what this client uses instead, and it is not a
     * placeholder to be filled in with a permissive one.
     */
    fun submit(body: JsonObject): SentinelHttp.Answer

    companion object {

        /**
         * THE ONLY IMPLEMENTATION IN THIS APPLICATION: there is no Edge, and it
         * says so.
         *
         * It answers status 0 — the same status a transport failure produces —
         * because that is the truth from the caller's position: no answer
         * arrived. `EdgeSubmission` classifies it as NOT_WITNESSED, the entry
         * stays queued exactly where it was, and the operation drains to central
         * on reconnect with no witness attached. For the one operation kind
         * WP-29A queues that is not a degradation at all:
         * `INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE` is in
         * `DEVICE_OFFLINE_STALE_TOLERANT_OPERATION_KINDS`, so it is admissible
         * with `witness: NONE`. For a time-bounded kind it would be a refusal at
         * NO_TRUSTWORTHY_TIME_WITNESS, which is the designed, VISIBLE outcome —
         * and visible is the whole difference between this and the alternatives
         * the file comment refuses.
         *
         * It is an object rather than a null transport so that the degraded
         * state has a value and the caller has one code path. A nullable
         * transport is a nullable transport somebody eventually forgets to
         * check.
         */
        val NotConfigured: EdgeTransport = object : EdgeTransport {
            override fun submit(body: JsonObject): SentinelHttp.Answer = SentinelHttp.Answer(
                status = 0,
                body = null,
                text = "no site Edge is configured on this device: there is no channel that " +
                    "distributes an Edge address and a pinned TLS trust anchor to a handset",
            )
        }
    }
}
