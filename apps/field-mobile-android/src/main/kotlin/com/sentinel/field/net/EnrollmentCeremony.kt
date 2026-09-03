package com.sentinel.field.net

import com.sentinel.field.security.ClientNonce
import com.sentinel.field.security.DeviceStatements
import com.sentinel.field.security.StrongBoxKeyManager
import java.util.Base64
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray

/**
 * ============================================================================
 * THE FIVE ENROLLMENT CROSSINGS, IN THE ONE ORDER THAT IS CORRECT.
 *
 * D26-04A — THE SERVER NONCE COMES BEFORE KEY GENERATION
 * ------------------------------------------------------
 *     sign in (human session)
 *      -> POST attestation-challenge      (presenting the bootstrap token)
 *      -> GENERATE the StrongBox key WITH THAT EXACT CHALLENGE   <- AFTER
 *      -> POST requests                   (public key + certificate chain)
 *      -> [an INDEPENDENT COMMANDER approves, out of band, in Command web]
 *      -> POST possession-challenge
 *      -> sign, POST possession
 *      -> POST commit
 *
 * The ordering is the security property, not a convenience. Android Key
 * Attestation is produced WHEN THE KEY IS GENERATED — `setAttestationChallenge`
 * puts the relying party's challenge inside the certificate precisely so the key
 * can be shown to have been created in response to a specific request. Generate
 * first and submit afterwards and the server can be handed a certificate minted
 * last year. This class exists so that ordering lives in ONE readable place
 * rather than being distributed across button handlers.
 *
 * WHAT THIS CLASS CANNOT DO, STRUCTURALLY
 * ---------------------------------------
 * It cannot approve anything. There is no approval route on the mobile ingress
 * and there is no code path to one — the word `approve` does not appear on the
 * server's `MobileEnrollmentController`, and it does not appear here either.
 * Approval happens in Command web, by a different human, against the exact
 * request fingerprint. If the phone could cause its own approval the ceremony
 * would be decorative.
 *
 * It also cannot claim anything about its own hardware. There is no
 * `key_storage` field on the request, no `attestation_outcome` and no `trust`.
 * The server DERIVES all three from its own verifier's verdict, and a client
 * that could claim `HARDWARE_BACKED` is a client that could claim `TRUSTED`.
 * `claimed_signature_profile` is sent because the contract requires the claim,
 * and it is exactly that — a claim the server equality-binds to the profile it
 * resolved for itself.
 * ============================================================================
 */
class EnrollmentCeremony(
    private val http: SentinelHttp,
    private val keys: StrongBoxKeyManager,
) {

    companion object {
        private const val INGRESS = "/api/v1/device-enrollment"

        /**
         * C18-R1 — the server's non-terminal answer on the request route.
         *
         * `409 DEVICE_ENROLLMENT_COMPLETION_UNKNOWN`: the server has recorded
         * that this exact submission spent this challenge, and cannot yet prove
         * what it produced. It is the ONE status on this surface that is neither
         * a success nor terminal, and the client's whole obligation on seeing it
         * is to keep its ceremony material and retry the identical body.
         */
        private const val COMPLETION_UNKNOWN = 409
    }

    /** Phase 0's answer, carried forward to key generation. */
    data class AttestationChallenge(
        val attestationChallengeId: String,
        /** Unpadded base64url. NOT a secret — a freshness value. */
        val challenge: String,
        val expiresAt: String,
    )

    /** Crossing A's answer. `requestFingerprint` is what a commander approves. */
    data class SubmittedRequest(
        val outcome: String,
        val enrollmentRequestId: String,
        val requestFingerprint: String,
        /** The SERVER's verdict, without its reason. Never the client's claim. */
        val attestationOutcome: String,
        /** EARNED, not claimed. `HARDWARE_BACKED` only when the verifier said so. */
        val keyStorage: String,
    )

    /** The end of the ceremony: a registered device, or a converged retry. */
    data class Committed(
        val outcome: String,
        val deviceId: String,
        val keyId: String?,
        val keyVersion: Int?,
        /** What the REGISTRY concluded. Nothing on the wire chose it. */
        val trust: String?,
    )

    // -----------------------------------------------------------------------
    // Phase 0 — the server nonce, BEFORE the phone has a key
    // -----------------------------------------------------------------------

    fun requestAttestationChallenge(
        sessionUserId: String,
        organisationId: String,
        siteId: String,
        intendedUserId: String,
        bootstrapToken: String,
    ): CeremonyStep<AttestationChallenge> {
        val answer = http.post(
            "$INGRESS/attestation-challenge",
            sessionUserId,
            buildJsonObject {
                put("organisation_id", organisationId)
                put("site_id", siteId)
                put("intended_user_id", intendedUserId)
                put("bootstrap_token", bootstrapToken)
            },
        )
        // C18-R3: PHASE 0 PROBES THE GRANT; IT DOES NOT SPEND IT.
        //
        // Shield is explicit that a correctly scoped presentation neither
        // consumes nor modifies the bootstrap grant — only a WRONG-CONTEXT
        // probe burns it. So a transport failure, a 5xx or an unreadable
        // success here says nothing authoritative about the grant, and
        // destroying it on that basis costs the operative a commander-issued
        // credential for no security gain. Only an AUTHORITATIVE refusal — the
        // server reached, and answering 4xx — is terminal.
        //
        // An unobserved challenge created just before a lost response confers
        // no device authority. It simply expires, and a later valid
        // presentation obtains another one.
        val body = answer.body
        if (!answer.ok || body == null) {
            val terminal = answer.status in 400..499
            return if (terminal) refusal(answer) else CeremonyStep.completionUnknown(answer.status, answer.text)
        }
        val issued =
            try {
                AttestationChallenge(
                    attestationChallengeId = body.text("attestation_challenge_id"),
                    challenge = body.text("challenge"),
                    expiresAt = body.text("expires_at"),
                )
            } catch (unreadable: Exception) {
                // Same reasoning as C18-R1A: a success we cannot read is not a
                // refusal, and the grant is not spent by a phase-0 probe.
                return CeremonyStep.completionUnknown(answer.status, "unreadable challenge body")
            }
        return CeremonyStep.ok(issued)
    }

    // -----------------------------------------------------------------------
    // Key generation — AFTER phase 0, against THAT challenge
    // -----------------------------------------------------------------------

    /**
     * Generates the StrongBox key against the exact bytes the server issued.
     *
     * The challenge arrives as unpadded base64url and is decoded here to the
     * bytes that go into the certificate. Attesting over the base64url TEXT
     * rather than the decoded bytes would produce a chain the server refuses
     * `ATTESTATION_CHALLENGE_MISMATCH`, and the server's own acceptance suite
     * does `Buffer.from(challengeValue, 'base64url')`, so this must too.
     */
    fun generateKey(challenge: AttestationChallenge): CeremonyStep<StrongBoxKeyManager.GenerateOutcome.Generated> {
        val challengeBytes = try {
            Base64.getUrlDecoder().decode(challenge.challenge)
        } catch (error: IllegalArgumentException) {
            return CeremonyStep.refused(0, "the server challenge is not unpadded base64url")
        }
        return when (val outcome = keys.generate(challengeBytes)) {
            is StrongBoxKeyManager.GenerateOutcome.Generated -> CeremonyStep.ok(outcome)
            is StrongBoxKeyManager.GenerateOutcome.DeviceUnsupported -> CeremonyStep.deviceUnsupported(outcome.detail)
            is StrongBoxKeyManager.GenerateOutcome.Failed -> CeremonyStep.refused(0, outcome.detail)
        }
    }

    // -----------------------------------------------------------------------
    // Crossing A — the public key and the attestation evidence
    // -----------------------------------------------------------------------

    /**
     * ONE SUBMISSION, AND THREE KINDS OF ANSWER (C18-R1).
     *
     * This is the only crossing whose failure can be AMBIGUOUS, because it is
     * the only one that CREATES something on the server. Everything before it is
     * a read or a local key generation; everything after it names an enrollment
     * request that already exists and can simply be asked about again. So this is
     * where the distinction between "it did not happen" and "it may have
     * happened" has to be drawn, and it is drawn here rather than in the caller
     * so that no button handler can get it wrong.
     *
     * See [classifySubmission] for the rule and its reasoning.
     */
    fun submitEnrollmentRequest(
        sessionUserId: String,
        organisationId: String,
        siteId: String,
        intendedUserId: String,
        bootstrapToken: String,
        attestationChallengeId: String,
        generated: StrongBoxKeyManager.GenerateOutcome.Generated,
        custody: String = "PERSONAL",
        custodyRegimeId: String? = null,
    ): CeremonyStep<SubmittedRequest> {
        val answer = http.post(
            "$INGRESS/requests",
            sessionUserId,
            buildJsonObject {
                put("organisation_id", organisationId)
                put("site_id", siteId)
                put("intended_user_id", intendedUserId)
                put("bootstrap_token", bootstrapToken)
                put("attestation_challenge_id", attestationChallengeId)
                put("public_key", generated.publicKey)
                put("claimed_signature_profile", DeviceStatements.SIGNATURE_PROFILE)
                put("custody", custody)
                // CONTROLLED_SHARED only, and required there (C15-08/C16-01).
                if (custodyRegimeId == null) put("custody_regime_id", JsonNull)
                else put("custody_regime_id", custodyRegimeId)
                putJsonArray("certificate_chain") {
                    for (certificate in generated.certificateChainBase64) add(certificate)
                }
            },
        )
        return classifySubmission(answer)
    }

    /**
     * ============================================================================
     * C18-R1 — WHAT THE CLIENT MAY CONCLUDE FROM ONE ANSWER TO CROSSING A.
     * ============================================================================
     *
     *     a parsed 2xx                        -> OK. The server named the
     *                                            request; the outcome field says
     *                                            REQUESTED or CONVERGED, and
     *                                            both are authoritative.
     *
     *     4xx other than 409                  -> REFUSED, and TERMINAL. The
     *                                            server evaluated this
     *                                            submission and declined it: a
     *                                            dead grant, a foreign tenant, a
     *                                            changed key under a spent
     *                                            challenge, a malformed body.
     *                                            Nothing was created and nothing
     *                                            will be.
     *
     *     409                                 -> COMPLETION UNKNOWN, said by the
     *                                            server itself.
     *
     *     status 0                            -> COMPLETION UNKNOWN. `SentinelHttp`
     *                                            reports EVERY transport failure
     *                                            as 0, and that bucket contains
     *                                            the case this correction is
     *                                            about: the POST arrived, the
     *                                            server committed, and the
     *                                            RESPONSE was lost. From here a
     *                                            lost request and a lost response
     *                                            are the same event, so the
     *                                            client must assume the one that
     *                                            costs it nothing to assume.
     *
     *     5xx                                 -> COMPLETION UNKNOWN. A server
     *                                            that failed mid-request may have
     *                                            failed AFTER creating the
     *                                            enrollment request — that exact
     *                                            window is what the server's own
     *                                            incomplete-receipt state
     *                                            describes.
     *
     *     2xx whose body did not parse        -> COMPLETION UNKNOWN. The server
     *                                            evidently succeeded at
     *                                            something; this client simply
     *                                            cannot read what.
     *
     * THE ASYMMETRY IS DELIBERATE AND IT IS THE WHOLE CORRECTION. Treating an
     * unknown as a refusal destroys recovery material and makes a SUCCEEDED
     * ceremony unfinishable. Treating an unknown as a retryable unknown costs one
     * repeated request, which the server answers from recorded state and which
     * creates no second request and no second artifact. The two mistakes are not
     * comparable, so the fallthrough is UNKNOWN, not REFUSED.
     */
    private fun classifySubmission(answer: SentinelHttp.Answer): CeremonyStep<SubmittedRequest> {
        val body = answer.body
        if (answer.ok && body != null) {
            // C18-R1A: THE EXTRACTION IS THE PART THAT CAN FAIL.
            //
            // This method already claimed that an unreadable 2xx becomes
            // COMPLETION_UNKNOWN, and it did not: `text()` throws when a field
            // is missing, null or the wrong shape, so a malformed success
            // ESCAPED the classifier entirely rather than being classified.
            // That is the same defect C18-R1 corrected one layer out — an
            // answer whose completion cannot be proved was being turned into
            // something other than "unknown".
            //
            // Only the extraction is wrapped. A `catch` around the whole branch
            // would swallow failures from the caller too, and the point here is
            // to classify ONE thing: whether this response can be read as the
            // outcome it claims to be.
            val submitted =
                try {
                    SubmittedRequest(
                        outcome = body.text("outcome"),
                        enrollmentRequestId = body.text("enrollment_request_id"),
                        requestFingerprint = body.text("request_fingerprint"),
                        attestationOutcome = body.text("attestation_outcome"),
                        keyStorage = body.text("key_storage"),
                    )
                } catch (unreadable: Exception) {
                    // The server may well have committed. We cannot tell from
                    // here, so this is UNKNOWN and the ceremony material is kept.
                    return CeremonyStep.completionUnknown(answer.status, "unreadable success body")
                }
            return CeremonyStep.ok(submitted)
        }
        val terminal = answer.status in 400..499 && answer.status != COMPLETION_UNKNOWN
        if (terminal) return refusal(answer)
        return CeremonyStep.completionUnknown(answer.status, answer.text)
    }

    // -----------------------------------------------------------------------
    // Crossing B — possession, AFTER an independent commander has approved
    // -----------------------------------------------------------------------

    data class PossessionChallenge(val challengeId: String, val nonce: String, val expiresAt: String)

    /**
     * Shield refuses this unless the ceremony has ALREADY been approved by an
     * independent human, so a refusal here most often means "nobody has approved
     * it yet", and the app must not present that as a device fault.
     */
    fun requestPossessionChallenge(
        sessionUserId: String,
        organisationId: String,
        enrollmentRequestId: String,
    ): CeremonyStep<PossessionChallenge> {
        val answer = http.post(
            "$INGRESS/possession-challenge",
            sessionUserId,
            buildJsonObject {
                put("organisation_id", organisationId)
                put("enrollment_request_id", enrollmentRequestId)
            },
        )
        val body = answer.body
        if (!answer.ok || body == null) return refusal(answer)
        return CeremonyStep.ok(
            PossessionChallenge(
                challengeId = body.text("challenge_id"),
                nonce = body.text("nonce"),
                expiresAt = body.text("expires_at"),
            ),
        )
    }

    /**
     * THE FIRST CRYPTOGRAPHIC ACT OF THE CEREMONY, AND IT COMMITS NOTHING.
     *
     * `verified: false` is a real recorded server verdict rather than a refusal
     * (C15-03) — a refusal would mean the check did not happen — so this returns
     * the outcome as data. The commit gate re-validates everything under lock
     * regardless.
     */
    fun submitPossession(
        sessionUserId: String,
        organisationId: String,
        enrollmentRequestId: String,
        requestFingerprint: String,
        challenge: PossessionChallenge,
    ): CeremonyStep<String> {
        val statement = DeviceStatements.possessionStatement(
            challengeId = challenge.challengeId,
            enrollmentRequestId = enrollmentRequestId,
            enrollmentRequestFingerprint = requestFingerprint,
            nonce = challenge.nonce,
            publicKeyThumbprint = keys.readPublicKeyThumbprint(),
        )
        val signature = keys.signCanonicalStatement(statement)
        val answer = http.post(
            "$INGRESS/possession",
            sessionUserId,
            buildJsonObject {
                put("organisation_id", organisationId)
                put("enrollment_request_id", enrollmentRequestId)
                put("challenge_id", challenge.challengeId)
                put(
                    "response",
                    buildJsonObject {
                        put("schema_version", 1)
                        put("challenge_id", challenge.challengeId)
                        put("enrollment_request_id", enrollmentRequestId)
                        put("claimed_signature_profile", DeviceStatements.SIGNATURE_PROFILE)
                        put("signature", signature)
                        // CLIENT TELEMETRY. Freshness is judged on the SERVER's
                        // verification instant, never on this.
                        put("answered_at", ClientNonce.nowIso())
                    },
                )
            },
        )
        val body = answer.body
        if (!answer.ok || body == null) return refusal(answer)
        return CeremonyStep.ok(body.text("outcome"))
    }

    // -----------------------------------------------------------------------
    // The commit — ONE transaction, in Shield, or nothing
    // -----------------------------------------------------------------------

    fun commit(
        sessionUserId: String,
        organisationId: String,
        enrollmentRequestId: String,
        challengeId: String,
    ): CeremonyStep<Committed> {
        val answer = http.post(
            "$INGRESS/commit",
            sessionUserId,
            buildJsonObject {
                put("organisation_id", organisationId)
                put("enrollment_request_id", enrollmentRequestId)
                put("challenge_id", challengeId)
            },
        )
        val body = answer.body
        if (!answer.ok || body == null) return refusal(answer)
        return CeremonyStep.ok(
            Committed(
                outcome = body.text("outcome"),
                deviceId = body.text("device_id"),
                keyId = body.textOrNull("key_id"),
                keyVersion = body.intOrNull("key_version"),
                trust = body.textOrNull("trust"),
            ),
        )
    }

    private fun <T> refusal(answer: SentinelHttp.Answer): CeremonyStep<T> =
        CeremonyStep.refused(answer.status, answer.text)
}

// ---------------------------------------------------------------------------
// Small, explicit readers.
//
// Every value this client goes on to SIGN is read out by NAME, here and in
// `DeviceStatements`, and never by re-serialising a parsed response. That is the
// difference between "the device signed the challenge the server issued" and
// "the device signed whatever JSON arrived".
// ---------------------------------------------------------------------------

internal fun JsonObject.textOrNull(key: String): String? {
    val element = this[key] ?: return null
    if (element is JsonNull) return null
    return (element as? JsonPrimitive)?.contentOrNull
}

internal fun JsonObject.text(key: String): String =
    textOrNull(key) ?: throw IllegalStateException("the server response is missing '$key'")

internal fun JsonObject.intOrNull(key: String): Int? = textOrNull(key)?.toIntOrNull()

internal fun JsonObject.int(key: String): Int =
    intOrNull(key) ?: throw IllegalStateException("the server response is missing integer '$key'")
