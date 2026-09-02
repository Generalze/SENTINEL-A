import { randomUUID } from 'node:crypto';
import { BadRequestException, Body, Controller, ForbiddenException, Inject, Post, Req } from '@nestjs/common';
import { z } from 'zod';
import { DeviceCustodySchema, DeviceSignatureProfileSchema } from '@sentinel/contracts';
import { requirePrincipal, type RequestWithPrincipal } from '../../common/security/principal';
import {
  MAX_ATTESTATION_CERTIFICATE_BASE64_LENGTH,
  MAX_ATTESTATION_CHAIN_LENGTH,
} from './device-enrollment-ingress.constants';
import { DeviceEnrollmentIngressService } from './device-enrollment-ingress.service';

/**
 * ============================================================================
 * WP-26/D26-09 — THE MOBILE HALF OF THE ENROLLMENT BRIDGE.
 *
 * THE FIRST PRE-REGISTRATION DEVICE SURFACE IN SENTINEL.
 *
 * WP-25's gateway is the surface for a device that is ALREADY REGISTERED: it
 * begins by resolving a persisted context and a registry key. A phone holding a
 * key that is registered nowhere has neither, and bending the gateway to accept
 * it would mean adding an unauthenticated path to the one surface whose entire
 * purpose is that there is no such path. So this is a separate, narrower
 * controller, reachable only for the pre-registration ceremony.
 *
 * WHAT AUTHENTICATES A CALLER HERE — TWO FACTS, AND NEITHER IS THE DEVICE
 * ----------------------------------------------------------------------
 *     THE SESSION          the INTENDED USER's ordinary authenticated human
 *                          principal, attached by the global guard chain. The
 *                          same one every other authenticated route in this
 *                          codebase carries.
 *
 *     THE GRANT SECRET     one-shot, short-lived, bound by a commander to one
 *                          organisation, one site and one intended user, and
 *                          BURNED if presented anywhere else (D24-03a).
 *
 * The DEVICE contributes evidence — a public key and an attestation chain — and
 * no authority whatsoever. It is not authenticated here and it cannot be: it has
 * no registered key, which is the reason this ceremony exists rather than a gap
 * in it. What substitutes for device authentication is the second human
 * approving the exact request fingerprint, and that happens in Command web,
 * through `CommandEnrollmentController`, by a different person.
 *
 * NOT `@Public()`. NOT EVER. (C17-01, inherited.)
 *
 * A mobile client is exactly the context in which "the device is right here,
 * surely that is enough" becomes tempting. It is not enough, and this controller
 * is where saying so costs something: every route below reads
 * `requirePrincipal`, the service equality-binds that principal's organisation
 * and user id to the grant's before ANY Shield call, and
 * `test/device-enrollment-ingress-boundary.architecture.spec.ts` asserts the
 * absence of `@Public()` as a source fact — because a behavioural test can prove
 * that the routes it calls require a session, and cannot prove that the sixth
 * route somebody adds next quarter does.
 *
 * THERE IS NO APPROVAL ROUTE HERE, AND THERE IS NO CODE PATH TO ONE.
 *
 * If the phone could cause its own approval the ceremony would be decorative.
 * The word `approve` does not appear on this controller, this controller's
 * service calls no approval method, and the Command-side action refuses a Field
 * operative's principal even on its own route.
 *
 * THE EXTERNAL ANSWER FOR EVERY REFUSAL IS IDENTICAL (D25-13's discipline).
 *
 * A dead grant, a grant for another tenant, a spent attestation challenge, an
 * expired one, a chain that does not verify, a session that is not the intended
 * user — all 403, all the same body. The precise reason goes to the internal
 * reason log. The one thing a caller learns is whether the SERVER's attestation
 * verdict was positive, which the client needs in order to tell its operative
 * that the device is not supported; it learns no detail of WHY.
 *
 * REST ONLY (D25-10, still binding). There is no device WebSocket path here.
 *
 * THIS IS NOT PROOF C (D26-08). A server that can enrol a physical device is not
 * a physical device invoking a real DEVICE_ACTION Whisper and being gated end to
 * end. WP-26 makes Proof C possible; it does not claim it.
 * ============================================================================
 */

/**
 * THE THREE EXTERNAL ANSWERS, AS CONSTANTS.
 *
 * Constants rather than inline strings so that "every refusal, whatever caused
 * it, is byte-identical" is a fact about one value rather than a fact about
 * seven string literals staying in agreement. The global exception filter turns
 * each into `{ error, trace_id }`.
 */
const EXTERNAL_REFUSED = 'DEVICE_ENROLLMENT_REFUSED';
const EXTERNAL_MALFORMED = 'DEVICE_ENROLLMENT_MALFORMED';

/** Bounded, so an unbounded string cannot reach a digest or a database column. */
const boundedId = z.string().min(1).max(256);

/**
 * `.strict()` ON EVERY SCHEMA, AT A CRYPTOGRAPHIC BOUNDARY (C17-06).
 *
 * A top-level key that is no part of what the ceremony defines is REFUSED here
 * rather than dropped quietly. It is not a bypass today — nothing reads those
 * keys — and it is exactly the debt a later refactor turns into one, the day
 * somebody adds `const storage = body.key_storage` to a handler that already
 * parsed successfully.
 *
 * NOTE THE ABSENCES, WHICH ARE THE POINT:
 *   * there is no `key_storage` field. D26-02: `HARDWARE_BACKED` is EARNED from
 *     the server's own verdict, never claimed. A client that can claim
 *     `HARDWARE_BACKED` is a client that can claim TRUSTED.
 *   * there is no `attestation_outcome`, `trust`, `attestation_reference` or
 *     `signature_profile` that SELECTS anything. The client never supplies the
 *     verdict, only the evidence (D26-04).
 *   * there is no `organisation_id` on the ceremony routes that already name an
 *     enrollment request: the tenant is the session's (C17-02).
 */
const AttestationChallengeRequestSchema = z
  .object({
    organisation_id: boundedId,
    site_id: boundedId,
    intended_user_id: boundedId,
    /** The one-time secret, as issued. Digested by Shield and never stored raw. */
    bootstrap_token: z.string().min(1).max(1024),
  })
  .strict();

const EnrollmentRequestSchema = z
  .object({
    organisation_id: boundedId,
    site_id: boundedId,
    intended_user_id: boundedId,
    bootstrap_token: z.string().min(1).max(1024),
    /** The D26-04A challenge the key was GENERATED against. */
    attestation_challenge_id: boundedId,
    /** Canonical base64url uncompressed SEC1 point (C15-02). */
    public_key: z.string().min(1).max(256),
    /** C15-01: A CLAIM. Shield equality-binds it to its own resolved profile. */
    claimed_signature_profile: DeviceSignatureProfileSchema,
    custody: DeviceCustodySchema,
    /** CONTROLLED_SHARED only, and required there (C15-08/C16-01). */
    custody_regime_id: boundedId.nullable(),
    /**
     * The Android Key Attestation chain, base64 DER, LEAF FIRST.
     *
     * Bounded in both dimensions. An unauthenticated-device surface must not be
     * a way to make the server perform unbounded signature verification, and a
     * length check is a cheaper refusal than a DER parser discovering the same
     * thing slowly.
     */
    certificate_chain: z
      .array(z.string().min(1).max(MAX_ATTESTATION_CERTIFICATE_BASE64_LENGTH))
      .min(1)
      .max(MAX_ATTESTATION_CHAIN_LENGTH),
  })
  .strict();

const PossessionChallengeRequestSchema = z
  .object({ organisation_id: boundedId, enrollment_request_id: boundedId })
  .strict();

const PossessionRequestSchema = z
  .object({
    organisation_id: boundedId,
    enrollment_request_id: boundedId,
    challenge_id: boundedId,
    /**
     * The frozen `DevicePossessionResponse`. Left as `unknown` and handed to
     * Shield, which parses it against the contract schema — the ONE parse, in
     * the module that owns the rule. A second schema here would be a second
     * opinion about a signed structure.
     */
    response: z.unknown(),
  })
  .strict();

const CommitRequestSchema = z
  .object({ organisation_id: boundedId, enrollment_request_id: boundedId, challenge_id: boundedId })
  .strict();

@Controller('api/v1/device-enrollment')
export class MobileEnrollmentController {
  constructor(@Inject(DeviceEnrollmentIngressService) private readonly ingress: DeviceEnrollmentIngressService) {}

  /**
   * D26-04A, PHASE 0. The server nonce, issued BEFORE the phone generates a key.
   *
   * This is the correction that matters. Android Key Attestation is produced at
   * key generation; a server that hands out nothing first has no way to tell a
   * certificate minted seconds ago from one minted last year.
   */
  @Post('attestation-challenge')
  async attestationChallenge(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<unknown> {
    const principal = requirePrincipal(req);
    const parsed = AttestationChallengeRequestSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(EXTERNAL_MALFORMED);

    const outcome = await this.ingress.issueAttestationChallenge(principal, {
      organisationId: parsed.data.organisation_id,
      siteId: parsed.data.site_id,
      intendedUserId: parsed.data.intended_user_id,
      bootstrapToken: parsed.data.bootstrap_token,
      traceId: traceIdOf(req),
    });
    if (outcome.outcome === 'REFUSED') throw new ForbiddenException(EXTERNAL_REFUSED);
    return {
      attestation_challenge_id: outcome.attestationChallengeId,
      // NOT A SECRET. The phone must embed this in the key it is about to
      // generate; withholding it would make Key Attestation unusable.
      challenge: outcome.challengeValue,
      expires_at: outcome.expiresAt.toISOString(),
    };
  }

  /**
   * D26-01, CROSSING A. The public key and the attestation chain.
   *
   * It creates a REQUEST, never a device. Nothing here is registered, trusted or
   * approved; what comes back is an id and the fingerprint an independent
   * commander will be asked to approve.
   */
  @Post('requests')
  async createRequest(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<unknown> {
    const principal = requirePrincipal(req);
    const parsed = EnrollmentRequestSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(EXTERNAL_MALFORMED);

    const outcome = await this.ingress.submitEnrollmentRequest(principal, {
      organisationId: parsed.data.organisation_id,
      siteId: parsed.data.site_id,
      intendedUserId: parsed.data.intended_user_id,
      bootstrapToken: parsed.data.bootstrap_token,
      attestationChallengeId: parsed.data.attestation_challenge_id,
      publicKey: parsed.data.public_key,
      claimedSignatureProfile: parsed.data.claimed_signature_profile,
      custody: parsed.data.custody,
      custodyRegimeId: parsed.data.custody_regime_id,
      certificateChainBase64: parsed.data.certificate_chain,
      traceId: traceIdOf(req),
    });
    if (outcome.outcome === 'REFUSED') throw new ForbiddenException(EXTERNAL_REFUSED);
    return {
      outcome: outcome.outcome,
      enrollment_request_id: outcome.enrollmentRequestId,
      request_fingerprint: outcome.requestFingerprint,
      // The server's verdict, not the client's claim, and deliberately without
      // the verifier's precise reason — that stays internal.
      attestation_outcome: outcome.attestationOutcome,
      key_storage: outcome.keyStorage,
    };
  }

  /**
   * D26-01, before crossing B. A fresh possession challenge.
   *
   * Shield refuses this unless the ceremony has already been APPROVED by an
   * independent human: a device that could begin proving possession of a key
   * nobody approved would have got one step for free.
   */
  @Post('possession-challenge')
  async possessionChallenge(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<unknown> {
    const principal = requirePrincipal(req);
    const parsed = PossessionChallengeRequestSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(EXTERNAL_MALFORMED);

    const outcome = await this.ingress.issuePossessionChallenge(principal, {
      organisationId: parsed.data.organisation_id,
      enrollmentRequestId: parsed.data.enrollment_request_id,
      traceId: traceIdOf(req),
    });
    if (outcome.outcome !== 'ISSUED') throw new ForbiddenException(EXTERNAL_REFUSED);
    return { challenge_id: outcome.challengeId, nonce: outcome.nonce, expires_at: outcome.expiresAt.toISOString() };
  }

  /**
   * D26-01, CROSSING B. The StrongBox signature over the server's challenge.
   *
   * THE FIRST CRYPTOGRAPHIC ACT OF THE CEREMONY, AND IT STILL COMMITS NOTHING.
   *
   * C15-03: `verified: false` is a real recorded server verdict, not a refusal,
   * and it is returned as its own outcome — a refusal would mean the check did
   * not happen. The commit gate re-validates everything under lock regardless.
   */
  @Post('possession')
  async possession(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<unknown> {
    const principal = requirePrincipal(req);
    const parsed = PossessionRequestSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(EXTERNAL_MALFORMED);

    const outcome = await this.ingress.verifyPossession(principal, {
      organisationId: parsed.data.organisation_id,
      enrollmentRequestId: parsed.data.enrollment_request_id,
      challengeId: parsed.data.challenge_id,
      response: parsed.data.response,
      traceId: traceIdOf(req),
    });
    if (outcome.outcome === 'REFUSED') throw new ForbiddenException(EXTERNAL_REFUSED);
    return { outcome: outcome.outcome, verification_id: outcome.verificationId };
  }

  /**
   * D26-01, the end of the ceremony. ONE transaction, in Shield, or nothing.
   *
   * Every authority-bearing row is re-read under `SELECT ... FOR UPDATE` and
   * re-validated inside that transaction, and `evaluateDeviceEnrollmentCommit`
   * owns every admissibility rule. This route contributes the authenticated
   * human and nothing else — which is the third of C14-02's four facts, and the
   * only one a network boundary can supply.
   */
  @Post('commit')
  async commit(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<unknown> {
    const principal = requirePrincipal(req);
    const parsed = CommitRequestSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(EXTERNAL_MALFORMED);

    const outcome = await this.ingress.commitEnrollment(principal, {
      organisationId: parsed.data.organisation_id,
      enrollmentRequestId: parsed.data.enrollment_request_id,
      challengeId: parsed.data.challenge_id,
      traceId: traceIdOf(req),
    });
    if (outcome.outcome === 'REFUSED') throw new ForbiddenException(EXTERNAL_REFUSED);
    if (outcome.outcome === 'CONVERGED') return { outcome: 'CONVERGED', device_id: outcome.deviceId };
    return {
      outcome: 'COMMITTED',
      device_id: outcome.deviceId,
      key_id: outcome.keyId,
      key_version: outcome.keyVersion,
      // The trust the registry CONCLUDED. D23-03/C14-05 decide it from the
      // storage and the attestation standing; nothing on this surface chose it.
      trust: outcome.trust,
    };
  }
}

/**
 * The request trace, or a fresh one.
 *
 * Non-semantic, and never an authorisation input. Generated here rather than
 * accepted from the caller when absent, so an internal refusal line always has a
 * correlation handle even for a request that arrived with nothing.
 */
function traceIdOf(req: RequestWithPrincipal): string {
  return req.traceId ?? randomUUID();
}
