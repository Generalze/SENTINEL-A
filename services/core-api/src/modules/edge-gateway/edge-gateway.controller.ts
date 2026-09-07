import {
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  ForbiddenException,
  Inject,
  Post,
  Req,
  ServiceUnavailableException,
} from '@nestjs/common';
import { DeviceEdgeReceiptSchema } from '@sentinel/contracts';
import { z } from 'zod';
import type { RequestWithTraceId } from '../../common/http-types';
import { Public } from '../../common/security/requires-action.decorator';
import { CentralEdgeTrustedTimeVerifier } from '../edge-trusted-time/central-edge-trusted-time.verifier';
import { EdgeAuthenticationService } from './edge-authentication.service';
import { EdgeEvidenceStandingService } from './edge-evidence-standing.service';
import { EdgeReceiptObservationService } from './edge-receipt-observation.service';
import { EdgeWitnessService } from './edge-witness.service';

/**
 * WP-29B EDGE-B / M3B §7-§8 — THE EDGE -> CENTRAL INGRESS.
 *
 * THE TWO-LAYER RULE, ENFORCED HERE BECAUSE HERE IS WHERE IT CAN BE BROKEN
 * -----------------------------------------------------------------------
 * `EdgeGatewayModule` deliberately shipped no controller until one existed that
 * gets this order right:
 *
 *     1. AUTHENTICATE THE CALLER   (EdgeAuthenticationService)
 *     2. only then, verify whatever receipt it carries (EdgeWitnessService)
 *
 * A VERIFIED RECEIPT IS NOT AN AUTHENTICATED CALLER. Reversing these, or
 * letting step 2 supply an identity step 1 did not establish, is the single
 * defect this module exists to make impossible: any party could then replay a
 * genuine receipt captured from the wire and be treated as the Edge that
 * signed it.
 *
 * `@Public()` is correct and is not a weakening. This caller is an Edge, not a
 * human; it authenticates with a signed request proof over the exact body
 * digest, verified against the registry. The global session guard would refuse
 * it for having no human session, which is the wrong question to ask a machine.
 *
 * WHAT THIS ROUTE DOES AND DOES NOT DO
 * ------------------------------------
 * It records that CENTRAL VERIFIED AN EDGE WITNESS. It does NOT apply the
 * device's operation, and it does not authorise it. Those still belong to the
 * existing offline replay path, which asks its own questions of the human and
 * the device -- see the note at the end of this file, which is the reason the
 * domain-submission step is absent rather than forgotten.
 */
const EdgeWitnessSubmissionSchema = z
  .object({
    /** The device-signed envelope, forwarded untouched. Central re-parses it. */
    envelope: z.unknown(),
    /** The device's payload, forwarded untouched. */
    payload: z.unknown(),
    /** The Edge's own statement about the operation it witnessed. */
    receipt: z.unknown(),
    /**
     * §7's evidence, or explicit `null`.
     *
     * NULLABLE AND REQUIRED, not optional. An Edge with no anchor yet is
     * behaving correctly and must be able to say so; what it must not be able
     * to do is omit the field and have central treat the absence as
     * unremarkable. `null` is an assertion; a missing key is an ambiguity.
     */
    trusted_time_evidence: z.unknown().nullable(),
  })
  .strict();

@Controller('api/v1/edge-gateway')
export class EdgeGatewayController {
  constructor(
    @Inject(EdgeAuthenticationService) private readonly authentication: EdgeAuthenticationService,
    @Inject(EdgeWitnessService) private readonly witness: EdgeWitnessService,
    @Inject(CentralEdgeTrustedTimeVerifier) private readonly trustedTime: CentralEdgeTrustedTimeVerifier,
    @Inject(EdgeReceiptObservationService) private readonly observations: EdgeReceiptObservationService,
    @Inject(EdgeEvidenceStandingService) private readonly standing: EdgeEvidenceStandingService,
  ) {}

  /**
   * An Edge forwards one device-signed operation together with its own witness.
   *
   * The response is deliberately coarse (D25-13): an Edge learns whether its
   * witness was recorded, and nothing about why a refusal happened. The
   * operator learns the reason from `edge_security_events`.
   */
  @Public()
  @Post('witness')
  async submitWitness(@Req() req: RequestWithTraceId, @Body() body: unknown): Promise<unknown> {
    const parsed = EdgeWitnessSubmissionSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException({ error: 'EDGE_REQUEST_MALFORMED' });

    const traceId = req.traceId ?? '';
    const proof = (req.headers['x-edge-proof'] as string | undefined) ?? null;
    if (proof === null) throw new ForbiddenException({ error: 'EDGE_REQUEST_REFUSED' });

    let decodedProof: unknown;
    try {
      decodedProof = JSON.parse(Buffer.from(proof, 'base64url').toString('utf8'));
    } catch {
      throw new ForbiddenException({ error: 'EDGE_REQUEST_REFUSED' });
    }

    // -- LAYER 1: WHO IS CALLING -------------------------------------------
    // The body digest is bound by the proof, so the exact bytes below cannot be
    // swapped for others after signing. `rawBody` is the bytes as received, not
    // a re-serialisation of the parsed object: re-encoding would compute a
    // digest over what WE produced rather than over what they SENT.
    const authenticated = await this.authentication.authenticate({
      proof: decodedProof,
      method: 'POST',
      route: '/api/v1/edge-gateway/witness',
      // NO FALLBACK TO A RE-ENCODED BODY. If the raw bytes are unavailable the
      // request is refused below on digest mismatch, which is the correct
      // outcome: an application built without `rawBody` cannot verify an Edge
      // signature, and pretending otherwise would verify our own serialisation.
      body: req.rawBody ?? '',
      traceId,
    });
    if (authenticated.outcome === 'REFUSED') throw new ForbiddenException({ error: 'EDGE_REQUEST_REFUSED' });
    const context = authenticated.context;

    // -- LAYER 2: WHAT DID THEY WITNESS ------------------------------------
    const admission = await this.witness.admitReceipt(context, parsed.data.receipt, traceId);
    if (admission.outcome === 'REFUSED') throw new ForbiddenException({ error: 'EDGE_REQUEST_REFUSED' });

    // -- §7: IS THE TIME ON THAT WITNESS ANYTHING CENTRAL CAN STAND BEHIND --
    // A refusal here is NOT a request failure. An Edge that has never held an
    // anchor still witnessed the operation, and the observation is worth
    // recording with an honest NULL time. What must never happen is the Edge's
    // unverified claim being recorded as though central had established it.
    const receipt = DeviceEdgeReceiptSchema.safeParse(parsed.data.receipt);
    const claimedTime = receipt.success ? receipt.data.edge_trusted_time : null;
    const timeVerification = this.trustedTime.verify(context, parsed.data.trusted_time_evidence, claimedTime);

    // -- §8: THE CENTRAL-SIDE RECORD PROOF D READS -------------------------
    const offlineOperationId = readClaimedOperationId(parsed.data.envelope);
    const recorded = await this.observations.record({
      witness: admission.witness,
      verifiedTime: timeVerification.ok ? timeVerification.evidence : null,
      offlineOperationId,
      traceId,
    });

    // §5: the same evidence identity carrying changed semantics is a CONFLICT,
    // never a convergence. Refusing is the only safe answer -- accepting would
    // let one signed receipt be re-bound to a different operation.
    if (recorded === 'CONFLICT') throw new ConflictException({ error: 'EDGE_EVIDENCE_CONFLICT' });
    // A write that failed must not be reported as a held witness.
    if (recorded === 'NOT_RECORDED') throw new ServiceUnavailableException({ error: 'EDGE_EVIDENCE_NOT_RECORDED' });

    // -- §6: THE CURRENT AUTHORITATIVE STANDING ----------------------------
    // Read from the DEVICE's replay record, never from the evidence just
    // written. An Edge that delivered evidence learns where the operation
    // actually stands; it does not learn a standing its own delivery created.
    const standing = await this.standing.standingOf(context.organisationId, offlineOperationId);

    return {
      evidence: recorded,
      trusted_time: timeVerification.ok ? 'VERIFIED' : 'UNVERIFIED',
      // The Edge maps this into its own queue vocabulary. EVIDENCE_RECORDED is
      // the honest answer while the Field device has not reconnected, and the
      // Edge queue's own transitions forbid it becoming a terminal state.
      standing,
    };
  }
}

/**
 * The device's own operation id, read from the forwarded envelope.
 *
 * AN UNTRUSTED READ, used only to correlate the observation with an operation
 * that may arrive later through the device's own reconnect. It is not an
 * authorisation input and nothing is decided from it; an unreadable envelope
 * yields `null`, and the observation is recorded with an honest gap rather than
 * refused. Recording a verified witness we cannot correlate is strictly better
 * than discarding evidence because a correlation hint was missing.
 */
function readClaimedOperationId(envelope: unknown): string | null {
  if (typeof envelope !== 'object' || envelope === null) return null;
  const claimed = (envelope as Record<string, unknown>)['offline_operation_id'];
  return typeof claimed === 'string' && claimed.length > 0 ? claimed : null;
}

/**
 * WHY THE DOMAIN OPERATION IS NOT SUBMITTED HERE.
 *
 * M3B §9 asks this path to end by submitting to the existing central offline
 * replay ingress. It cannot, and the reason is a security property rather than
 * a missing wire.
 *
 * `evaluateDeviceOperationPrincipals` refuses `USER_NOT_AUTHENTICATED` before
 * it asks anything else, and `DeviceOfflineIngressService` derives that fact
 * from the authenticated HUMAN principal on the request (C17-01). WP-29A chose
 * that deliberately: "a device reconnecting on its own, holding a perfectly
 * good key and a perfectly good queue, is not sufficient."
 *
 * An Edge forwarding on behalf of a device has no live human session, and
 * cannot manufacture one. The three ways to close the gap all change something
 * load-bearing:
 *
 *   - let Edge-forwarded work satisfy `userAuthenticated`, which retires
 *     C17-01's rule for exactly the path it was written for;
 *   - carry a device-signed assertion of the human's session across the
 *     outage, which is a new credential with a new lifetime and no revocation
 *     story;
 *   - keep the split that already exists -- the Edge delivers EVIDENCE, and the
 *     operation replays through the human-authenticated path when the device
 *     reconnects.
 *
 * The third needs no ruling to be safe, and it is what this route does. It is
 * also what M3B §3 already says an observation means: "CENTRAL VERIFIED THIS
 * EDGE WITNESS", not "CENTRAL AUTHORISED THE OPERATION". Choosing between the
 * first two is a CTO decision and is reported as one.
 */
