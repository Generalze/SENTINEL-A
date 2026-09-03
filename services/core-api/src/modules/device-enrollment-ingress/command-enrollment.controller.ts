import { randomUUID } from 'node:crypto';
import { BadRequestException, Body, Controller, ForbiddenException, Get, Inject, Param, Post, Query, Req } from '@nestjs/common';
import { z } from 'zod';
import { requirePrincipal, type RequestWithPrincipal } from '../../common/security/principal';
import { RequiresAction } from '../../common/security/requires-action.decorator';
import { DeviceEnrollmentService } from '../shield/device-enrollment.service';
import {
  ACTION_DEVICE_ENROLLMENT_APPROVE,
  ACTION_DEVICE_ENROLLMENT_ISSUE,
  ACTION_DEVICE_REGISTRY_READ,
} from '../shield/shield.constants';

/**
 * ============================================================================
 * WP-26/D26-09 — THE COMMAND HALF OF THE ENROLLMENT BRIDGE.
 *
 * WHY THIS CONTROLLER EXISTS, AND WHY IT IS NOT IN SHIELD
 * -------------------------------------------------------
 * Shield has NO HTTP controller at all (D24-13), which means that until this
 * file there was no route for commander bootstrap issuance and no route for
 * commander approval either — not just none for the phone. Shield keeps that
 * property: the ingress owns transport for BOTH sides while the registry stays
 * internal, and every handler below calls an exported Shield service.
 *
 * THE SEPARATION THIS CONTROLLER IS HERE TO PRESERVE
 * --------------------------------------------------
 *
 *     issuer  !=  approver  !=  intended user
 *
 * and a human still approves THE EXACT REQUEST FINGERPRINT.
 *
 * D24-03 enforces all of it inside Shield, twice: once at the approval surface,
 * where it gives the approver a clear refusal, and again inside the commit
 * transaction against LOCKED rows, which is the one that holds when nothing can
 * move underneath it. This controller adds the §62 action gate and the tenant,
 * and takes no security decision of its own.
 *
 * THE MOBILE SURFACE CANNOT REACH ANY OF THIS.
 *
 * Not because the routes are hidden — they are not — but because
 * `device.enrollment.approve` and `device.enrollment.issue` are commander
 * actions, and a Field operative's principal holds neither. An operative
 * presenting a perfect body to the approval route below is refused by
 * `checkDeviceAuthority` inside Shield, and would still be refused by
 * `INTENDED_USER_MAY_NOT_APPROVE` if they somehow held the action. There are two
 * independent reasons, and the Crucible asserts both.
 *
 * `@RequiresAction` IS DEFENCE IN DEPTH, NOT THE GATE.
 *
 * The global `AccessGuard` refuses an unauthorised caller before the handler
 * runs, which keeps a §62 action visible on the route where a reviewer reads it.
 * The real gate is Shield's own `checkDeviceAuthority`, which additionally
 * resolves SITE scope against the row being acted on — something a route
 * decorator cannot do, because the site of an enrollment request is not in the
 * request body.
 *
 * THE RAW ATTESTATION CHAIN IS NOT ON THIS SURFACE EITHER (D26-04B).
 *
 * The pending queue carries the attestation OUTCOME — which is part of what the
 * commander is approving — and the parsed facts Shield holds. It cannot carry
 * the chain: no read path in Shield can load it, and the ingress repository's
 * only reader deliberately does not select the column.
 * ============================================================================
 */

const EXTERNAL_REFUSED = 'DEVICE_ENROLLMENT_REFUSED';
const EXTERNAL_MALFORMED = 'DEVICE_ENROLLMENT_MALFORMED';

const boundedId = z.string().min(1).max(256);

const IssueGrantSchema = z
  .object({ organisation_id: boundedId, site_id: boundedId, intended_user_id: boundedId })
  .strict();

const RevokeGrantSchema = z.object({ organisation_id: boundedId }).strict();

/**
 * C14-02, AS A REQUIRED FIELD.
 *
 * `expected_request_fingerprint` is not optional and never will be. An approver
 * approves a specific set of bytes — this key, this custody, this attestation
 * evidence evaluated at this instant — and must not be able to be made to
 * approve a different request that merely shares an id. Shield compares it
 * against the fingerprint RECOMPUTED from the stored request, so a fingerprint
 * that was true when the queue was rendered and false by the time the commander
 * clicked is a refusal rather than a surprise.
 */
const ApproveSchema = z
  .object({ organisation_id: boundedId, expected_request_fingerprint: z.string().min(1).max(256) })
  .strict();

const PendingQuerySchema = z.object({ organisation_id: boundedId }).strict();

@Controller('api/v1/device-enrollment/command')
export class CommandEnrollmentController {
  constructor(@Inject(DeviceEnrollmentService) private readonly enrollment: DeviceEnrollmentService) {}

  /**
   * D24-03a. One bootstrap grant, and its secret returned EXACTLY ONCE.
   *
   * The token is in transit only: Shield persists a SHA-256 digest and nothing
   * else, there is no read path that can produce it a second time, and a lost
   * token is a re-issued grant rather than a recovered one. It is echoed here
   * because this is the only moment it exists outside the caller's hand.
   *
   * A GRANT CREATES ZERO DEVICE AUTHORITY (D24-03). It is provenance for one
   * ceremony, bound to one organisation, one site, one intended user and one
   * issuing human, and on its own it can enrol nothing at all.
   */
  @Post('bootstrap-grants')
  @RequiresAction(ACTION_DEVICE_ENROLLMENT_ISSUE)
  async issueGrant(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<unknown> {
    const principal = requirePrincipal(req);
    const parsed = IssueGrantSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(EXTERNAL_MALFORMED);

    const outcome = await this.enrollment.issueBootstrapGrant(principal, {
      organisationId: parsed.data.organisation_id,
      siteId: parsed.data.site_id,
      intendedUserId: parsed.data.intended_user_id,
      traceId: traceIdOf(req),
    });
    if (outcome.outcome === 'REFUSED') throw new ForbiddenException(EXTERNAL_REFUSED);
    return {
      grant_id: outcome.grantId,
      /** In transit only. Nothing on the server holds this value. */
      bootstrap_token: outcome.token,
      site_id: outcome.siteId,
      intended_user_id: outcome.intendedUserId,
      expires_at: outcome.expiresAt.toISOString(),
    };
  }

  /** D24-03a: a grant is revocable before use. Revocation is a burn, not a delete. */
  @Post('bootstrap-grants/:id/revoke')
  @RequiresAction(ACTION_DEVICE_ENROLLMENT_ISSUE)
  async revokeGrant(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<unknown> {
    const principal = requirePrincipal(req);
    const parsed = RevokeGrantSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(EXTERNAL_MALFORMED);

    const outcome = await this.enrollment.revokeBootstrapGrant(principal, {
      organisationId: parsed.data.organisation_id,
      grantId: id,
      traceId: traceIdOf(req),
    });
    if (outcome.outcome === 'REFUSED') throw new ForbiddenException(EXTERNAL_REFUSED);
    return { grant_id: outcome.grantId, outcome: 'REVOKED' };
  }

  /**
   * The approver's queue.
   *
   * C16-06's projection applies: genuine organisation-wide authority sees the
   * tenant, a site-scoped commander sees only their sites, and a principal
   * holding `device.registry.read` at no site sees an empty list rather than
   * everything. Holding one site is not a way to enumerate another.
   */
  @Get('pending')
  @RequiresAction(ACTION_DEVICE_REGISTRY_READ)
  async pending(@Req() req: RequestWithPrincipal, @Query() query: unknown): Promise<unknown> {
    const principal = requirePrincipal(req);
    const parsed = PendingQuerySchema.safeParse(query);
    if (!parsed.success) throw new BadRequestException(EXTERNAL_MALFORMED);

    const outcome = await this.enrollment.listPendingEnrollments(principal, { organisationId: parsed.data.organisation_id });
    if (outcome.outcome === 'REFUSED') throw new ForbiddenException(EXTERNAL_REFUSED);
    return {
      requests: outcome.requests.map((request) => ({
        enrollment_request_id: request.enrollmentRequestId,
        site_id: request.siteId,
        intended_user_id: request.intendedUserId,
        custody: request.custody,
        custody_regime_id: request.custodyRegimeId,
        key_storage: request.keyStorage,
        public_key_thumbprint: request.publicKeyThumbprint,
        /** The exact value the approver must name back. See `ApproveSchema`. */
        request_fingerprint: request.requestFingerprint,
        attestation_outcome: request.attestationOutcome,
        state: request.state,
        requested_at: request.requestedAt.toISOString(),
      })),
    };
  }

  /**
   * THE INDEPENDENT HUMAN APPROVAL. The one crossing the device never makes.
   *
   * Shield checks, in this order: that the caller holds
   * `device.enrollment.approve` AT THE REQUEST'S SITE; that the request is still
   * awaiting a decision; that the approver is NOT the grant's issuer; that the
   * approver is NOT the intended user; and that the fingerprint they named is
   * the one recomputed from the stored request. Every one of those is re-checked
   * inside the commit transaction against locked rows.
   */
  @Post('enrollment-requests/:id/approve')
  @RequiresAction(ACTION_DEVICE_ENROLLMENT_APPROVE)
  async approve(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<unknown> {
    const principal = requirePrincipal(req);
    const parsed = ApproveSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(EXTERNAL_MALFORMED);

    const outcome = await this.enrollment.approveEnrollmentRequest(principal, {
      organisationId: parsed.data.organisation_id,
      enrollmentRequestId: id,
      expectedRequestFingerprint: parsed.data.expected_request_fingerprint,
      traceId: traceIdOf(req),
    });
    if (outcome.outcome === 'REFUSED') throw new ForbiddenException(EXTERNAL_REFUSED);
    return {
      outcome: 'APPROVED',
      approval_id: outcome.approvalId,
      approved_request_fingerprint: outcome.approvedRequestFingerprint,
    };
  }
}

/** The request trace, or a fresh one. Non-semantic; never an authorisation input. */
function traceIdOf(req: RequestWithPrincipal): string {
  return req.traceId ?? randomUUID();
}
