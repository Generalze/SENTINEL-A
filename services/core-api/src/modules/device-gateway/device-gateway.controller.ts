import { randomUUID } from 'node:crypto';
import { BadRequestException, Body, ConflictException, Controller, ForbiddenException, Inject, Param, Post, Req } from '@nestjs/common';
import { z } from 'zod';
import { requirePrincipal, type RequestWithPrincipal } from '../../common/security/principal';
import { Public } from '../../common/security/requires-action.decorator';
import { DeviceContextService } from './device-context.service';
import type { DeviceGatewayOperationKind } from './device-gateway.envelope';
import { DeviceGatewayService } from './device-gateway.service';
import type { DeviceGatewayOperationResult } from './device-gateway.types';

/**
 * ============================================================================
 * WP-25 — THE FIRST DEVICE-FACING BOUNDARY IN SENTINEL.
 *
 * WP-23 froze the contracts. WP-24 made them authoritative server state and
 * deliberately shipped NO device-facing route — `shield.module.ts` still
 * carries the prohibition and names this work package as the one that lifts
 * it. THIS FILE IS THAT LIFT, and it is lifted only for a surface that
 * consumes real device authentication.
 *
 * WHAT AUTHENTICATES A CALLER HERE
 * --------------------------------
 * A FRESH, HARDWARE-SIGNED `DeviceRequestProof`. Nothing else. There is no
 * device bearer token, no device session cookie, no authenticated socket, no
 * per-connection exemption and no header this controller reads as a
 * credential.
 *
 *     A context id presented WITHOUT a matching possession proof is refused
 *     POSSESSION_NOT_PROVEN (D25-01).
 *
 * `AuthenticatedDeviceContext` is a SCOPE STATEMENT, not a credential: holding
 * one says what a device WOULD be entitled to IF the hardware were present. So
 * `context_id` may be logged, echoed and even leaked without conferring
 * anything, and every effect-causing request carries its own proof, bound to
 * the context, the key version, the purpose, the payload digest and a one-shot
 * nonce.
 *
 * WHY THE DEVICE ROUTES ARE `@Public()`
 * -------------------------------------
 * `@Public()` in this codebase means exactly one thing: the global DevAuthGuard
 * attaches no HUMAN SESSION principal. It does NOT mean unauthenticated. These
 * routes are authenticated by hardware possession, which is a stronger
 * statement than the `x-dev-user-id` header the human routes carry — and
 * marking them otherwise would require the device to also present a human
 * session credential, which is the bearer-token shortcut D25-01 forbids. The
 * HUMAN half of the invariant is not skipped: it is re-established from CURRENT
 * server state on every request, and `evaluateDeviceOperationPrincipals`
 * refuses when either principal is missing.
 *
 * The establishment REQUEST route is the opposite and is deliberately NOT
 * `@Public()`: it is the one call in this module made by a person, and the
 * ceremony rests on that independent human session existing.
 *
 * WHAT THIS BOUNDARY REFUSES
 * --------------------------
 *   * a context id with no proof, or with a proof that does not verify;
 *   * a proof replayed verbatim — the nonce is one-shot;
 *   * a proof minted for another purpose, another payload or another operation;
 *   * a body that names an `operation_kind` other than the route's (D25-11);
 *   * any attempt to choose the downstream domain idempotency key (D25-16B);
 *   * `start`, `complete`, `cancel` and reassignment — there is no route for
 *     them and nothing in this module constructs those actions (D25-10);
 *   * anything at all, once the device is revoked, the key is rotated, the
 *     context is closed, the actor's authority is withdrawn or the site
 *     entitlement is lost — re-checked under lock, per request (D25-04A).
 *
 * THE REFUSAL BOUNDARY IS NOT AN ENUMERATION ORACLE (D25-13)
 * ----------------------------------------------------------
 * A foreign-tenant device, a nonexistent device, a foreign context, a
 * nonexistent context and a device not usable by this actor or site all shape
 * the SAME external refusal. The precise reason and the trace id go to the
 * internal audit, where an operator can read them and an attacker cannot. No
 * raw signature, private key, session credential or nonce ever enters an audit
 * payload.
 *
 * REST ONLY (D25-10). There is no device WebSocket authentication path in
 * WP-25, and existing server-to-client realtime is untouched. When WP-26/27 add
 * device realtime ingress the rule is unchanged: socket authenticated is not
 * message authorized, and every effect-causing device message carries its own
 * fresh signed proof.
 *
 * THIS IS NOT PROOF C (D25-07/D25-09). A gateway that authenticates a process
 * holding a P-256 key is not a physical device with a hardware-backed key
 * speaking through a real client. This boundary makes Proof C possible; it
 * does not claim it.
 * ============================================================================
 */

/**
 * THE THREE EXTERNAL ANSWERS, AS CONSTANTS.
 *
 * They are constants rather than inline strings so that the D25-13 property —
 * every refusal, whatever caused it, is byte-identical — is a fact about one
 * value rather than a fact about seven string literals staying in agreement.
 * The global exception filter turns each into `{ error, trace_id }`.
 */
const EXTERNAL_REFUSED = 'DEVICE_REQUEST_REFUSED';
const EXTERNAL_MALFORMED = 'DEVICE_REQUEST_MALFORMED';
const EXTERNAL_CONFLICT = 'DEVICE_REQUEST_CONFLICT';

const EstablishmentRequestSchema = z
  .object({
    organisation_id: z.string().min(1).max(256),
    device_id: z.string().min(1).max(256),
    site_id: z.string().min(1).max(256),
  })
  .strict();

const CompleteEstablishmentSchema = z
  .object({
    establishment_id: z.string().min(1).max(256),
    proof: z.unknown(),
  })
  .passthrough();

@Controller('api/v1/device-gateway')
export class DeviceGatewayController {
  constructor(
    @Inject(DeviceContextService) private readonly contexts: DeviceContextService,
    @Inject(DeviceGatewayService) private readonly gateway: DeviceGatewayService,
  ) {}

  /**
   * STEP ONE of D25-03A. A PERSON asks for an establishment challenge for a
   * registered device at a site.
   *
   * Not `@Public()`: the global session guard runs, so a request with no human
   * session is rejected before this handler is reached. That is the whole point
   * — the challenge is not a secret, and what makes stealing it useless is that
   * obtaining one required a live session and using one requires the key.
   *
   * There is deliberately no `@RequiresAction`. The authority this ceremony
   * needs is not a single §62 action: it is "this person currently holds SOME
   * gateway-operable capability at THIS site", checked against the site in the
   * request by `DeviceContextService`. Pinning the route to one of the three
   * actions would either admit a person who cannot perform the operation they
   * intend or refuse a person who can. Issuing a challenge settles nothing
   * either way: every operation re-asks for its OWN action, under lock.
   */
  @Post('contexts/establishment')
  async requestEstablishment(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<unknown> {
    const principal = requirePrincipal(req);
    const parsed = EstablishmentRequestSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(EXTERNAL_MALFORMED);

    const outcome = await this.contexts.requestEstablishment(principal, {
      organisationId: parsed.data.organisation_id,
      deviceId: parsed.data.device_id,
      siteId: parsed.data.site_id,
      traceId: traceIdOf(req),
    });
    // One refusal for every reason (D25-13). The internal audit already holds
    // the precise one.
    if (outcome.outcome === 'REFUSED') throw new ForbiddenException(EXTERNAL_REFUSED);
    return { challenge: outcome.challenge };
  }

  /**
   * STEP TWO of D25-03A. The DEVICE answers the challenge and a context is
   * issued, or nothing is.
   *
   * The response carries the ISSUED context, assembled from the committed row.
   * The IN-MEMORY CANDIDATE the evaluators judged is never returned, never
   * persisted and accepted nowhere else — on any refusal this route returns no
   * context at all, and no context row exists.
   */
  @Post('contexts')
  @Public()
  async completeEstablishment(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<unknown> {
    const parsed = CompleteEstablishmentSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(EXTERNAL_MALFORMED);

    const outcome = await this.contexts.completeEstablishment({
      establishmentId: parsed.data.establishment_id,
      proof: parsed.data.proof,
      traceId: traceIdOf(req),
    });
    if (outcome.outcome === 'REFUSED') throw new ForbiddenException(EXTERNAL_REFUSED);
    return { context: outcome.context };
  }

  /**
   * A. Field state update.
   *
   * The target is the operative themselves, so there is no target id in the
   * path: it is resolved from the persisted context. A route that took one
   * would be a route through which a device could name whose state it is
   * writing.
   */
  @Post('operations/field-state')
  @Public()
  async fieldState(@Req() req: RequestWithPrincipal, @Body() body: unknown): Promise<unknown> {
    return this.run(req, 'FIELD_STATE_UPDATE', null, body);
  }

  /** B. Assignment ACCEPT. */
  @Post('operations/assignments/:id/accept')
  @Public()
  async acceptAssignment(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<unknown> {
    return this.run(req, 'ASSIGNMENT_ACCEPT', id, body);
  }

  /**
   * B. Assignment DECLINE.
   *
   * ACCEPT and DECLINE are the ONLY assignment transitions with a route here.
   * `start`, `complete`, `cancel` and reassignment are not merely ungated —
   * they have no route, no operation kind and no action string anywhere in this
   * module (D25-10).
   */
  @Post('operations/assignments/:id/decline')
  @Public()
  async declineAssignment(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<unknown> {
    return this.run(req, 'ASSIGNMENT_DECLINE', id, body);
  }

  /**
   * C. Incident Field Message acknowledgement, DELIVERED -> ACKNOWLEDGED.
   *
   * §76's first transition a DEVICE can cause, and it obeys the same rule as
   * everything else: an acknowledgement that arrives without possession is not
   * a weaker acknowledgement, it is not an acknowledgement (D25-06). Delivery
   * evidence stays server-owned and the device's claim about when it saw
   * something remains telemetry — there is nowhere in the signed payload to put
   * one.
   */
  @Post('operations/messages/:id/acknowledge')
  @Public()
  async acknowledgeMessage(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() body: unknown): Promise<unknown> {
    return this.run(req, 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE', id, body);
  }

  /**
   * The ONE mapping from an internal outcome to an external answer.
   *
   * It is one method rather than four so the D25-13 boundary cannot be got
   * subtly wrong on one route: every refusal, whatever caused it, leaves here
   * as the same 403 body, and no branch can grow a reason field.
   */
  private async run(
    req: RequestWithPrincipal,
    kind: DeviceGatewayOperationKind,
    targetId: string | null,
    body: unknown,
  ): Promise<unknown> {
    const result: DeviceGatewayOperationResult = await this.gateway.execute(kind, {
      proof: readProof(body),
      body,
      targetId,
      traceId: traceIdOf(req),
    });
    if (result.outcome === 'REFUSED') throw new ForbiddenException(EXTERNAL_REFUSED);
    if (result.outcome === 'CONFLICT') throw new ConflictException(EXTERNAL_CONFLICT);
    return {
      outcome: result.outcome,
      operation_kind: result.operationKind,
      target_type: result.targetType,
      target_id: result.targetId,
      /** Safe to echo: a context id authorises nothing (D25-13). */
      context_id: result.contextId,
      result: result.view,
    };
  }
}

/** The proof, carved off the body before anything else looks at it. */
function readProof(body: unknown): unknown {
  if (typeof body !== 'object' || body === null) return undefined;
  return (body as { proof?: unknown }).proof;
}

/**
 * The request trace, or a fresh one.
 *
 * It is non-semantic and is never an authorisation input. It is generated here
 * rather than accepted from the caller when absent, so an audit row always has
 * a correlation handle even for a request that arrived with nothing.
 */
function traceIdOf(req: RequestWithPrincipal): string {
  return req.traceId ?? randomUUID();
}
