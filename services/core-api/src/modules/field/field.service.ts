import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import type { FieldAssignmentStatus } from '@sentinel/contracts';
import { z } from 'zod';
import { isSafeSubjectToken, SUBJECT_TOKEN_RULE } from '../../common/messaging/subject-token';
import type { Principal } from '../../common/security/principal';
import type { SiteScope } from '../identity/list-pagination';
import { mapFieldAssignment, mapFieldState } from './field.mapper';
import { FieldRepository, type TransitionResult } from './field.repository';
import type { FieldAssignmentAction, FieldAssignmentView, FieldOperativeStateView } from './field.types';

/**
 * WP-17/D3: every Field mutation names the site it writes to, and that site id
 * becomes a NATS subject token on the delivery path. Reject an unsafe id here,
 * at the API boundary, so it is never persisted — the publisher's identical
 * check is then an unreachable backstop rather than the only guard.
 */
const subjectSafeSiteId = z.string().min(1).refine(isSafeSubjectToken, { message: `site_id ${SUBJECT_TOKEN_RULE}` });

const CreateAssignmentInputSchema = z.object({
  site_id: subjectSafeSiteId,
  incident_id: z.string().uuid().nullable().optional(),
  assignee_user_id: z.string().min(1),
  assignment_type: z.string().min(1).max(128),
  priority: z.enum(['SEV1', 'SEV2', 'SEV3', 'SEV4', 'SEV5']),
  need_to_know_summary: z.string().min(1).max(8192),
  expires_at: z.string().datetime().nullable().optional(),
  idempotency_key: z.string().min(1).max(256),
});
export type CreateAssignmentInput = z.infer<typeof CreateAssignmentInputSchema>;

const AssignmentActionInputSchema = z.object({
  expected_status: z.enum(['REQUESTED', 'ACCEPTED', 'DECLINED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', 'EXPIRED']),
  idempotency_key: z.string().min(1).max(256),
});
export type AssignmentActionInput = z.infer<typeof AssignmentActionInputSchema>;

const StateUpdateInputSchema = z.object({
  site_id: subjectSafeSiteId,
  device_id: z.string().min(1).max(256),
  state: z.enum(['AVAILABLE', 'PATROL', 'OBSERVING', 'RESPONDING', 'ON_SCENE', 'NEED_SUPPORT', 'COMPROMISED', 'OFF_DUTY']),
  location: z.record(z.unknown()).nullable().optional(),
  source_at: z.string().datetime(),
  freshness_ms: z.number().int().nonnegative(),
  idempotency_key: z.string().min(1).max(256),
  trace_id: z.string().min(1).max(256),
});
export type StateUpdateInput = z.infer<typeof StateUpdateInputSchema>;

const ACTION_TARGETS: Readonly<Record<FieldAssignmentAction, AssignmentActionInput['expected_status']>> = {
  accept: 'ACCEPTED',
  decline: 'DECLINED',
  start: 'IN_PROGRESS',
  complete: 'COMPLETED',
  cancel: 'CANCELLED',
};

function parseOrBadRequest<T>(schema: z.ZodSchema<T>, raw: unknown): T {
  const parsed = schema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException({ message: parsed.error.issues.map((issue) => issue.message) });
  return parsed.data;
}

function siteAllowed(siteScope: SiteScope, siteId: string): boolean {
  return siteScope.orgWide || siteScope.siteIds.includes(siteId);
}

/**
 * WP-25/D25-16: forwards the composition transaction ONLY when there is one.
 *
 * Passing an explicit `undefined` would be semantically identical, and that is
 * not the standard this seam is held to: an existing human caller must reach
 * the repository with EXACTLY the arguments it always did, so "existing
 * callers are unchanged" is true at the call boundary and not merely true in
 * effect. It is also what keeps the seam invisible to every spec that asserts
 * on the old call shape.
 */
function txArg(tx?: Prisma.TransactionClient): [] | [Prisma.TransactionClient] {
  return tx === undefined ? [] : [tx];
}

@Injectable()
export class FieldService {
  constructor(@Inject(FieldRepository) private readonly repository: FieldRepository) {}

  parseCreateAssignment(raw: unknown): CreateAssignmentInput {
    return parseOrBadRequest(CreateAssignmentInputSchema, raw);
  }

  parseAssignmentAction(raw: unknown): AssignmentActionInput {
    return parseOrBadRequest(AssignmentActionInputSchema, raw);
  }

  parseStateUpdate(raw: unknown): StateUpdateInput {
    return parseOrBadRequest(StateUpdateInputSchema, raw);
  }

  /**
   * WP-17A/C7-07: the site a Field write names must exist in the caller's own
   * organisation. A nonexistent site and another tenant's real site produce the
   * identical 404 — the caller must not be able to use this endpoint to learn
   * that some id is a real site somewhere else in the platform.
   */
  private async assertSiteInOrganisation(organisationId: string, siteId: string, tx?: Prisma.TransactionClient): Promise<void> {
    if (!(await this.repository.siteExistsInOrganisation(organisationId, siteId, ...txArg(tx)))) {
      throw new NotFoundException('Site not found');
    }
  }

  async createAssignment(principal: Principal, siteScope: SiteScope, input: CreateAssignmentInput): Promise<FieldAssignmentView> {
    if (!siteAllowed(siteScope, input.site_id)) throw new ForbiddenException('Principal is not scoped to this site');
    await this.assertSiteInOrganisation(principal.organisation_id, input.site_id);
    if (!(await this.repository.assigneeCanReceive(principal.organisation_id, input.site_id, input.assignee_user_id))) {
      throw new BadRequestException('Assignee is not a field operative at this site');
    }
    if (input.incident_id && !(await this.repository.incidentExists(principal.organisation_id, input.site_id, input.incident_id))) {
      throw new BadRequestException('Incident is not in the caller organisation/site scope');
    }
    const result = await this.repository.createAssignment({
      organisationId: principal.organisation_id,
      siteId: input.site_id,
      incidentId: input.incident_id ?? null,
      assigneeUserId: input.assignee_user_id,
      assignmentType: input.assignment_type,
      priority: input.priority,
      needToKnowSummary: input.need_to_know_summary,
      expiresAt: input.expires_at ? new Date(input.expires_at) : null,
      idempotencyKey: input.idempotency_key,
      actorUserId: principal.user.id,
    });
    return mapFieldAssignment(result.assignment);
  }

  async listAssignments(principal: Principal, siteScope: SiteScope): Promise<FieldAssignmentView[]> {
    const rows = await this.repository.listAssignments(principal.organisation_id, siteScope);
    return rows.map(mapFieldAssignment);
  }

  /**
   * WP-17/D5: the refetch path for an operative. A socket only signals that
   * something in scope changed; the authoritative record is read here, where
   * organisation, site, and assignee are all re-checked server-side.
   */
  async listOwnAssignments(principal: Principal, siteScope: SiteScope): Promise<FieldAssignmentView[]> {
    const rows = await this.repository.listAssignments(principal.organisation_id, siteScope, principal.user.id);
    return rows.map(mapFieldAssignment);
  }

  /**
   * WP-17/D5: one own assignment. A non-assignee gets 404 rather than 403 —
   * the same "never reveal existence" rule the AccessGuard applies to a
   * cross-organisation match, since the assignee set of an assignment is
   * itself need-to-know.
   */
  async getOwnAssignment(principal: Principal, siteScope: SiteScope, assignmentId: string): Promise<FieldAssignmentView> {
    const row = await this.repository.getAssignment(principal.organisation_id, assignmentId, siteScope);
    if (!row || row.assigneeUserId !== principal.user.id) throw new NotFoundException('Assignment not found');
    return mapFieldAssignment(row);
  }

  /** WP-17/D5: one assignment for a dispatcher/commander, org- and site-scoped. */
  async getAssignment(principal: Principal, siteScope: SiteScope, assignmentId: string): Promise<FieldAssignmentView> {
    const row = await this.repository.getAssignment(principal.organisation_id, assignmentId, siteScope);
    if (!row) throw new NotFoundException('Assignment not found');
    return mapFieldAssignment(row);
  }

  /**
   * WP-20/B10-02 idempotency recovery probe — pure evidence lookup, no mutable
   * eligibility re-evaluation, actor-scoped per the C8-05 lesson.
   *
   * The offline replay executor asks THIS domain — the owner of the assignment
   * status machine — whether a downstream idempotency identity it already
   * derived has committed. It deliberately does not call `transitionAssignment`
   * to find out: that path re-evaluates CURRENT mutable eligibility (assignee,
   * expected-status CAS, the transition table) before it ever reaches the
   * idempotency check, so drift since the first attempt could report an effect
   * that DID commit as a rejection — false history.
   *
   * `status` is the ORIGINAL intended post-transition status, taken from this
   * service's own ACTION_TARGETS, NOT the assignment's current status. The
   * evidence proves that this action, by this actor, under this key, landed;
   * what it landed was ACTION_TARGETS[action]. Reading live status instead
   * would put a value the first attempt never produced into a receipt.
   */
  async probeTransitionEvidence(
    principal: Principal,
    assignmentId: string,
    action: FieldAssignmentAction,
    idempotencyKey: string,
  ): Promise<{ committed: false } | { committed: true; status: FieldAssignmentStatus }> {
    const committed = await this.repository.findTransitionEvidence(principal.organisation_id, assignmentId, action, principal.user.id, idempotencyKey);
    return committed ? { committed: true, status: ACTION_TARGETS[action] } : { committed: false };
  }

  /**
   * WP-25/D25-02 idempotency recovery probe for state updates — the third
   * member of the WP-20/B10-02 probe family, with the identical argument.
   *
   * `recordState` re-checks site scope and site existence and then WRITES when
   * the key is unknown, so it cannot be used to ask whether a downstream
   * identity already committed: asking would answer by causing the effect. The
   * evidence row can be read without touching anything.
   *
   * Actor-scoped and device-scoped, matching the state-update idempotency
   * identity exactly. `principal.organisation_id` binds the tenant and
   * `principal.user.id` binds the operative, so no caller can probe another
   * tenant's or another operative's evidence through this method.
   */
  async probeStateEvidence(principal: Principal, input: { siteId: string; deviceId: string; idempotencyKey: string }): Promise<boolean> {
    return this.repository.findStateEvidence(principal.organisation_id, input.siteId, principal.user.id, input.deviceId, input.idempotencyKey);
  }

  /**
   * WP-25/D25-16: `tx` is an internal composition seam, not a public API
   * concern. An orchestrator that must commit this transition together with
   * its own rows hands its transaction in; every existing human caller passes
   * nothing and gets exactly the behaviour it always had. The eligibility
   * rules, the expected-status CAS, the transition table and the `FOR UPDATE`
   * fence all stay where they are — this service, and the repository beneath
   * it, remain the only implementation of assignment transition semantics.
   */
  async transitionAssignment(
    principal: Principal,
    siteScope: SiteScope,
    assignmentId: string,
    action: FieldAssignmentAction,
    input: AssignmentActionInput,
    tx?: Prisma.TransactionClient,
  ): Promise<FieldAssignmentView> {
    const result = await this.repository.transitionAssignment(
      {
        organisationId: principal.organisation_id,
        assignmentId,
        actorUserId: principal.user.id,
        action,
        expectedStatus: input.expected_status,
        targetStatus: ACTION_TARGETS[action],
        idempotencyKey: input.idempotency_key,
        siteScope,
        actorMustBeAssignee: action !== 'cancel',
      },
      ...txArg(tx),
    );
    return this.mapTransitionResult(result);
  }

  /**
   * WP-25/D25-16: `tx` is an internal composition seam, not a public API
   * concern. It is threaded to BOTH the site-existence check and the write,
   * deliberately: `assertSiteInOrganisation` runs before the write
   * transaction, so on an orchestrated path the two must share one transaction
   * or the check-to-commit gap is a real race. Human callers pass no `tx` and
   * keep the existing ordering unchanged, and Field remains the only
   * implementation of state-update semantics.
   */
  async recordState(principal: Principal, siteScope: SiteScope, input: StateUpdateInput, tx?: Prisma.TransactionClient): Promise<FieldOperativeStateView> {
    if (!siteAllowed(siteScope, input.site_id)) throw new ForbiddenException('Principal is not scoped to this site');
    await this.assertSiteInOrganisation(principal.organisation_id, input.site_id, tx);
    const sourceAt = new Date(input.source_at);
    const receivedAt = new Date();
    const authoritativeFreshnessMs = Math.max(0, receivedAt.getTime() - sourceAt.getTime());
    const stateInput = {
      organisationId: principal.organisation_id,
      siteId: input.site_id,
      actorUserId: principal.user.id,
      deviceId: input.device_id,
      state: input.state,
      location: input.location === null || input.location === undefined ? null : (input.location as Prisma.JsonObject),
      sourceAt,
      receivedAt,
      clientFreshnessMs: input.freshness_ms,
      authoritativeFreshnessMs,
      traceId: input.trace_id,
      idempotencyKey: input.idempotency_key,
    };
    this.repository.validateStateContract(stateInput);
    const result = await this.repository.recordState(stateInput, ...txArg(tx));
    return mapFieldState(result.state);
  }

  async getCurrentState(principal: Principal, siteScope: SiteScope, userId: string): Promise<FieldOperativeStateView> {
    if (userId !== principal.user.id && !principal.hasAction('field.state.read')) throw new ForbiddenException('Cannot read another operative state');
    const row = await this.repository.getCurrentState(principal.organisation_id, userId, siteScope);
    if (!row) throw new NotFoundException('Field state not found');
    return mapFieldState(row);
  }

  private mapTransitionResult(result: TransitionResult): FieldAssignmentView {
    if (result.kind === 'not_found') throw new NotFoundException('Assignment not found');
    if (result.kind === 'forbidden') throw new ForbiddenException('Only the assignee can perform this assignment action');
    if (result.kind === 'conflict') throw new ConflictException(`Assignment status is ${result.currentStatus}`);
    return mapFieldAssignment(result.assignment);
  }
}
