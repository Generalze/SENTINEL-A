import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { z } from 'zod';
import type { Principal } from '../../common/security/principal';
import type { SiteScope } from '../identity/list-pagination';
import { mapFieldAssignment, mapFieldState } from './field.mapper';
import { FieldRepository, type TransitionResult } from './field.repository';
import type { FieldAssignmentAction, FieldAssignmentView, FieldOperativeStateView } from './field.types';

const CreateAssignmentInputSchema = z.object({
  site_id: z.string().min(1),
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
  site_id: z.string().min(1),
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

  async createAssignment(principal: Principal, siteScope: SiteScope, input: CreateAssignmentInput): Promise<FieldAssignmentView> {
    if (!siteAllowed(siteScope, input.site_id)) throw new ForbiddenException('Principal is not scoped to this site');
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

  async transitionAssignment(
    principal: Principal,
    siteScope: SiteScope,
    assignmentId: string,
    action: FieldAssignmentAction,
    input: AssignmentActionInput,
  ): Promise<FieldAssignmentView> {
    const result = await this.repository.transitionAssignment({
      organisationId: principal.organisation_id,
      assignmentId,
      actorUserId: principal.user.id,
      action,
      expectedStatus: input.expected_status,
      targetStatus: ACTION_TARGETS[action],
      idempotencyKey: input.idempotency_key,
      siteScope,
      actorMustBeAssignee: action !== 'cancel',
    });
    return this.mapTransitionResult(result);
  }

  async recordState(principal: Principal, siteScope: SiteScope, input: StateUpdateInput): Promise<FieldOperativeStateView> {
    if (!siteAllowed(siteScope, input.site_id)) throw new ForbiddenException('Principal is not scoped to this site');
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
    const result = await this.repository.recordState(stateInput);
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
