import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type FieldAssignment, type FieldOperativeCurrentState } from '@prisma/client';
import { canTransitionFieldAssignmentStatus, FieldAssignmentSchema, FieldOperativeStateUpdateSchema, type FieldAssignmentStatus } from '@sentinel/contracts';
import { PrismaService } from '../../prisma/prisma.service';
import type { FieldAssignmentAction, SiteScope } from './field.types';

export function isUniqueViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

function siteScopeWhere(siteScope: SiteScope): Prisma.FieldAssignmentWhereInput {
  return siteScope.orgWide ? {} : { siteId: { in: siteScope.siteIds } };
}

function stateSiteScopeWhere(siteScope: SiteScope): Prisma.FieldOperativeCurrentStateWhereInput {
  return siteScope.orgWide ? {} : { siteId: { in: siteScope.siteIds } };
}

function auditPayload(value: Prisma.InputJsonValue): Prisma.InputJsonValue {
  return value;
}

interface CreateAssignmentInput {
  organisationId: string;
  siteId: string;
  incidentId: string | null;
  assigneeUserId: string;
  assignmentType: string;
  priority: string;
  needToKnowSummary: string;
  expiresAt: Date | null;
  idempotencyKey: string;
  actorUserId: string;
}

interface TransitionInput {
  organisationId: string;
  assignmentId: string;
  actorUserId: string;
  action: FieldAssignmentAction;
  expectedStatus: FieldAssignmentStatus;
  targetStatus: FieldAssignmentStatus;
  idempotencyKey: string;
  siteScope: SiteScope;
  actorMustBeAssignee: boolean;
}

interface StateInput {
  organisationId: string;
  siteId: string;
  actorUserId: string;
  deviceId: string;
  state: string;
  location: Prisma.JsonObject | null;
  sourceAt: Date;
  receivedAt: Date;
  clientFreshnessMs: number;
  authoritativeFreshnessMs: number;
  traceId: string;
  idempotencyKey: string;
}

export type TransitionResult =
  | { kind: 'updated'; assignment: FieldAssignment }
  | { kind: 'duplicate' | 'noop'; assignment: FieldAssignment }
  | { kind: 'not_found' }
  | { kind: 'forbidden' }
  | { kind: 'conflict'; currentStatus: string };

@Injectable()
export class FieldRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  async assigneeCanReceive(organisationId: string, siteId: string, userId: string): Promise<boolean> {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, organisationId, roles: { some: { role: 'field.operative', siteId } } },
      select: { id: true },
    });
    return user !== null;
  }

  async incidentExists(organisationId: string, siteId: string, incidentId: string): Promise<boolean> {
    const incident = await this.prisma.incident.findFirst({ where: { id: incidentId, organisationId, siteId }, select: { id: true } });
    return incident !== null;
  }

  async createAssignment(input: CreateAssignmentInput): Promise<{ assignment: FieldAssignment; created: boolean }> {
    try {
      const assignment = await this.prisma.$transaction(async (tx) => {
        const row = await tx.fieldAssignment.create({
          data: {
            organisationId: input.organisationId,
            siteId: input.siteId,
            incidentId: input.incidentId,
            assigneeUserId: input.assigneeUserId,
            assignmentType: input.assignmentType,
            priority: input.priority,
            status: 'REQUESTED',
            deliveryState: 'REQUESTED',
            needToKnowSummary: input.needToKnowSummary,
            idempotencyKey: input.idempotencyKey,
            expiresAt: input.expiresAt,
            createdByUserId: input.actorUserId,
            updatedByUserId: input.actorUserId,
          },
        });
        await tx.fieldAuditLog.create({
          data: {
            organisationId: input.organisationId,
            siteId: input.siteId,
            assignmentId: row.id,
            actorUserId: input.actorUserId,
            kind: 'FIELD_ASSIGNMENT_CREATED',
            payload: auditPayload({ assignment_id: row.id, assignee_user_id: input.assigneeUserId, incident_id: input.incidentId }),
          },
        });
        await tx.fieldOutbox.create({
          data: {
            organisationId: input.organisationId,
            siteId: input.siteId,
            payload: { kind: 'FIELD_ASSIGNMENT_CREATED', assignment_id: row.id, organisation_id: input.organisationId, site_id: input.siteId },
          },
        });
        return row;
      });
      this.assertAssignmentContract(assignment);
      return { assignment, created: true };
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      const existing = await this.prisma.fieldAssignment.findFirst({
        where: { organisationId: input.organisationId, siteId: input.siteId, idempotencyKey: input.idempotencyKey },
      });
      if (!existing) throw error;
      this.assertAssignmentContract(existing);
      return { assignment: existing, created: false };
    }
  }

  async transitionAssignment(input: TransitionInput): Promise<TransitionResult> {
    return this.prisma.$transaction(async (tx) => {
      const found = await tx.fieldAssignment.findFirst({
        where: { id: input.assignmentId, organisationId: input.organisationId, ...siteScopeWhere(input.siteScope) },
        select: { id: true },
      });
      if (!found) return { kind: 'not_found' };
      await tx.$queryRaw(Prisma.sql`SELECT id FROM field_assignments WHERE id = ${found.id}::uuid FOR UPDATE`);
      const current = await tx.fieldAssignment.findUniqueOrThrow({ where: { id: found.id } });
      if (input.actorMustBeAssignee && current.assigneeUserId !== input.actorUserId) return { kind: 'forbidden' };
      const duplicate = await tx.fieldAssignmentActionIdempotency.findUnique({
        where: { assignmentId_action_idempotencyKey: { assignmentId: current.id, action: input.action, idempotencyKey: input.idempotencyKey } },
      });
      if (duplicate) return { kind: 'duplicate', assignment: current };
      if (current.status === input.targetStatus) return { kind: 'noop', assignment: current };
      if (current.status !== input.expectedStatus || !canTransitionFieldAssignmentStatus(current.status as FieldAssignmentStatus, input.targetStatus)) {
        return { kind: 'conflict', currentStatus: current.status };
      }
      const at = new Date();
      const updated = await tx.fieldAssignment.update({
        where: { id: current.id },
        data: {
          status: input.targetStatus,
          updatedByUserId: input.actorUserId,
          ...(input.action === 'accept' ? { acceptedAt: at, acceptedByUserId: input.actorUserId, deliveryState: 'ACKNOWLEDGED' } : {}),
          ...(input.action === 'decline' ? { declinedAt: at } : {}),
          ...(input.action === 'start' ? { startedAt: at } : {}),
          ...(input.action === 'complete' ? { completedAt: at } : {}),
          ...(input.action === 'cancel' ? { cancelledAt: at } : {}),
        },
      });
      await tx.fieldAssignmentActionIdempotency.create({
        data: { assignmentId: current.id, action: input.action, idempotencyKey: input.idempotencyKey, actorUserId: input.actorUserId },
      });
      const kind = `FIELD_ASSIGNMENT_${input.targetStatus}`;
      await tx.fieldAuditLog.create({
        data: {
          organisationId: current.organisationId,
          siteId: current.siteId,
          assignmentId: current.id,
          actorUserId: input.actorUserId,
          kind,
          payload: { assignment_id: current.id, from_status: current.status, to_status: input.targetStatus, action: input.action },
        },
      });
      await tx.fieldOutbox.create({
        data: {
          organisationId: current.organisationId,
          siteId: current.siteId,
          payload: { kind, assignment_id: current.id, organisation_id: current.organisationId, site_id: current.siteId },
        },
      });
      this.assertAssignmentContract(updated);
      return { kind: 'updated', assignment: updated };
    });
  }

  async recordState(input: StateInput): Promise<{ state: FieldOperativeCurrentState; created: boolean }> {
    return this.prisma.$transaction(async (tx) => {
      const duplicate = await tx.fieldStateUpdateIdempotency.findUnique({
        where: {
          organisationId_siteId_userId_deviceId_idempotencyKey: {
            organisationId: input.organisationId,
            siteId: input.siteId,
            userId: input.actorUserId,
            deviceId: input.deviceId,
            idempotencyKey: input.idempotencyKey,
          },
        },
      });
      if (duplicate) {
        const current = await tx.fieldOperativeCurrentState.findUniqueOrThrow({
          where: { organisationId_siteId_userId: { organisationId: input.organisationId, siteId: input.siteId, userId: input.actorUserId } },
        });
        return { state: current, created: false };
      }
      await tx.fieldStateUpdateIdempotency.create({
        data: {
          organisationId: input.organisationId,
          siteId: input.siteId,
          userId: input.actorUserId,
          deviceId: input.deviceId,
          idempotencyKey: input.idempotencyKey,
        },
      });
      await tx.fieldOperativeStateHistory.create({
        data: {
          organisationId: input.organisationId,
          siteId: input.siteId,
          userId: input.actorUserId,
          deviceId: input.deviceId,
          state: input.state,
          location: input.location === null ? Prisma.DbNull : input.location,
          sourceAt: input.sourceAt,
          receivedAt: input.receivedAt,
          clientFreshnessMs: input.clientFreshnessMs,
          authoritativeFreshnessMs: input.authoritativeFreshnessMs,
          traceId: input.traceId,
        },
      });
      const current = await tx.fieldOperativeCurrentState.upsert({
        where: { organisationId_siteId_userId: { organisationId: input.organisationId, siteId: input.siteId, userId: input.actorUserId } },
        create: {
          organisationId: input.organisationId,
          siteId: input.siteId,
          userId: input.actorUserId,
          deviceId: input.deviceId,
          state: input.state,
          location: input.location === null ? Prisma.DbNull : input.location,
          sourceAt: input.sourceAt,
          receivedAt: input.receivedAt,
          clientFreshnessMs: input.clientFreshnessMs,
          authoritativeFreshnessMs: input.authoritativeFreshnessMs,
          traceId: input.traceId,
        },
        update: {
          deviceId: input.deviceId,
          state: input.state,
          location: input.location === null ? Prisma.DbNull : input.location,
          sourceAt: input.sourceAt,
          receivedAt: input.receivedAt,
          clientFreshnessMs: input.clientFreshnessMs,
          authoritativeFreshnessMs: input.authoritativeFreshnessMs,
          traceId: input.traceId,
        },
      });
      await tx.fieldAuditLog.create({
        data: {
          organisationId: input.organisationId,
          siteId: input.siteId,
          actorUserId: input.actorUserId,
          kind: 'FIELD_STATE_UPDATED',
          payload: { user_id: input.actorUserId, state: input.state, source_at: input.sourceAt.toISOString(), received_at: input.receivedAt.toISOString() },
        },
      });
      await tx.fieldOutbox.create({
        data: {
          organisationId: input.organisationId,
          siteId: input.siteId,
          payload: { kind: 'FIELD_STATE_UPDATED', user_id: input.actorUserId, state: input.state, organisation_id: input.organisationId, site_id: input.siteId },
        },
      });
      return { state: current, created: true };
    });
  }

  async listAssignments(organisationId: string, siteScope: SiteScope): Promise<FieldAssignment[]> {
    return this.prisma.fieldAssignment.findMany({
      where: { organisationId, ...siteScopeWhere(siteScope) },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: 200,
    });
  }

  async getAssignment(organisationId: string, id: string, siteScope: SiteScope): Promise<FieldAssignment | null> {
    return this.prisma.fieldAssignment.findFirst({ where: { id, organisationId, ...siteScopeWhere(siteScope) } });
  }

  async getCurrentState(organisationId: string, userId: string, siteScope: SiteScope): Promise<FieldOperativeCurrentState | null> {
    return this.prisma.fieldOperativeCurrentState.findFirst({
      where: { organisationId, userId, ...stateSiteScopeWhere(siteScope) },
    });
  }

  async auditCount(assignmentId: string): Promise<number> {
    return this.prisma.fieldAuditLog.count({ where: { assignmentId } });
  }

  async outboxCountForAssignment(assignmentId: string): Promise<number> {
    return this.prisma.fieldOutbox.count({ where: { payload: { path: ['assignment_id'], equals: assignmentId } } });
  }

  private assertAssignmentContract(row: FieldAssignment): void {
    FieldAssignmentSchema.parse({
      schema_version: 1,
      assignment_id: row.id,
      organisation_id: row.organisationId,
      site_id: row.siteId,
      incident_id: row.incidentId,
      assignee_user_id: row.assigneeUserId,
      assignment_type: row.assignmentType,
      priority: row.priority,
      status: row.status,
      delivery_state: row.deliveryState,
      need_to_know_summary: row.needToKnowSummary,
      created_at: row.createdAt.toISOString(),
      updated_at: row.updatedAt.toISOString(),
      expires_at: row.expiresAt?.toISOString() ?? null,
      accepted_at: row.acceptedAt?.toISOString() ?? null,
      completed_at: row.completedAt?.toISOString() ?? null,
      created_by_user_id: row.createdByUserId,
      updated_by_user_id: row.updatedByUserId,
      accepted_by_user_id: row.acceptedByUserId,
      trace_id: row.id,
    });
  }

  validateStateContract(input: StateInput): void {
    FieldOperativeStateUpdateSchema.parse({
      schema_version: 1,
      organisation_id: input.organisationId,
      site_id: input.siteId,
      actor_user_id: input.actorUserId,
      device_id: input.deviceId,
      state: input.state,
      location: input.location,
      source_at: input.sourceAt.toISOString(),
      freshness_ms: input.clientFreshnessMs,
      trace_id: input.traceId,
    });
  }
}
