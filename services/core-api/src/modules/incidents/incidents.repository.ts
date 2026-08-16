import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type Incident, type ResponseTask } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import type { CreateIncidentInput, IncidentListFilter } from './incidents.types';
import type { SiteScope } from '../identity/list-pagination';
import { PLAYBOOK_PROOF_A_V1, TASK_DISPATCH_FIELD, TASK_NOTIFY_COMMANDER, TASK_PRESERVE_EVIDENCE } from './incidents.constants';

export function isUniqueViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

function siteScopeWhere(siteScope: SiteScope): Prisma.IncidentWhereInput {
  return siteScope.orgWide ? {} : { siteId: { in: siteScope.siteIds } };
}

@Injectable()
export class IncidentsRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  async createFromCandidate(input: CreateIncidentInput): Promise<{ incident: Incident; created: boolean }> {
    try {
      const incident = await this.prisma.$transaction(async (tx) => {
        const row = await tx.incident.create({
          data: {
            hypothesisId: input.hypothesisId,
            incidentCandidateId: input.incidentCandidateId,
            organisationId: input.organisationId,
            siteId: input.siteId,
            incidentType: input.incidentType,
            severity: input.severity,
            threatState: input.threatState,
            confidence: input.confidence,
            responseMode: input.responseMode,
            relatedEventIds: input.relatedEventIds,
            supportingEventIds: input.supportingEventIds,
            contradictingEventIds: input.contradictingEventIds,
            playbookVersion: ['SEV1', 'SEV2'].includes(input.severity) ? PLAYBOOK_PROOF_A_V1 : null,
          },
        });
        await tx.incidentTimelineEntry.create({
          data: {
            incidentId: row.id,
            kind: 'INCIDENT_OPENED',
            payload: { hypothesis_id: input.hypothesisId, incident_candidate_id: input.incidentCandidateId, severity: input.severity },
          },
        });
        await tx.incidentUpdateOutbox.create({ data: { incidentId: row.id, organisationId: input.organisationId, payload: { id: row.id, organisation_id: input.organisationId, kind: 'INCIDENT_OPENED' } } });
        return row;
      });
      return { incident, created: true };
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      const incident = await this.prisma.incident.findUnique({ where: { hypothesisId: input.hypothesisId } });
      if (!incident) throw error;
      return { incident, created: false };
    }
  }

  async ensureProofATasks(incidentId: string): Promise<ResponseTask[]> {
    await this.prisma.responseTask.createMany({
      data: [TASK_PRESERVE_EVIDENCE, TASK_NOTIFY_COMMANDER, TASK_DISPATCH_FIELD].map((taskType) => ({
        incidentId,
        taskType,
        playbookVersion: PLAYBOOK_PROOF_A_V1,
      })),
      skipDuplicates: true,
    });
    return this.prisma.responseTask.findMany({ where: { incidentId }, orderBy: { createdAt: 'asc' } });
  }

  async findTask(incidentId: string, taskId: string, organisationId: string, siteScope: SiteScope): Promise<(ResponseTask & { incident: Incident }) | null> {
    return this.prisma.responseTask.findFirst({
      where: { id: taskId, incidentId, incident: { organisationId, ...siteScopeWhere(siteScope) } }, include: { incident: true },
    });
  }

  async recordSilentApproval(taskId: string, userId: string): Promise<boolean> {
    try {
      await this.prisma.$transaction(async (tx) => {
        const task = await tx.responseTask.findUniqueOrThrow({ where: { id: taskId }, include: { incident: true } });
        await tx.responseTaskSilentApproval.create({ data: { taskId, userId, claimedRole: 'site.commander' } });
        await tx.incidentTimelineEntry.create({ data: { incidentId: task.incidentId, kind: 'SILENT_APPROVAL_RECORDED', actorUserId: userId, payload: { task_id: taskId, claimed_role: 'site.commander' } } });
        await tx.incidentUpdateOutbox.create({ data: { incidentId: task.incidentId, organisationId: task.incident.organisationId, payload: { id: task.incidentId, organisation_id: task.incident.organisationId, kind: 'SILENT_APPROVAL_RECORDED' } } });
      });
      return true;
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      return false;
    }
  }

  async recordConstitutionDecision(taskId: string, kind: string, payload: Prisma.InputJsonValue): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      const task = await tx.responseTask.findUniqueOrThrow({ where: { id: taskId }, include: { incident: true } });
      await tx.incidentTimelineEntry.create({ data: { incidentId: task.incidentId, kind, payload } });
      await tx.incidentUpdateOutbox.create({ data: { incidentId: task.incidentId, organisationId: task.incident.organisationId, payload: { id: task.incidentId, organisation_id: task.incident.organisationId, kind } } });
    });
  }

  async listSilentApprovals(taskId: string): Promise<Array<{ userId: string; claimedRole: string; approvedAt: Date }>> {
    return this.prisma.responseTaskSilentApproval.findMany({ where: { taskId }, orderBy: { approvedAt: 'asc' } });
  }

  async acknowledgeTask(taskId: string, actorUserId: string, at: Date): Promise<ResponseTask | null> {
    return this.prisma.$transaction(async (tx) => {
      const task = await tx.responseTask.findUnique({ where: { id: taskId }, include: { incident: true } });
      if (!task || task.deliveryState !== 'DELIVERED') return null;
      const updated = await tx.responseTask.update({ where: { id: taskId }, data: { deliveryState: 'ACKNOWLEDGED', acknowledgedAt: at, acknowledgedByUserId: actorUserId } });
      await tx.incidentTimelineEntry.create({ data: { incidentId: task.incidentId, kind: 'FIELD_DISPATCH_ACKNOWLEDGED', actorUserId, payload: { task_id: taskId, acknowledged_at: at.toISOString() } } });
      await tx.incidentUpdateOutbox.create({ data: { incidentId: task.incidentId, organisationId: task.incident.organisationId, payload: { id: task.incidentId, organisation_id: task.incident.organisationId, kind: 'FIELD_DISPATCH_ACKNOWLEDGED' } } });
      return updated;
    });
  }

  async createLocalDispatchHandoff(taskId: string, responseMode: string): Promise<ResponseTask | null> {
    try {
      return await this.prisma.$transaction(async (tx) => {
        const task = await tx.responseTask.findUniqueOrThrow({ where: { id: taskId }, include: { incident: true } });
        await tx.responseDispatchHandoff.create({
          data: { taskId, destination: 'local:field-dispatch-inbox', receipt: { accepted_by: 'local-dispatch-inbox' } },
        });
        const updated = await tx.responseTask.updateMany({ where: { id: taskId, deliveryState: 'REQUESTED' }, data: { deliveryState: 'DELIVERED' } });
        if (updated.count !== 1) throw new Error('Task changed before local handoff could be accepted');
        await tx.incidentTimelineEntry.create({ data: { incidentId: task.incidentId, kind: 'FIELD_DISPATCH_DELIVERED', payload: { task_id: taskId, response_mode: responseMode, destination: 'local:field-dispatch-inbox' } } });
        await tx.incidentUpdateOutbox.create({ data: { incidentId: task.incidentId, organisationId: task.incident.organisationId, payload: { id: task.incidentId, organisation_id: task.incident.organisationId, kind: 'FIELD_DISPATCH_DELIVERED' } } });
        return tx.responseTask.findUnique({ where: { id: taskId } });
      });
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      return this.prisma.responseTask.findUnique({ where: { id: taskId } });
    }
  }

  async claimEvidenceSnapshot(taskId: string): Promise<void> {
    await this.prisma.responseTask.updateMany({
      where: { id: taskId, evidenceSnapshotStartedAt: null }, data: { evidenceSnapshotStartedAt: new Date() },
    });
  }

  async completeEvidenceSnapshot(taskId: string, evidenceSnapshotId: string | null, detail: Prisma.InputJsonValue): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      const task = await tx.responseTask.findUniqueOrThrow({ where: { id: taskId }, include: { incident: true } });
      if (task.completedAt) return;
      await tx.responseTask.update({ where: { id: taskId }, data: { evidenceSnapshotId, completedAt: new Date(), completionDetail: detail } });
      const kind = evidenceSnapshotId ? 'EVIDENCE_SNAPSHOT_PRESERVED' : 'EVIDENCE_SNAPSHOT_SKIPPED';
      await tx.incidentTimelineEntry.create({ data: { incidentId: task.incidentId, kind, payload: evidenceSnapshotId ? { task_id: taskId, evidence_id: evidenceSnapshotId } : { task_id: taskId, detail } } });
      await tx.incidentUpdateOutbox.create({ data: { incidentId: task.incidentId, organisationId: task.incident.organisationId, payload: { id: task.incidentId, organisation_id: task.incident.organisationId, kind } } });
    });
  }

  async transitionIncidentStatus(
    incidentId: string,
    organisationId: string,
    expectedStatus: string,
    status: string,
    closureReason: string | null,
    siteScope: SiteScope,
    actorUserId: string | null,
  ): Promise<Incident | null> {
    return this.prisma.$transaction(async (tx) => {
      const result = await tx.incident.updateMany({ where: { id: incidentId, organisationId, status: expectedStatus, ...siteScopeWhere(siteScope) }, data: { status, closureReason, ...(status === 'closed' ? { closedAt: new Date() } : {}) } });
      if (result.count !== 1) return null;
      const incident = await tx.incident.findUniqueOrThrow({ where: { id: incidentId } });
      await tx.incidentTimelineEntry.create({ data: { incidentId, kind: `INCIDENT_${status.toUpperCase()}`, actorUserId, payload: { from_status: expectedStatus, to_status: status } } });
      await tx.incidentUpdateOutbox.create({ data: { incidentId, organisationId, payload: { id: incidentId, organisation_id: organisationId, kind: `INCIDENT_${status.toUpperCase()}` } } });
      return incident;
    });
  }

  async appendTimeline(incidentId: string, kind: string, payload: Prisma.InputJsonValue, actorUserId: string | null = null): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      const incident = await tx.incident.findUniqueOrThrow({ where: { id: incidentId }, select: { organisationId: true } });
      await tx.incidentTimelineEntry.create({ data: { incidentId, kind, payload, actorUserId } });
      await tx.incidentUpdateOutbox.create({
        data: { incidentId, organisationId: incident.organisationId, payload: { id: incidentId, organisation_id: incident.organisationId, kind } },
      });
    });
  }

  async pendingOutbox(limit = 100) {
    return this.prisma.incidentUpdateOutbox.findMany({ where: { publishedAt: null }, orderBy: { createdAt: 'asc' }, take: limit });
  }

  async markOutboxPublished(id: string): Promise<boolean> {
    const updated = await this.prisma.incidentUpdateOutbox.updateMany({ where: { id, publishedAt: null }, data: { publishedAt: new Date() } });
    return updated.count === 1;
  }

  async list(filter: IncidentListFilter): Promise<Incident[]> {
    return this.prisma.incident.findMany({
      where: {
        organisationId: filter.organisationId,
        ...siteScopeWhere(filter.siteScope),
        ...(filter.status ? { status: filter.status } : {}),
        ...(filter.severity ? { severity: filter.severity } : {}),
      },
      orderBy: [{ openedAt: 'desc' }, { id: 'desc' }], take: filter.limit,
    });
  }

  async detail(organisationId: string, id: string, siteScope: SiteScope): Promise<(Incident & { timeline: import('@prisma/client').IncidentTimelineEntry[]; responseTasks: ResponseTask[] }) | null> {
    return this.prisma.incident.findFirst({
      where: { id, organisationId, ...siteScopeWhere(siteScope) },
      include: { timeline: { orderBy: [{ at: 'asc' }, { id: 'asc' }] }, responseTasks: { orderBy: { createdAt: 'asc' } } },
    });
  }
}
