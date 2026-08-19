import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type Incident, type ResponseTask } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import type { CreateIncidentInput, IncidentListFilter, OpenWhisperSilentIncidentInput } from './incidents.types';
import type { SiteScope } from '../identity/list-pagination';
import {
  INCIDENT_SOURCE_KIND_WHISPER_RECOGNITION,
  PLAYBOOK_PROOF_A_V1,
  TASK_DISPATCH_FIELD,
  TASK_NOTIFY_COMMANDER,
  TASK_PRESERVE_EVIDENCE,
  WHISPER_INCIDENT_SEVERITY,
  WHISPER_INCIDENT_THREAT_STATE,
  WHISPER_INCIDENT_TYPE,
} from './incidents.constants';

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
            // B11-13: this method IS the Fusion source path (the only
            // production writer of an incident row), so its source identity
            // is fixed HERE rather than accepted from the caller — nothing
            // upstream can claim a different origin for a Fusion incident.
            // The literal matches the WP-21B migration backfill exactly.
            sourceKind: 'FUSION_HYPOTHESIS',
            sourceRef: input.hypothesisId,
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
            hypothesisUpdatedAt: input.hypothesisUpdatedAt,
            hypothesisVersion: input.hypothesisVersion,
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

  /**
   * B11-13/B11-14: opens — or REUSES — the incident a recognised Whisper
   * device-action signal enters the SILENT response path through.
   *
   * IDENTICAL IN SHAPE TO `createFromCandidate`, DELIBERATELY. Both are source
   * paths, so both fix their own source identity here rather than accepting it
   * from a caller, and both express redelivery idempotence as a P2002 on a
   * unique index rather than a read-then-create a crash could interleave with.
   * The Fusion path above is untouched.
   *
   * WHAT THIS METHOD REFUSES TO INVENT. `hypothesis_id` and
   * `incident_candidate_id` are NULL, because a duress recognition is not a
   * Fusion assessment: fabricating either would mean inventing evidence no
   * Fusion pipeline ever produced, and would destroy the one guarantee those
   * columns exist to give. The related/supporting/contradicting event arrays
   * are empty for the same reason — a recognition cites no events, and an
   * empty array says exactly that while a populated one would be a lie.
   *
   * IDEMPOTENCE IS CRASH-SAFE, and it has to be. The recognition receipt is
   * claimed before this call and finalized after it, so a process that dies in
   * between leaves a receipt reclaimable under its lease; the retry re-enters
   * on the SAME recognition fingerprint, collides on
   * `incidents_source_identity_key`, and converges on the incident the first
   * attempt already opened. Without that, a crash between the two would open a
   * second incident for one duress signal.
   *
   * The timeline entry names NO ACTOR, deliberately. `incident.view` is held by
   * six roles, so recording who signalled here would broadcast the identity of
   * the person under duress far beyond the four Whisper capabilities. W21-14
   * puts WHO in the Whisper audit log, which carries `incident_id`, so the
   * chain stays reconstructable by anyone entitled to walk it — and by nobody
   * else.
   */
  async createFromWhisperRecognition(input: OpenWhisperSilentIncidentInput): Promise<{ incident: Incident; created: boolean }> {
    const sourceRef = input.recognitionFingerprint;
    try {
      const incident = await this.prisma.$transaction(async (tx) => {
        const row = await tx.incident.create({
          data: {
            hypothesisId: null,
            incidentCandidateId: null,
            sourceKind: INCIDENT_SOURCE_KIND_WHISPER_RECOGNITION,
            sourceRef,
            organisationId: input.organisationId,
            siteId: input.siteId,
            incidentType: WHISPER_INCIDENT_TYPE,
            severity: WHISPER_INCIDENT_SEVERITY,
            threatState: WHISPER_INCIDENT_THREAT_STATE,
            // C11-04: the SIGNED confidence, so an intercepted recognition
            // could not have had this figure raised in flight.
            confidence: input.confidence,
            responseMode: 'SILENT',
            relatedEventIds: [],
            supportingEventIds: [],
            contradictingEventIds: [],
            playbookVersion: PLAYBOOK_PROOF_A_V1,
            proofAStartedAt: new Date(),
          },
        });
        await tx.incidentTimelineEntry.create({
          data: {
            incidentId: row.id,
            kind: 'INCIDENT_OPENED',
            payload: {
              source_kind: INCIDENT_SOURCE_KIND_WHISPER_RECOGNITION,
              source_ref: sourceRef,
              incident_type: WHISPER_INCIDENT_TYPE,
              severity: WHISPER_INCIDENT_SEVERITY,
              response_mode: 'SILENT',
              trace_id: input.traceId,
            },
          },
        });
        await tx.incidentUpdateOutbox.create({
          data: {
            incidentId: row.id,
            organisationId: input.organisationId,
            payload: { id: row.id, organisation_id: input.organisationId, kind: 'INCIDENT_OPENED' },
          },
        });
        return row;
      });
      return { incident, created: true };
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      const incident = await this.prisma.incident.findUnique({
        where: {
          organisationId_sourceKind_sourceRef: {
            organisationId: input.organisationId,
            sourceKind: INCIDENT_SOURCE_KIND_WHISPER_RECOGNITION,
            sourceRef,
          },
        },
      });
      // A P2002 on some OTHER constraint would leave this read empty. Rethrow
      // the original rather than reinterpret an unrelated violation as a
      // successful convergence.
      if (!incident) throw error;
      return { incident, created: false };
    }
  }

  /**
   * B11-13: the EVIDENCE probe for Whisper crash recovery.
   *
   * A pure lookup of the row `createFromWhisperRecognition` writes inside the
   * SAME transaction as the incident it records. That atomicity is the whole
   * argument: presence proves the effect committed, absence proves it did not.
   * It consults no mutable state — not the incident's status, not its tasks —
   * because all of those may legitimately have moved on since the attempt
   * being recovered.
   */
  async findByWhisperRecognition(organisationId: string, recognitionFingerprint: string): Promise<Incident | null> {
    return this.prisma.incident.findUnique({
      where: {
        organisationId_sourceKind_sourceRef: {
          organisationId,
          sourceKind: INCIDENT_SOURCE_KIND_WHISPER_RECOGNITION,
          sourceRef: recognitionFingerprint,
        },
      },
    });
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

  /**
   * Applies one newer Fusion assessment and, on its first critical-severity
   * crossing, creates the durable PB-PROOF-A tasks in the same transaction.
   * Older/equal source timestamps are intentional at-least-once no-ops.
   */
  async advanceFromHypothesis(input: {
    hypothesisId: string; organisationId: string; sourceAt: Date; triggeringEventId: string; hypothesisVersion: number; state: number; severity: string; confidence: number;
    supportingEventIds: string[]; contradictingEventIds: string[];
  }): Promise<{ incident: Incident; startedProofA: boolean } | null> {
    return this.prisma.$transaction(async (tx) => {
      const found = await tx.incident.findFirst({ where: { hypothesisId: input.hypothesisId, organisationId: input.organisationId }, select: { id: true } });
      if (!found) return null;
      // Serialise assessments for this incident. The post-lock reread is
      // essential under READ COMMITTED: a concurrent newer transaction may
      // have committed while this transaction was waiting for the row lock.
      await tx.$queryRaw(Prisma.sql`SELECT id FROM incidents WHERE id = ${found.id}::uuid FOR UPDATE`);
      const current = await tx.incident.findUniqueOrThrow({ where: { id: found.id } });
      const isOlder = current.hypothesisVersion !== null && current.hypothesisVersion > input.hypothesisVersion;
      const isDuplicate = current.hypothesisVersion !== null && current.hypothesisVersion === input.hypothesisVersion;
      if (isOlder || isDuplicate) return null;
      const critical = ['SEV1', 'SEV2'].includes(input.severity);
      const startedProofA = critical && current.proofAStartedAt === null;
      const updated = await tx.incident.update({
        where: { id: current.id },
        data: {
          threatState: input.state, severity: input.severity, confidence: input.confidence,
          supportingEventIds: input.supportingEventIds,
          contradictingEventIds: input.contradictingEventIds,
          relatedEventIds: [...new Set([...input.supportingEventIds, ...input.contradictingEventIds])],
          hypothesisUpdatedAt: input.sourceAt,
          hypothesisTriggeringEventId: input.triggeringEventId,
          hypothesisVersion: input.hypothesisVersion,
          ...(startedProofA ? { playbookVersion: PLAYBOOK_PROOF_A_V1, proofAStartedAt: input.sourceAt } : {}),
        },
      });
      if (startedProofA) {
        await tx.responseTask.createMany({
          data: [TASK_PRESERVE_EVIDENCE, TASK_NOTIFY_COMMANDER, TASK_DISPATCH_FIELD].map((taskType) => ({ incidentId: current.id, taskType, playbookVersion: PLAYBOOK_PROOF_A_V1 })),
          skipDuplicates: true,
        });
      }
      await tx.incidentTimelineEntry.create({ data: { incidentId: current.id, kind: 'HYPOTHESIS_UPDATED', payload: {
        hypothesis_id: input.hypothesisId, source_at: input.sourceAt.toISOString(), threat_state: input.state, severity: input.severity,
        ...(startedProofA ? { playbook_started: PLAYBOOK_PROOF_A_V1 } : {}),
      } } });
      await tx.incidentUpdateOutbox.create({ data: { incidentId: current.id, organisationId: current.organisationId, payload: { id: current.id, organisation_id: current.organisationId, kind: 'HYPOTHESIS_UPDATED' } } });
      return { incident: updated, startedProofA };
    });
  }

  async findForHypothesis(hypothesisId: string, organisationId: string): Promise<Incident | null> {
    return this.prisma.incident.findFirst({ where: { hypothesisId, organisationId } });
  }

  async latestHypothesis(hypothesisId: string, organisationId: string) {
    return this.prisma.hypothesis.findFirst({ where: { id: hypothesisId, organisationId } });
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
