import { BadRequestException, ConflictException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { canTransition, type DeliveryState, type IncidentStatus, type ResponseMode } from '@sentinel/contracts';
import type { IncidentCandidateMessage } from '../fusion/fusion.types';
import { ConstitutionService } from '../constitution/constitution.service';
import { EvidenceService } from '../evidence/evidence.service';
import {
  PLAYBOOK_PROOF_A_V1,
  RESPONSE_SYSTEM_ACTOR,
  SILENT_DISPATCH_ACTION,
  STANDARD_DISPATCH_ACTION,
  TASK_DISPATCH_FIELD,
  TASK_NOTIFY_COMMANDER,
  TASK_PRESERVE_EVIDENCE,
} from './incidents.constants';
import { toIncidentView, toTaskView, toTimelineView } from './incidents.mapper';
import { IncidentsPublisher } from './incidents.publisher';
import { IncidentsRepository } from './incidents.repository';
import type { IncidentDetailView, IncidentListFilter, IncidentTransitionInput } from './incidents.types';
import type { SiteScope } from '../identity/list-pagination';

const CRITICAL_PLAYBOOK_SEVERITIES = new Set(['SEV1', 'SEV2']);
const SYSTEM_SITE_SCOPE: SiteScope = { orgWide: true, siteIds: [] };

/**
 * WP-05 currently exposes no dedicated response-mode field on an incident
 * candidate. Its versioned rule-pack markers are therefore the only durable
 * candidate metadata from which the WP-07 coercion/duress family flag can be
 * recovered. The match is deliberately exact-token based, not a heuristic on
 * prose or event ids; a future typed flag can replace this without changing
 * the incident object.
 */
export function responseModeForCandidate(candidate: IncidentCandidateMessage): ResponseMode {
  const flags = candidate.rule_or_model_versions.flatMap((version) => version.toLowerCase().split(/[^a-z]+/u));
  return flags.includes('coercion') || flags.includes('duress') ? 'SILENT' : 'STANDARD';
}

@Injectable()
export class IncidentsService {
  constructor(
    @Inject(IncidentsRepository) private readonly repository: IncidentsRepository,
    @Inject(EvidenceService) private readonly evidence: EvidenceService,
    @Inject(ConstitutionService) private readonly constitution: ConstitutionService,
    @Inject(IncidentsPublisher) private readonly publisher: IncidentsPublisher,
  ) {}

  /** Durable, idempotent hand-off from Fusion's incident-candidate stream. */
  async handleCandidate(candidate: IncidentCandidateMessage): Promise<IncidentDetailView> {
    const responseMode = responseModeForCandidate(candidate);
    const { incident } = await this.repository.createFromCandidate({
      hypothesisId: candidate.hypothesis_id,
      incidentCandidateId: candidate.incident_candidate_id,
      organisationId: candidate.organisation_id,
      siteId: candidate.site_id,
      incidentType: 'fusion.hypothesis',
      severity: candidate.operational_severity,
      threatState: candidate.threat_state,
      confidence: candidate.threat_probability,
      responseMode,
      relatedEventIds: [...new Set([...candidate.supporting_event_ids, ...candidate.contradicting_event_ids])],
      supportingEventIds: [...new Set(candidate.supporting_event_ids)],
      contradictingEventIds: [...new Set(candidate.contradicting_event_ids)],
    });

    if (CRITICAL_PLAYBOOK_SEVERITIES.has(incident.severity)) {
      await this.runProofA(
        incident.id,
        incident.organisationId,
        incident.siteId,
        responseMode,
        incident.supportingEventIds,
        incident.contradictingEventIds,
      );
    }

    const detail = await this.getDetail(incident.organisationId, incident.id, SYSTEM_SITE_SCOPE);
    // A notification is best-effort by design; nothing may roll back a
    // committed incident because a transient realtime path is unavailable.
    await this.publisher.publishUpdated(detail);
    return detail;
  }

  /** The only incident status transition point: open -> contained -> closed. */
  async transitionStatus(organisationId: string, incidentId: string, siteScope: SiteScope, input: IncidentTransitionInput): Promise<IncidentDetailView> {
    const detail = await this.getDetail(organisationId, incidentId, siteScope);
    const from = detail.status;
    const allowed: Readonly<Record<IncidentStatus, readonly IncidentStatus[]>> = {
      open: ['contained'],
      contained: ['closed'],
      closed: [],
    };
    if (!allowed[from].includes(input.status)) {
      throw new ConflictException(`Illegal incident status transition ${from} -> ${input.status}`);
    }
    if (input.status === 'closed' && (!input.closureReason || input.closureReason.trim().length === 0)) {
      throw new BadRequestException('closure_reason is required when closing an incident');
    }
    const updated = await this.repository.transitionIncidentStatus(
      incidentId,
      organisationId,
      from,
      input.status,
      input.status === 'closed' ? input.closureReason!.trim() : null,
      siteScope,
      input.actorUserId,
    );
    if (!updated) throw new ConflictException('Incident changed concurrently; retry the transition');
    const result = await this.getDetail(organisationId, updated.id, siteScope);
    await this.publisher.publishUpdated(result);
    return result;
  }

  async acknowledge(organisationId: string, incidentId: string, taskId: string, actorUserId: string, siteScope: SiteScope): Promise<IncidentDetailView> {
    const task = await this.repository.findTask(incidentId, taskId, organisationId, siteScope);
    if (!task || task.taskType !== TASK_DISPATCH_FIELD) throw new NotFoundException('Field dispatch task not found');
    if (task.deliveryState === 'ACKNOWLEDGED') return this.getDetail(organisationId, incidentId, siteScope);
    this.assertDeliveryTransition(task.deliveryState as DeliveryState, 'ACKNOWLEDGED');
    const acknowledgedAt = new Date();
    const updated = await this.repository.acknowledgeTask(task.id, actorUserId, acknowledgedAt);
    if (!updated) {
      const retried = await this.repository.findTask(incidentId, taskId, organisationId, siteScope);
      if (retried?.deliveryState === 'ACKNOWLEDGED') return this.getDetail(organisationId, incidentId, siteScope);
      throw new ConflictException('Task changed concurrently; retry acknowledgement');
    }
    const result = await this.getDetail(organisationId, incidentId, siteScope);
    await this.publisher.publishUpdated(result);
    return result;
  }

  /** Records a distinct site-command approval then re-evaluates the pending SILENT dispatch. */
  async approveSilentDispatch(organisationId: string, incidentId: string, taskId: string, actorUserId: string, siteScope: SiteScope): Promise<IncidentDetailView> {
    const task = await this.repository.findTask(incidentId, taskId, organisationId, siteScope);
    if (!task || task.taskType !== TASK_DISPATCH_FIELD || task.incident.responseMode !== 'SILENT') {
      throw new NotFoundException('Silent field dispatch task not found');
    }
    const created = await this.repository.recordSilentApproval(task.id, actorUserId);
    if (!created) return this.getDetail(organisationId, incidentId, siteScope);
    if (task.deliveryState === 'REQUESTED') {
      const approvals = await this.repository.listSilentApprovals(task.id);
      const traceId = `incident:${incidentId}:task:${task.id}:dispatch:silent:approval-count:${approvals.length}`;
      const decision = await this.constitution.evaluate(
        {
          action: SILENT_DISPATCH_ACTION,
          actor: { userId: RESPONSE_SYSTEM_ACTOR, roles: ['system.response'], organisationId, clearance: 5, purpose: 'silent-response-dispatch', deviceTrust: 'TRUSTED' },
          target: { organisationId, siteId: task.incident.siteId, classification: 'SENSITIVE', classificationLevel: 2 },
          approvals: approvals.map((approval) => ({ userId: approval.userId, role: approval.claimedRole, at: approval.approvedAt.toISOString() })),
          approver_roles: Object.fromEntries(approvals.map((approval) => [approval.userId, ['site.commander']])),
        },
        { traceId },
      );
      const payload = JSON.parse(JSON.stringify({ task_id: task.id, action: SILENT_DISPATCH_ACTION, decision: decision.decision, trace_id: traceId, trace: decision.trace, approvals })) as Prisma.InputJsonValue;
      await this.repository.recordConstitutionDecision(task.id, `CONSTITUTION_${decision.decision}`, payload);
      if (decision.decision === 'ALLOW') await this.handoffDispatch(task.id, 'SILENT');
    }
    return this.getDetail(organisationId, incidentId, siteScope);
  }

  async list(filter: IncidentListFilter): Promise<IncidentDetailView[]> {
    return (await this.repository.list(filter)).map(toIncidentView);
  }

  async getDetail(organisationId: string, incidentId: string, siteScope: SiteScope = SYSTEM_SITE_SCOPE): Promise<IncidentDetailView> {
    const row = await this.repository.detail(organisationId, incidentId, siteScope);
    if (!row) throw new NotFoundException('Incident not found');
    return { ...toIncidentView(row), timeline: row.timeline.map(toTimelineView), tasks: row.responseTasks.map(toTaskView) };
  }

  private async runProofA(
    incidentId: string,
    organisationId: string,
    siteId: string,
    responseMode: ResponseMode,
    supportingEventIds: string[],
    contradictingEventIds: string[],
  ): Promise<void> {
    const tasks = await this.repository.ensureProofATasks(incidentId);
    const taskByType = new Map(tasks.map((task) => [task.taskType, task]));
    const preserve = taskByType.get(TASK_PRESERVE_EVIDENCE);
    const notify = taskByType.get(TASK_NOTIFY_COMMANDER);
    const dispatch = taskByType.get(TASK_DISPATCH_FIELD);
    if (!preserve || !notify || !dispatch) throw new Error(`Playbook ${PLAYBOOK_PROOF_A_V1} tasks were not persisted`);

    if (!preserve.completedAt) {
      const eventIds = [...new Set([...supportingEventIds, ...contradictingEventIds])];
      await this.repository.claimEvidenceSnapshot(preserve.id);
      if (eventIds.length > 0) {
        const evidenceId = await this.evidence.preserveEventSnapshot({
          organisation_id: organisationId,
          incident_id: incidentId,
          event_ids: eventIds,
          actor: { kind: 'system' },
          response_task_id: preserve.id,
        });
        await this.repository.completeEvidenceSnapshot(preserve.id, evidenceId, { outcome: 'preserved', evidence_id: evidenceId });
      } else {
        await this.repository.completeEvidenceSnapshot(preserve.id, null, { outcome: 'skipped', reason: 'no_related_events' });
      }
    }
    // No external notification connector exists in M1. Its task remains
    // REQUESTED until an actual destination accepts it; a timeline entry must
    // never be used as a false delivery receipt.
    if (dispatch.deliveryState === 'REQUESTED') {
      const action = responseMode === 'SILENT' ? SILENT_DISPATCH_ACTION : STANDARD_DISPATCH_ACTION;
      const traceId = `incident:${incidentId}:task:${dispatch.id}:dispatch:${responseMode.toLowerCase()}`;
      const decision = await this.constitution.evaluate(
        {
          action,
          actor: {
            userId: RESPONSE_SYSTEM_ACTOR,
            roles: ['system.response'],
            organisationId,
            clearance: 5,
            purpose: `${responseMode.toLowerCase()}-response-dispatch`,
            deviceTrust: 'TRUSTED',
          },
          target: { organisationId, siteId, classification: 'SENSITIVE', classificationLevel: 2 },
        },
        { traceId },
      );
      const decisionPayload = JSON.parse(
        JSON.stringify({ task_id: dispatch.id, action, decision: decision.decision, trace_id: traceId, trace: decision.trace }),
      ) as Prisma.InputJsonValue;
      await this.repository.recordConstitutionDecision(dispatch.id, `CONSTITUTION_${decision.decision}`, decisionPayload);
      if (decision.decision === 'ALLOW') await this.handoffDispatch(dispatch.id, responseMode);
    }
  }

  private async handoffDispatch(taskId: string, responseMode: ResponseMode): Promise<void> {
    this.assertDeliveryTransition('REQUESTED', 'DELIVERED');
    const task = await this.repository.createLocalDispatchHandoff(taskId, responseMode);
    if (!task || task.deliveryState !== 'DELIVERED') throw new ConflictException('Local field dispatch handoff was not accepted');
  }

  private assertDeliveryTransition(from: DeliveryState, to: DeliveryState): void {
    if (!canTransition(from, to)) throw new ConflictException(`Illegal delivery-state transition ${from} -> ${to}`);
  }
}
