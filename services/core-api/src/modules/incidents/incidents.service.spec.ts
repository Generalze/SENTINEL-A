import { BadRequestException, ConflictException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import type { IncidentCandidateMessage } from '../fusion/fusion.types';
import { IncidentsService, responseModeForCandidate } from './incidents.service';

function candidate(ruleVersions: string[] = ['fusion-rules-1.0.0']): IncidentCandidateMessage {
  return {
    schema_version: 1,
    incident_candidate_id: '00000000-0000-4000-8000-000000000001',
    hypothesis_id: '00000000-0000-4000-8000-000000000002',
    organisation_id: 'org-a',
    site_id: 'site-a',
    zone_id: null,
    threat_state: 4,
    detection_confidence: 0.9,
    threat_probability: 0.9,
    potential_impact: 'HIGH',
    operational_severity: 'SEV1',
    supporting_event_ids: [],
    contradicting_event_ids: [],
    confidence_explanation: 'test',
    rule_or_model_versions: ruleVersions,
    re_escalation: false,
    emission_number: 1,
    triggering_event_id: 'event-a',
    emitted_at: '2026-08-16T09:00:00.000Z',
  };
}

describe('IncidentsService', () => {
  it('selects SILENT only when a versioned rule-pack marker explicitly flags coercion or duress', () => {
    expect(responseModeForCandidate(candidate())).toBe('STANDARD');
    expect(responseModeForCandidate(candidate(['fusion-rules-1.0.0', 'family:duress']))).toBe('SILENT');
  });

  it('rejects an illegal REQUESTED -> ACKNOWLEDGED delivery transition', async () => {
    const repository = {
      findTask: vi.fn().mockResolvedValue({ id: 'task-a', taskType: 'dispatch-field', deliveryState: 'REQUESTED' }),
    };
    const service = new IncidentsService(repository as never, {} as never, {} as never, {} as never);

    const scope = { orgWide: false, siteIds: ['site-a'] };
    await expect(service.acknowledge('org-a', 'incident-a', 'task-a', 'field-user', scope)).rejects.toBeInstanceOf(ConflictException);
    expect(repository.findTask).toHaveBeenCalledWith('incident-a', 'task-a', 'org-a', scope);
  });

  it('persists acknowledgement actor/time once and makes an ACK retry a no-op', async () => {
    const scope = { orgWide: false, siteIds: ['site-a'] };
    const repository = {
      findTask: vi
        .fn()
        .mockResolvedValueOnce({ id: 'task-a', taskType: 'dispatch-field', deliveryState: 'DELIVERED' })
        .mockResolvedValueOnce({ id: 'task-a', taskType: 'dispatch-field', deliveryState: 'ACKNOWLEDGED' }),
      acknowledgeTask: vi.fn().mockResolvedValue({ id: 'task-a', deliveryState: 'ACKNOWLEDGED' }),
      appendTimeline: vi.fn(),
    };
    const publisher = { publishUpdated: vi.fn() };
    const service = new IncidentsService(repository as never, {} as never, {} as never, publisher as never);
    const detail = { id: 'incident-a', organisation_id: 'org-a' } as never;
    vi.spyOn(service, 'getDetail').mockResolvedValue(detail);

    await expect(service.acknowledge('org-a', 'incident-a', 'task-a', 'field-user', scope)).resolves.toBe(detail);
    expect(repository.acknowledgeTask).toHaveBeenCalledWith('task-a', 'field-user', expect.any(Date));
    expect(repository.appendTimeline).not.toHaveBeenCalled();
    expect(publisher.publishUpdated).toHaveBeenCalledOnce();

    await expect(service.acknowledge('org-a', 'incident-a', 'task-a', 'other-field-user', scope)).resolves.toBe(detail);
    expect(repository.acknowledgeTask).toHaveBeenCalledOnce();
    expect(repository.appendTimeline).not.toHaveBeenCalled();
  });

  it('requires a closure reason before attempting contained -> closed', async () => {
    const service = new IncidentsService({} as never, {} as never, {} as never, {} as never);
    vi.spyOn(service, 'getDetail').mockResolvedValue({ status: 'contained' } as never);

    await expect(
      service.transitionStatus('org-a', 'incident-a', { orgWide: true, siteIds: [] }, { status: 'closed', actorUserId: 'commander' }),
    ).rejects.toBeInstanceOf(BadRequestException);
  });

  it('keeps automatic evidence completion separate from delivery state and snapshots both evidence sides', async () => {
    const input = { ...candidate(), supporting_event_ids: ['supporting-1'], contradicting_event_ids: ['contradicting-1'] };
    const incident = {
      id: 'incident-a', organisationId: 'org-a', siteId: 'site-a', severity: 'SEV1',
      supportingEventIds: ['supporting-1'], contradictingEventIds: ['contradicting-1'],
    };
    const preserve = { id: 'preserve-task', taskType: 'preserve-evidence', deliveryState: 'REQUESTED', completedAt: null };
    const notify = { id: 'notify-task', taskType: 'notify-commander', deliveryState: 'REQUESTED', completedAt: null };
    const dispatch = { id: 'dispatch-task', taskType: 'dispatch-field', deliveryState: 'REQUESTED', completedAt: null };
    const repository = {
      createFromCandidate: vi.fn().mockResolvedValue({ incident }),
      ensureProofATasks: vi.fn().mockResolvedValue([preserve, notify, dispatch]),
      claimEvidenceSnapshot: vi.fn(),
      completeEvidenceSnapshot: vi.fn(),
      createLocalDispatchHandoff: vi.fn().mockResolvedValue({ id: dispatch.id, deliveryState: 'DELIVERED' }),
      appendTimeline: vi.fn(),
      recordConstitutionDecision: vi.fn(),
    };
    const evidence = { preserveEventSnapshot: vi.fn().mockResolvedValue('evidence-a') };
    const publisher = { publishUpdated: vi.fn() };
    const constitution = { evaluate: vi.fn().mockResolvedValue({ decision: 'ALLOW', trace: [] }) };
    const service = new IncidentsService(repository as never, evidence as never, constitution as never, publisher as never);
    vi.spyOn(service, 'getDetail').mockResolvedValue({ id: incident.id, organisation_id: incident.organisationId } as never);

    await service.handleCandidate(input);

    expect(repository.createFromCandidate).toHaveBeenCalledWith(expect.objectContaining({
      supportingEventIds: ['supporting-1'],
      contradictingEventIds: ['contradicting-1'],
      relatedEventIds: ['supporting-1', 'contradicting-1'],
    }));
    expect(evidence.preserveEventSnapshot).toHaveBeenCalledWith(expect.objectContaining({
      event_ids: ['supporting-1', 'contradicting-1'], response_task_id: preserve.id,
    }));
    expect(repository.completeEvidenceSnapshot).toHaveBeenCalledWith(
      preserve.id,
      'evidence-a',
      { outcome: 'preserved', evidence_id: 'evidence-a' },
    );
    expect(repository.createLocalDispatchHandoff).toHaveBeenCalledWith(dispatch.id, 'STANDARD');
    expect(constitution.evaluate).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'response.dispatch.standard', target: expect.objectContaining({ classificationLevel: 2 }) }),
      expect.objectContaining({ traceId: `incident:${incident.id}:task:${dispatch.id}:dispatch:standard` }),
    );
    expect(repository.appendTimeline).not.toHaveBeenCalledWith(
      expect.anything(),
      'COMMANDER_NOTIFICATION_DELIVERED',
      expect.anything(),
    );
  });

  it('keeps a SILENT dispatch REQUESTED when Constitution requires two-person approval', async () => {
    const input = candidate(['family:duress']);
    const incident = { id: 'incident-silent', organisationId: 'org-a', siteId: 'site-a', severity: 'SEV1', supportingEventIds: [], contradictingEventIds: [] };
    const preserve = { id: 'preserve-silent', taskType: 'preserve-evidence', deliveryState: 'REQUESTED', completedAt: null };
    const notify = { id: 'notify-silent', taskType: 'notify-commander', deliveryState: 'REQUESTED', completedAt: null };
    const dispatch = { id: 'dispatch-silent', taskType: 'dispatch-field', deliveryState: 'REQUESTED', completedAt: null };
    const repository = {
      createFromCandidate: vi.fn().mockResolvedValue({ incident }), ensureProofATasks: vi.fn().mockResolvedValue([preserve, notify, dispatch]),
      claimEvidenceSnapshot: vi.fn(), completeEvidenceSnapshot: vi.fn(), appendTimeline: vi.fn(), createLocalDispatchHandoff: vi.fn(),
      recordConstitutionDecision: vi.fn(),
    };
    const constitution = { evaluate: vi.fn().mockResolvedValue({ decision: 'REQUIRE_TWO_PERSON', trace: [] }) };
    const service = new IncidentsService(repository as never, {} as never, constitution as never, { publishUpdated: vi.fn() } as never);
    vi.spyOn(service, 'getDetail').mockResolvedValue({ id: incident.id, organisation_id: incident.organisationId } as never);

    await service.handleCandidate(input);

    expect(constitution.evaluate).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'response.dispatch.silent', target: expect.objectContaining({ classificationLevel: 2 }) }),
      expect.objectContaining({ traceId: `incident:${incident.id}:task:${dispatch.id}:dispatch:silent` }),
    );
    expect(repository.createLocalDispatchHandoff).not.toHaveBeenCalled();
    expect(repository.recordConstitutionDecision).toHaveBeenCalledWith(
      dispatch.id,
      'CONSTITUTION_REQUIRE_TWO_PERSON',
      expect.objectContaining({ trace_id: `incident:${incident.id}:task:${dispatch.id}:dispatch:silent` }),
    );
  });

  it('does not re-evaluate a duplicate SILENT approval retry', async () => {
    const scope = { orgWide: false, siteIds: ['site-a'] };
    const task = {
      id: 'dispatch-silent', taskType: 'dispatch-field', deliveryState: 'REQUESTED',
      incident: { responseMode: 'SILENT', siteId: 'site-a' },
    };
    const repository = {
      findTask: vi.fn().mockResolvedValue(task),
      recordSilentApproval: vi.fn().mockResolvedValue(false),
      listSilentApprovals: vi.fn(),
    };
    const constitution = { evaluate: vi.fn() };
    const service = new IncidentsService(repository as never, {} as never, constitution as never, {} as never);
    const detail = { id: 'incident-silent', organisation_id: 'org-a' } as never;
    vi.spyOn(service, 'getDetail').mockResolvedValue(detail);

    await expect(service.approveSilentDispatch('org-a', 'incident-silent', task.id, 'commander-a', scope)).resolves.toBe(detail);

    expect(repository.recordSilentApproval).toHaveBeenCalledWith(task.id, 'commander-a');
    expect(repository.listSilentApprovals).not.toHaveBeenCalled();
    expect(constitution.evaluate).not.toHaveBeenCalled();
  });
});
