import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { JSONCodec } from 'nats';
import { EvidenceObjectStoreProvider } from '../evidence/evidence-object-store.provider';
import { EvidenceRepository } from '../evidence/evidence.repository';
import { EvidenceService } from '../evidence/evidence.service';
import { NatsProvider } from '../../infra/nats.provider';
import { PrismaService } from '../../prisma/prisma.service';
import { makeAppConfig, uniqueOrgId } from '../evidence/test-integration-support';
import { IncidentsPublisher } from './incidents.publisher';
import { IncidentsRepository } from './incidents.repository';
import { IncidentsService } from './incidents.service';

describe('WP-07 incident response (live stack)', () => {
  const config = makeAppConfig();
  const prisma = new PrismaService(config);
  // A separate client gives the regression a genuinely concurrent database
  // session even in constrained local test runners with a single-client pool.
  const concurrentPrisma = new PrismaService(config);
  const objectStore = new EvidenceObjectStoreProvider(config);
  const evidence = new EvidenceService(new EvidenceRepository(prisma), objectStore);
  const nats = new NatsProvider(config);
  const repository = new IncidentsRepository(prisma);
  const concurrentRepository = new IncidentsRepository(concurrentPrisma);
  const incidents = new IncidentsService(
    repository,
    evidence,
    { evaluate: async () => ({ decision: 'ALLOW', trace: [] }) } as never,
    new IncidentsPublisher(nats),
  );
  const orgIds: string[] = [];

  beforeAll(async () => {
    await prisma.$connect();
    await concurrentPrisma.$connect();
    await objectStore.ensureBucket();
  });

  afterEach(async () => {
    const organisationId = orgIds.pop();
    if (!organisationId) return;
    await prisma.evidenceCustodyEvent.deleteMany({ where: { evidence: { organisationId } } });
    await prisma.evidence.deleteMany({ where: { organisationId } });
    await prisma.responseDispatchHandoff.deleteMany({ where: { task: { incident: { organisationId } } } });
    await prisma.incidentUpdateOutbox.deleteMany({ where: { organisationId } });
    await prisma.incidentTimelineEntry.deleteMany({ where: { incident: { organisationId } } });
    await prisma.responseTask.deleteMany({ where: { incident: { organisationId } } });
    await prisma.incident.deleteMany({ where: { organisationId } });
    await prisma.event.deleteMany({ where: { organisationId } });
  });

  afterAll(async () => {
    await nats.onModuleDestroy();
    await concurrentPrisma.onModuleDestroy();
    await prisma.onModuleDestroy();
  });

  it('AC1/2/5: candidate creates one incident, preserves both evidence sides, is duplicate-safe, and ack publishes an update', async () => {
    const organisationId = uniqueOrgId('wp07-live');
    orgIds.push(organisationId);
    const now = new Date();
    const supporting = await prisma.event.create({
      data: {
        eventId: `evt-support-${Date.now()}`, schemaVersion: 1, organisationId, siteId: 'site-live', sourceType: 'camera', sourceId: 'cam-live', sourceTrust: 'trusted',
        eventType: 'motion_detected', confidence: 0.9, occurredAt: now, ingestedAt: now, location: {}, trackIds: [], evidenceRefs: [], metadata: {}, traceId: 'trace-live-support',
      },
    });
    const contradicting = await prisma.event.create({
      data: {
        eventId: `evt-contradict-${Date.now()}`, schemaVersion: 1, organisationId, siteId: 'site-live', sourceType: 'access', sourceId: 'access-live', sourceTrust: 'trusted',
        eventType: 'access_granted_valid', confidence: 0.8, occurredAt: now, ingestedAt: now, location: {}, trackIds: [], evidenceRefs: [], metadata: {}, traceId: 'trace-live-contradict',
      },
    });
    const candidate = {
      schema_version: 1 as const, incident_candidate_id: '00000000-0000-4000-8000-000000000011', hypothesis_id: '00000000-0000-4000-8000-000000000012',
      organisation_id: organisationId, site_id: 'site-live', zone_id: null, threat_state: 4 as const, detection_confidence: 0.9, threat_probability: 0.9,
      potential_impact: 'HIGH' as const, operational_severity: 'SEV1' as const, supporting_event_ids: [supporting.eventId], contradicting_event_ids: [contradicting.eventId],
      confidence_explanation: 'live test', rule_or_model_versions: ['fusion-rules-1.0.0'], re_escalation: false, emission_number: 1, triggering_event_id: supporting.eventId, emitted_at: now.toISOString(),
      hypothesis_version: 1,
    };

    const first = await incidents.handleCandidate(candidate);
    const second = await incidents.handleCandidate(candidate);
    expect(first.id).toBe(second.id);
    expect(await prisma.incident.count({ where: { organisationId } })).toBe(1);
    expect(await prisma.incidentUpdateOutbox.count({ where: { organisationId } })).toBeGreaterThan(0);
    expect(first.supporting_event_ids).toEqual([supporting.eventId]);
    expect(first.contradicting_event_ids).toEqual([contradicting.eventId]);
    const preserve = first.tasks.find((task) => task.task_type === 'preserve-evidence');
    const dispatch = first.tasks.find((task) => task.task_type === 'dispatch-field');
    expect(preserve?.completed_at).not.toBeNull();
    expect(dispatch?.delivery_state).toBe('DELIVERED');
    const snapshot = await prisma.evidence.findFirstOrThrow({ where: { responseTaskId: preserve?.id } });
    expect(snapshot.relatedEventIds.sort()).toEqual([supporting.id, contradicting.id].sort());

    const nc = await nats.getConnection();
    const sub = nc.subscribe(`sentinel.incidents.updated.${organisationId}`);
    const received = (async () => {
      for await (const message of sub) return JSONCodec<{ id: string }>().decode(message.data);
      throw new Error('subscription ended before incident update');
    })();
    await incidents.acknowledge(organisationId, first.id, dispatch!.id, 'field-live', { orgWide: false, siteIds: ['site-live'] });
    await nc.flush();
    await expect(received).resolves.toMatchObject({ id: first.id });
    sub.unsubscribe();
  }, 30_000);

  it('uses a strict Fusion version CAS for equal-time out-of-order concurrent updates and starts Proof-A once', async () => {
    const organisationId = uniqueOrgId('wp13-version-cas');
    orgIds.push(organisationId);
    const hypothesisId = randomUUID();
    const at = new Date();
    const { incident } = await repository.createFromCandidate({
      hypothesisId,
      incidentCandidateId: randomUUID(),
      organisationId,
      siteId: 'site-live',
      incidentType: 'fusion.hypothesis',
      severity: 'SEV3',
      threatState: 2,
      confidence: 0.4,
      responseMode: 'STANDARD',
      relatedEventIds: [],
      supportingEventIds: [],
      contradictingEventIds: [],
      hypothesisUpdatedAt: at,
      hypothesisVersion: 1,
    });
    const common = { hypothesisId, organisationId, sourceAt: at, supportingEventIds: [], contradictingEventIds: [] };
    const older = repository.advanceFromHypothesis({
      ...common, triggeringEventId: 'event-equal-time-old', hypothesisVersion: 2, state: 3, severity: 'SEV3', confidence: 0.7,
    });
    const newer = concurrentRepository.advanceFromHypothesis({
      ...common, triggeringEventId: 'event-equal-time-new', hypothesisVersion: 3, state: 4, severity: 'SEV2', confidence: 0.95,
    });
    await Promise.all([older, newer]);
    // An at-least-once replay of the highest version must be a true no-op.
    await expect(repository.advanceFromHypothesis({
      ...common, triggeringEventId: 'event-equal-time-new-replay', hypothesisVersion: 3, state: 4, severity: 'SEV2', confidence: 0.95,
    })).resolves.toBeNull();

    const current = await prisma.incident.findUniqueOrThrow({ where: { id: incident.id }, include: { responseTasks: true, timeline: true } });
    expect(current.hypothesisVersion).toBe(3);
    expect(current.hypothesisTriggeringEventId).toBe('event-equal-time-new');
    expect(current.severity).toBe('SEV2');
    expect(current.responseTasks).toHaveLength(3);
    expect(current.timeline.filter((entry) => (entry.payload as unknown as { playbook_started?: string }).playbook_started === 'PB-PROOF-A@1')).toHaveLength(1);
  });
});
