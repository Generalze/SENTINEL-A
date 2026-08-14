import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { Event as EventRow, Prisma } from '@prisma/client';
import { EvidenceObjectStoreProvider } from './evidence-object-store.provider';
import { EvidenceRepository } from './evidence.repository';
import { EvidenceService } from './evidence.service';
import { PrismaService } from '../../prisma/prisma.service';
import { makeAppConfig, uniqueOrgId } from './test-integration-support';

/**
 * Live-stack integration test for WP-09 acceptance criterion 5:
 * preserveEventSnapshot() round-trips — the stored snapshot content
 * parses back to exactly the events that were requested. Creates real
 * Event rows directly via the shared Prisma client (the events module's
 * table, read-only from this module's perspective — see
 * evidence.repository.ts's findEventsByIds doc comment) rather than
 * importing anything from modules/events.
 */
describe('preserveEventSnapshot (live stack)', () => {
  const appConfig = makeAppConfig();
  const prisma = new PrismaService(appConfig);
  const objectStore = new EvidenceObjectStoreProvider(appConfig);
  const repository = new EvidenceRepository(prisma);
  const service = new EvidenceService(repository, objectStore);

  const trackedOrgIds: string[] = [];
  function trackOrg(label: string): string {
    const id = uniqueOrgId(label);
    trackedOrgIds.push(id);
    return id;
  }

  async function makeEvent(organisationId: string, overrides: Partial<Prisma.EventUncheckedCreateInput> = {}): Promise<EventRow> {
    const now = new Date();
    return prisma.event.create({
      data: {
        eventId: `evt_snap_${Date.now()}_${Math.random().toString(36).slice(2)}`,
        schemaVersion: 1,
        organisationId,
        siteId: 'site-snap',
        sourceType: 'camera',
        sourceId: 'camera-snap',
        sourceTrust: 'trusted',
        eventType: 'motion.detected',
        confidence: 0.75,
        occurredAt: now,
        ingestedAt: now,
        location: { lat: 1.23, lng: 4.56 },
        trackIds: ['track-1'],
        evidenceRefs: [],
        metadata: { note: 'snapshot fixture' },
        traceId: `trace-snap-${Date.now()}`,
        ...overrides,
      },
    });
  }

  beforeAll(async () => {
    await prisma.$connect();
    await objectStore.ensureBucket();
  });

  afterEach(async () => {
    if (trackedOrgIds.length > 0) {
      await prisma.evidenceCustodyEvent.deleteMany({ where: { evidence: { organisationId: { in: trackedOrgIds } } } });
      await prisma.evidence.deleteMany({ where: { organisationId: { in: trackedOrgIds } } });
      await prisma.event.deleteMany({ where: { organisationId: { in: trackedOrgIds } } });
      trackedOrgIds.length = 0;
    }
  });

  afterAll(async () => {
    await prisma.onModuleDestroy();
  });

  it('AC5: snapshot content parses back to exactly the requested events', async () => {
    const orgId = trackOrg('ac5');
    const eventA = await makeEvent(orgId, { eventType: 'motion.detected' });
    const eventB = await makeEvent(orgId, { eventType: 'access.denied' });

    const evidenceId = await service.preserveEventSnapshot({
      organisation_id: orgId,
      incident_id: 'incident-ac5',
      event_ids: [eventA.id, eventB.id],
      actor: { kind: 'user', id: 'investigator-3' },
    });

    const evidenceRow = await prisma.evidence.findUniqueOrThrow({ where: { id: evidenceId } });
    expect(evidenceRow.classification).toBe('EVIDENCE');
    expect(evidenceRow.incidentId).toBe('incident-ac5');
    expect(evidenceRow.relatedEventIds.sort()).toEqual([eventA.id, eventB.id].sort());

    const stored = await objectStore.getObject(evidenceRow.objectKey);
    const parsed = JSON.parse(stored.toString('utf8')) as { organisation_id: string; incident_id: string; events: Array<Record<string, unknown>> };

    expect(parsed.organisation_id).toBe(orgId);
    expect(parsed.incident_id).toBe('incident-ac5');
    expect(parsed.events).toHaveLength(2);
    expect(parsed.events.map((e) => e.id)).toEqual([eventA.id, eventB.id]);
    expect(parsed.events.map((e) => e.event_id)).toEqual([eventA.eventId, eventB.eventId]);
    expect(parsed.events[0].event_type).toBe('motion.detected');
    expect(parsed.events[1].event_type).toBe('access.denied');
    expect(parsed.events[0].location).toEqual({ lat: 1.23, lng: 4.56 });
    expect(parsed.events[0].occurred_at).toBe(eventA.occurredAt.toISOString());

    // The snapshot ingest itself goes through the normal write path: hash matches, custody INGESTED recorded.
    expect(evidenceRow.contentHash).toBeTruthy();
    const custody = await prisma.evidenceCustodyEvent.findMany({ where: { evidenceId } });
    expect(custody.map((c) => c.action)).toEqual(['INGESTED']);
  });

  it('AC5: fails loudly instead of silently omitting an event id that does not belong to this organisation', async () => {
    const orgId = trackOrg('ac5-cross-tenant');
    const otherOrgId = trackOrg('ac5-other-org');
    const foreignEvent = await makeEvent(otherOrgId);

    await expect(
      service.preserveEventSnapshot({ organisation_id: orgId, incident_id: 'incident-x', event_ids: [foreignEvent.id], actor: { kind: 'system' } }),
    ).rejects.toThrow(/not found/i);

    const rows = await prisma.evidence.findMany({ where: { organisationId: orgId } });
    expect(rows).toHaveLength(0);
  });
});
