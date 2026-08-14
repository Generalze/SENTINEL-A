import { createHash } from 'node:crypto';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { EvidenceObjectStoreProvider } from './evidence-object-store.provider';
import { EvidenceRepository } from './evidence.repository';
import { EvidenceService } from './evidence.service';
import { PrismaService } from '../../prisma/prisma.service';
import { makeAppConfig, uniqueOrgId } from './test-integration-support';
import { makeIngestInput } from './test-fixtures';

/**
 * Live-stack integration tests for WP-09 acceptance criteria 1 and 2.
 * Requires the compose stack's Postgres (localhost:5433) and MinIO
 * (localhost:9000) to be reachable. Constructs the real
 * EvidenceService -> EvidenceRepository/EvidenceObjectStoreProvider stack
 * directly (bypassing full Nest DI bootstrap), the same way
 * modules/events/events.ingest.integration.spec.ts does.
 */
describe('Evidence ingest (live stack)', () => {
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

  beforeAll(async () => {
    await prisma.$connect();
    await objectStore.ensureBucket();
  });

  afterEach(async () => {
    if (trackedOrgIds.length > 0) {
      await prisma.evidenceCustodyEvent.deleteMany({ where: { evidence: { organisationId: { in: trackedOrgIds } } } });
      await prisma.evidence.deleteMany({ where: { organisationId: { in: trackedOrgIds } } });
      trackedOrgIds.length = 0;
    }
  });

  afterAll(async () => {
    await prisma.onModuleDestroy();
  });

  it('AC1: the stored content_hash matches an independently computed SHA-256 of the exact bytes ingested', async () => {
    const orgId = trackOrg('ac1');
    const content = Buffer.from(`ac1-content-${Date.now()}`, 'utf8');
    const independentHash = createHash('sha256').update(content).digest('hex');

    const evidence = await service.ingest(makeIngestInput({ organisation_id: orgId, content }));

    expect(evidence.content_hash).toBe(independentHash);

    // And the bytes actually stored at object_key hash to the same value —
    // not just the value the service happened to compute in memory.
    const stored = await objectStore.getObject(evidence.object_key);
    expect(createHash('sha256').update(stored).digest('hex')).toBe(independentHash);
    expect(stored.equals(content)).toBe(true);

    const custody = await prisma.evidenceCustodyEvent.findMany({ where: { evidenceId: evidence.id } });
    expect(custody).toHaveLength(1);
    expect(custody[0].action).toBe('INGESTED');
  });

  it('AC2: ingesting byte-identical content twice produces two distinct evidence ids/object keys, and both objects are independently retrievable (no overwrite)', async () => {
    const orgId = trackOrg('ac2');
    const content = Buffer.from(`ac2-shared-content-${Date.now()}`, 'utf8');
    const input = makeIngestInput({ organisation_id: orgId, content, source_id: 'camera-ac2' });

    const first = await service.ingest(input);
    const second = await service.ingest(input);

    expect(first.id).not.toBe(second.id);
    expect(first.object_key).not.toBe(second.object_key);
    // Same content -> same hash, by construction; the point of AC2 is that
    // this never causes the two ingests to collapse into one row/object.
    expect(first.content_hash).toBe(second.content_hash);

    const rows = await prisma.evidence.findMany({ where: { organisationId: orgId } });
    expect(rows).toHaveLength(2);
    expect(new Set(rows.map((r) => r.objectKey)).size).toBe(2);

    const firstStored = await objectStore.getObject(first.object_key);
    const secondStored = await objectStore.getObject(second.object_key);
    expect(firstStored.equals(content)).toBe(true);
    expect(secondStored.equals(content)).toBe(true);
  });

  it('AC2 (service surface): EvidenceService exposes no update/replace method for an existing evidence object', () => {
    const serviceMethods = Object.getOwnPropertyNames(EvidenceService.prototype);
    const forbidden = serviceMethods.filter((name) => /update|replace|overwrite/i.test(name));
    expect(forbidden).toEqual([]);
  });
});
