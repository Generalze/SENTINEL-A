import { ForbiddenException } from '@nestjs/common';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { EvidenceController } from './evidence.controller';
import { EvidenceObjectStoreProvider } from './evidence-object-store.provider';
import { EvidenceRepository } from './evidence.repository';
import { EvidenceService } from './evidence.service';
import { PrismaService } from '../../prisma/prisma.service';
import { makeAppConfig, makeCapturingRes, principalRequest, uniqueOrgId } from './test-integration-support';
import { makeIngestInput } from './test-fixtures';

/**
 * Live-stack integration test for WP-09 acceptance criterion 4: content
 * download is denied without a purpose and custody-logged (VIEWED) when a
 * purpose is supplied. Exercises the real
 * EvidenceController -> EvidenceService -> EvidenceRepository/
 * EvidenceObjectStoreProvider stack against live Postgres + MinIO.
 */
describe('Evidence content download (live stack)', () => {
  const appConfig = makeAppConfig();
  const prisma = new PrismaService(appConfig);
  const objectStore = new EvidenceObjectStoreProvider(appConfig);
  const repository = new EvidenceRepository(prisma);
  const service = new EvidenceService(repository, objectStore);
  const controller = new EvidenceController(service);

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

  it('AC4: download without a purpose header is denied and writes no custody event', async () => {
    const orgId = trackOrg('ac4-denied');
    const evidence = await service.ingest(makeIngestInput({ organisation_id: orgId, content: Buffer.from('secret bytes', 'utf8') }));

    const req = principalRequest(orgId, 'investigator-1');
    const res = makeCapturingRes();

    await expect(controller.downloadContent(req, evidence.id, {}, res)).rejects.toBeInstanceOf(ForbiddenException);

    const custody = await prisma.evidenceCustodyEvent.findMany({ where: { evidenceId: evidence.id } });
    expect(custody.map((c) => c.action)).toEqual(['INGESTED']); // no VIEWED
  });

  it('AC4: download with a purpose header succeeds and writes a VIEWED custody entry carrying the purpose', async () => {
    const orgId = trackOrg('ac4-allowed');
    const content = Buffer.from('the real content bytes', 'utf8');
    const evidence = await service.ingest(makeIngestInput({ organisation_id: orgId, content, content_type: 'text/plain' }));

    const req = principalRequest(orgId, 'investigator-2', 'it-trace', { 'x-purpose': 'incident response' });
    const res = makeCapturingRes();

    await controller.downloadContent(req, evidence.id, {}, res);

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('text/plain');
    expect(res.endedBuffer?.equals(content)).toBe(true);

    const custody = await prisma.evidenceCustodyEvent.findMany({ where: { evidenceId: evidence.id }, orderBy: { at: 'asc' } });
    expect(custody.map((c) => c.action)).toEqual(['INGESTED', 'VIEWED']);
    const viewed = custody[1];
    expect(viewed.actorKind).toBe('user');
    expect(viewed.actorId).toBe('investigator-2');
    expect((viewed.detail as Record<string, unknown>).purpose).toBe('incident response');
  });
});
