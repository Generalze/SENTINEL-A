import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { EvidenceObjectStoreProvider } from './evidence-object-store.provider';
import { EvidenceRepository } from './evidence.repository';
import { EvidenceService } from './evidence.service';
import { PrismaService } from '../../prisma/prisma.service';
import { makeAppConfig, uniqueOrgId } from './test-integration-support';
import { makeIngestInput } from './test-fixtures';

/**
 * Live-stack integration test for WP-09 acceptance criterion 3: tamper
 * detection. The tamper is performed with a *direct* S3 client (bypassing
 * EvidenceObjectStoreProvider/EvidenceService entirely) issuing a raw
 * `PutObjectCommand` at the exact same bucket+key an ingest already wrote
 * to — simulating an attacker (or a storage-layer bug) with direct object
 * store access, which is a scenario this module's application-level "no
 * overwrite method" guarantee cannot prevent by itself. verify() must
 * still catch it.
 */
describe('Evidence integrity verification (live stack)', () => {
  const appConfig = makeAppConfig();
  const prisma = new PrismaService(appConfig);
  const objectStore = new EvidenceObjectStoreProvider(appConfig);
  const repository = new EvidenceRepository(prisma);
  const service = new EvidenceService(repository, objectStore);

  // A raw client used only to simulate an attacker's direct-to-storage tamper write.
  const rawS3 = new S3Client({
    endpoint: appConfig.values.S3_ENDPOINT,
    region: appConfig.values.S3_REGION,
    forcePathStyle: true,
    credentials: { accessKeyId: appConfig.values.S3_ACCESS_KEY, secretAccessKey: appConfig.values.S3_SECRET_KEY },
  });

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

  it('AC3: verify() succeeds (VERIFIED) on an untampered object', async () => {
    const orgId = trackOrg('ac3-ok');
    const evidence = await service.ingest(makeIngestInput({ organisation_id: orgId }));

    const result = await service.verify(evidence.id, orgId, { kind: 'system' });

    expect(result.verified).toBe(true);
    const custody = await prisma.evidenceCustodyEvent.findMany({ where: { evidenceId: evidence.id }, orderBy: { at: 'asc' } });
    expect(custody.map((c) => c.action)).toEqual(['INGESTED', 'VERIFIED']);
  });

  it('AC3: verify() detects a tampered object (direct S3 overwrite of the same key) and records VERIFY_FAILED custody', async () => {
    const orgId = trackOrg('ac3-tamper');
    const evidence = await service.ingest(makeIngestInput({ organisation_id: orgId, content: Buffer.from('original bytes', 'utf8') }));

    // Attacker/storage-layer tamper: overwrite the exact same key directly.
    await rawS3.send(
      new PutObjectCommand({
        Bucket: appConfig.values.S3_EVIDENCE_BUCKET,
        Key: evidence.object_key,
        Body: Buffer.from('TAMPERED BYTES', 'utf8'),
        ContentType: evidence.content_type,
      }),
    );

    const result = await service.verify(evidence.id, orgId, { kind: 'user', id: 'investigator-1' });

    expect(result.verified).toBe(false);
    expect(result.expected_hash).toBe(evidence.content_hash);
    expect(result.actual_hash).not.toBe(evidence.content_hash);

    const custody = await prisma.evidenceCustodyEvent.findMany({ where: { evidenceId: evidence.id }, orderBy: { at: 'asc' } });
    expect(custody.map((c) => c.action)).toEqual(['INGESTED', 'VERIFY_FAILED']);
    const failure = custody[1];
    expect(failure.actorKind).toBe('user');
    expect(failure.actorId).toBe('investigator-1');
    expect((failure.detail as Record<string, unknown>).expected_hash).toBe(evidence.content_hash);
  });
});
