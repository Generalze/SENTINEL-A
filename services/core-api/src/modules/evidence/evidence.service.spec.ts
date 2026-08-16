import { ForbiddenException, NotFoundException } from '@nestjs/common';
import { Prisma, type Event as EventRow, Evidence as EvidenceRow, EvidenceCustodyEvent as CustodyRow } from '@prisma/client';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { sha256Hex } from './evidence.hash';
import type { EvidenceObjectStoreProvider } from './evidence-object-store.provider';
import type { EvidenceRepository } from './evidence.repository';
import { EvidenceService } from './evidence.service';
import { makeIngestInput } from './test-fixtures';

function buildEvidenceRow(overrides: Partial<EvidenceRow> = {}): EvidenceRow {
  return {
    id: 'ev-1',
    organisationId: 'org-1',
    sourceId: 'camera-1',
    objectKey: 'org-1/ev-1',
    contentHash: 'hash-1',
    sizeBytes: 10,
    contentType: 'application/octet-stream',
    classification: 'EVIDENCE',
    derivedFromEvidenceId: null,
    incidentId: null,
    responseTaskId: null,
    relatedEventIds: [],
    capturedAt: new Date('2026-01-01T00:00:00.000Z'),
    storedAt: new Date('2026-01-01T00:00:01.000Z'),
    ...overrides,
  } as EvidenceRow;
}

function buildCustodyRow(overrides: Partial<CustodyRow> = {}): CustodyRow {
  return {
    id: 'cust-1',
    evidenceId: 'ev-1',
    at: new Date(),
    actorKind: 'system',
    actorId: 'system:evidence-vault',
    action: 'INGESTED',
    detail: {},
    ...overrides,
  } as CustodyRow;
}

function buildEventRow(overrides: Partial<EventRow> = {}): EventRow {
  return {
    id: 'evt-uuid-1',
    eventId: 'evt_1',
    schemaVersion: 1,
    organisationId: 'org-1',
    siteId: 'site-1',
    zoneId: null,
    sourceType: 'camera',
    sourceId: 'camera-1',
    sourceTrust: 'trusted',
    eventType: 'motion.detected',
    confidence: 0.9,
    occurredAt: new Date('2026-01-01T00:00:00.000Z'),
    ingestedAt: new Date('2026-01-01T00:00:01.000Z'),
    location: {},
    trackIds: [],
    evidenceRefs: [],
    metadata: {},
    traceId: 'trace-1',
    idempotencyKey: null,
    duplicateOfEventId: null,
    receivedCount: 1,
    publishedAt: null,
    createdAt: new Date(),
    ...overrides,
  } as EventRow;
}

function makeRepository(): EvidenceRepository {
  return {
    createEvidence: vi.fn(),
    createCustodyEvent: vi.fn(),
    findById: vi.fn(),
    list: vi.fn(),
    findEventsByIds: vi.fn(),
    findSnapshotForResponseTask: vi.fn(),
  } as unknown as EvidenceRepository;
}

function makeObjectStore(): EvidenceObjectStoreProvider {
  return {
    objectKeyFor: vi.fn((org: string, id: string) => `${org}/${id}`),
    putObject: vi.fn(),
    getObject: vi.fn(),
  } as unknown as EvidenceObjectStoreProvider;
}

describe('EvidenceService.ingest', () => {
  let repository: EvidenceRepository;
  let objectStore: EvidenceObjectStoreProvider;
  let service: EvidenceService;

  beforeEach(() => {
    repository = makeRepository();
    objectStore = makeObjectStore();
    service = new EvidenceService(repository, objectStore);
  });

  it('hashes the content, PUTs before creating the row, and writes an INGESTED custody event', async () => {
    const input = makeIngestInput({ content: Buffer.from('hello evidence', 'utf8') });
    const expectedHash = sha256Hex(input.content);
    const callOrder: string[] = [];
    vi.mocked(objectStore.putObject).mockImplementation(async () => {
      callOrder.push('put');
    });
    vi.mocked(repository.createEvidence).mockImplementation(async (data) => {
      callOrder.push('createEvidence');
      return buildEvidenceRow({ id: data.id as string, contentHash: expectedHash, sizeBytes: input.content.byteLength });
    });
    vi.mocked(repository.createCustodyEvent).mockImplementation(async () => {
      callOrder.push('custody');
      return buildCustodyRow();
    });

    const result = await service.ingest(input);

    expect(callOrder).toEqual(['put', 'createEvidence', 'custody']);
    expect(result.content_hash).toBe(expectedHash);

    const createArgs = vi.mocked(repository.createEvidence).mock.calls[0][0];
    expect(createArgs.contentHash).toBe(expectedHash);
    expect(createArgs.sizeBytes).toBe(input.content.byteLength);
    expect(createArgs.organisationId).toBe(input.organisation_id);

    const custodyArgs = vi.mocked(repository.createCustodyEvent).mock.calls[0][0];
    expect(custodyArgs.action).toBe('INGESTED');
    expect(custodyArgs.evidenceId).toBe(createArgs.id);
  });

  it('AC2: two ingests of byte-identical content produce two different object keys / evidence ids', async () => {
    const bytes = Buffer.from('same bytes', 'utf8');
    const input = makeIngestInput({ content: bytes });
    vi.mocked(repository.createEvidence).mockImplementation(async (data) => buildEvidenceRow({ id: data.id as string, objectKey: data.objectKey as string }));
    vi.mocked(repository.createCustodyEvent).mockResolvedValue(buildCustodyRow());

    await service.ingest(input);
    await service.ingest(input);

    const [firstArgs, secondArgs] = vi.mocked(repository.createEvidence).mock.calls.map((call) => call[0]);
    expect(firstArgs.id).not.toBe(secondArgs.id);
    expect(firstArgs.objectKey).not.toBe(secondArgs.objectKey);

    const [firstPutKey, secondPutKey] = vi.mocked(objectStore.putObject).mock.calls.map((call) => call[0]);
    expect(firstPutKey).not.toBe(secondPutKey);
  });

  it('attributes a user actor to the custody event when the caller carries one', async () => {
    const input = makeIngestInput({ actor: { kind: 'user', id: 'user-42' } });
    vi.mocked(repository.createEvidence).mockResolvedValue(buildEvidenceRow());
    vi.mocked(repository.createCustodyEvent).mockResolvedValue(buildCustodyRow());

    await service.ingest(input);

    const custodyArgs = vi.mocked(repository.createCustodyEvent).mock.calls[0][0];
    expect(custodyArgs.actorKind).toBe('user');
    expect(custodyArgs.actorId).toBe('user-42');
  });
});

describe('EvidenceService.derive', () => {
  let repository: EvidenceRepository;
  let objectStore: EvidenceObjectStoreProvider;
  let service: EvidenceService;

  beforeEach(() => {
    repository = makeRepository();
    objectStore = makeObjectStore();
    service = new EvidenceService(repository, objectStore);
  });

  it('creates a new row linked via derived_from_evidence_id with its own key/hash, and writes DERIVED on both rows', async () => {
    const original = buildEvidenceRow({ id: 'ev-original', objectKey: 'org-1/ev-original', classification: 'EVIDENCE' });
    vi.mocked(repository.findById).mockResolvedValue(original);
    vi.mocked(repository.createEvidence).mockImplementation(async (data) =>
      buildEvidenceRow({ id: data.id as string, objectKey: data.objectKey as string, derivedFromEvidenceId: data.derivedFromEvidenceId as string }),
    );
    vi.mocked(repository.createCustodyEvent).mockResolvedValue(buildCustodyRow());

    const result = await service.derive({
      evidence_id: original.id,
      organisation_id: original.organisationId,
      transform_label: 'thumbnail',
      content: Buffer.from('clip bytes', 'utf8'),
      content_type: 'image/png',
      actor: { kind: 'system' },
    });

    expect(result.derived_from_evidence_id).toBe(original.id);
    expect(result.id).not.toBe(original.id);

    const createArgs = vi.mocked(repository.createEvidence).mock.calls[0][0];
    expect(createArgs.objectKey).not.toBe(original.objectKey);

    const custodyCalls = vi.mocked(repository.createCustodyEvent).mock.calls.map((call) => call[0]);
    expect(custodyCalls).toHaveLength(2);
    expect(custodyCalls.every((c) => c.action === 'DERIVED')).toBe(true);
    expect(custodyCalls.some((c) => c.evidenceId === result.id)).toBe(true);
    expect(custodyCalls.some((c) => c.evidenceId === original.id)).toBe(true);
  });

  it('throws NotFoundException when the original does not exist in this organisation', async () => {
    vi.mocked(repository.findById).mockResolvedValue(null);

    await expect(
      service.derive({
        evidence_id: 'missing',
        organisation_id: 'org-1',
        transform_label: 'thumbnail',
        content: Buffer.from('x'),
        content_type: 'image/png',
        actor: { kind: 'system' },
      }),
    ).rejects.toBeInstanceOf(NotFoundException);
    expect(repository.createEvidence).not.toHaveBeenCalled();
  });
});

describe('EvidenceService.verify', () => {
  let repository: EvidenceRepository;
  let objectStore: EvidenceObjectStoreProvider;
  let service: EvidenceService;

  beforeEach(() => {
    repository = makeRepository();
    objectStore = makeObjectStore();
    service = new EvidenceService(repository, objectStore);
  });

  it('records VERIFIED when the re-downloaded content hashes to the stored hash', async () => {
    const content = Buffer.from('untampered', 'utf8');
    const row = buildEvidenceRow({ contentHash: sha256Hex(content) });
    vi.mocked(repository.findById).mockResolvedValue(row);
    vi.mocked(objectStore.getObject).mockResolvedValue(content);
    vi.mocked(repository.createCustodyEvent).mockResolvedValue(buildCustodyRow({ action: 'VERIFIED' }));

    const result = await service.verify(row.id, row.organisationId, { kind: 'system' });

    expect(result.verified).toBe(true);
    expect(result.actual_hash).toBe(row.contentHash);
    const custodyArgs = vi.mocked(repository.createCustodyEvent).mock.calls[0][0];
    expect(custodyArgs.action).toBe('VERIFIED');
  });

  it('AC3: records VERIFY_FAILED when the re-downloaded content hash differs (tampered object)', async () => {
    const row = buildEvidenceRow({ contentHash: sha256Hex(Buffer.from('original', 'utf8')) });
    vi.mocked(repository.findById).mockResolvedValue(row);
    vi.mocked(objectStore.getObject).mockResolvedValue(Buffer.from('tampered', 'utf8'));
    vi.mocked(repository.createCustodyEvent).mockResolvedValue(buildCustodyRow({ action: 'VERIFY_FAILED' }));

    const result = await service.verify(row.id, row.organisationId, { kind: 'system' });

    expect(result.verified).toBe(false);
    const custodyArgs = vi.mocked(repository.createCustodyEvent).mock.calls[0][0];
    expect(custodyArgs.action).toBe('VERIFY_FAILED');
    expect((custodyArgs.detail as Record<string, unknown>).expected_hash).toBe(row.contentHash);
  });

  it('records VERIFY_FAILED (not an unhandled rejection) when the object cannot be downloaded at all', async () => {
    const row = buildEvidenceRow();
    vi.mocked(repository.findById).mockResolvedValue(row);
    vi.mocked(objectStore.getObject).mockRejectedValue(new Error('NoSuchKey'));
    vi.mocked(repository.createCustodyEvent).mockResolvedValue(buildCustodyRow({ action: 'VERIFY_FAILED' }));

    const result = await service.verify(row.id, row.organisationId, { kind: 'system' });

    expect(result.verified).toBe(false);
    expect(result.actual_hash).toContain('NoSuchKey');
  });
});

describe('EvidenceService.preserveEventSnapshot', () => {
  let repository: EvidenceRepository;
  let objectStore: EvidenceObjectStoreProvider;
  let service: EvidenceService;

  beforeEach(() => {
    repository = makeRepository();
    objectStore = makeObjectStore();
    service = new EvidenceService(repository, objectStore);
  });

  it('ingests a canonical-JSON snapshot of the requested events as classification EVIDENCE and returns the new evidence id', async () => {
    const event = buildEventRow();
    vi.mocked(repository.findEventsByIds).mockResolvedValue([event]);
    vi.mocked(repository.createEvidence).mockImplementation(async (data) => buildEvidenceRow({ id: data.id as string, classification: data.classification as EvidenceRow['classification'] }));
    vi.mocked(repository.createCustodyEvent).mockResolvedValue(buildCustodyRow());

    const evidenceId = await service.preserveEventSnapshot({
      organisation_id: 'org-1',
      incident_id: 'inc-1',
      event_ids: [event.id],
      actor: { kind: 'system' },
    });

    expect(typeof evidenceId).toBe('string');
    const createArgs = vi.mocked(repository.createEvidence).mock.calls[0][0];
    expect(createArgs.classification).toBe('EVIDENCE');
    expect(createArgs.incidentId).toBe('inc-1');
    expect(createArgs.relatedEventIds).toEqual([event.id]);
    expect(createArgs.contentType).toBe('application/json');

    const snapshot = JSON.parse((objectStore.putObject as ReturnType<typeof vi.fn>).mock.calls[0][1].toString('utf8'));
    expect(snapshot.events).toHaveLength(1);
    expect(snapshot.events[0].event_id).toBe(event.eventId);
  });

  it('fails loudly (does not silently drop ids) when a requested event id is not found in this organisation', async () => {
    vi.mocked(repository.findEventsByIds).mockResolvedValue([]);

    await expect(
      service.preserveEventSnapshot({ organisation_id: 'org-1', incident_id: 'inc-1', event_ids: ['missing-evt'], actor: { kind: 'system' } }),
    ).rejects.toBeInstanceOf(NotFoundException);
    expect(repository.createEvidence).not.toHaveBeenCalled();
  });

  it('accepts Fusion NormalisedEvent.event_id values and stores canonical Event UUID references', async () => {
    const event = buildEventRow({ id: 'evt-uuid-canonical', eventId: 'external-event-id' });
    vi.mocked(repository.findEventsByIds).mockResolvedValue([event]);
    vi.mocked(repository.createEvidence).mockImplementation(async (data) =>
      buildEvidenceRow({ id: data.id as string, classification: data.classification as EvidenceRow['classification'] }),
    );
    vi.mocked(repository.createCustodyEvent).mockResolvedValue(buildCustodyRow());

    await service.preserveEventSnapshot({
      organisation_id: 'org-1',
      incident_id: 'inc-1',
      event_ids: [event.eventId],
      actor: { kind: 'system' },
    });

    expect(vi.mocked(repository.findEventsByIds)).toHaveBeenCalledWith('org-1', [event.eventId]);
    expect(vi.mocked(repository.createEvidence).mock.calls[0][0].relatedEventIds).toEqual([event.id]);
  });

  it('returns an existing response-task snapshot without writing a duplicate on retry', async () => {
    vi.mocked(repository.findSnapshotForResponseTask).mockResolvedValue(buildEvidenceRow({ id: 'existing-snapshot' }));

    await expect(
      service.preserveEventSnapshot({
        organisation_id: 'org-1',
        incident_id: 'inc-1',
        event_ids: ['evt-1'],
        response_task_id: 'task-1',
        actor: { kind: 'system' },
      }),
    ).resolves.toBe('existing-snapshot');
    expect(repository.findEventsByIds).not.toHaveBeenCalled();
    expect(repository.createEvidence).not.toHaveBeenCalled();
  });

  it('recovers the canonical response-task snapshot when concurrent persistence hits its unique boundary', async () => {
    const event = buildEventRow();
    vi.mocked(repository.findEventsByIds).mockResolvedValue([event]);
    vi.mocked(repository.createEvidence).mockRejectedValue(
      new Prisma.PrismaClientKnownRequestError('duplicate response task', { code: 'P2002', clientVersion: '6.19.3' }),
    );
    vi.mocked(repository.findSnapshotForResponseTask).mockResolvedValue(buildEvidenceRow({ id: 'canonical-snapshot', responseTaskId: 'task-1' }));

    await expect(
      service.preserveEventSnapshot({
        organisation_id: 'org-1', incident_id: 'inc-1', event_ids: [event.id], response_task_id: 'task-1', actor: { kind: 'system' },
      }),
    ).resolves.toBe('canonical-snapshot');
    expect(repository.createCustodyEvent).not.toHaveBeenCalled();
  });
});

describe('EvidenceService.getMetadata', () => {
  it('writes a VIEWED custody event on a successful metadata read', async () => {
    const repository = makeRepository();
    const objectStore = makeObjectStore();
    const service = new EvidenceService(repository, objectStore);
    const row = buildEvidenceRow();
    vi.mocked(repository.findById).mockResolvedValue(row);
    vi.mocked(repository.createCustodyEvent).mockResolvedValue(buildCustodyRow({ action: 'VIEWED' }));

    await service.getMetadata(row.id, row.organisationId, { kind: 'system' });

    const custodyArgs = vi.mocked(repository.createCustodyEvent).mock.calls[0][0];
    expect(custodyArgs.action).toBe('VIEWED');
  });

  it('throws NotFoundException and writes no custody event for an unknown/out-of-tenant id', async () => {
    const repository = makeRepository();
    const objectStore = makeObjectStore();
    const service = new EvidenceService(repository, objectStore);
    vi.mocked(repository.findById).mockResolvedValue(null);

    await expect(service.getMetadata('missing', 'org-1', { kind: 'system' })).rejects.toBeInstanceOf(NotFoundException);
    expect(repository.createCustodyEvent).not.toHaveBeenCalled();
  });
});

describe('EvidenceService.downloadContent', () => {
  let repository: EvidenceRepository;
  let objectStore: EvidenceObjectStoreProvider;
  let service: EvidenceService;

  beforeEach(() => {
    repository = makeRepository();
    objectStore = makeObjectStore();
    service = new EvidenceService(repository, objectStore);
  });

  it('AC4: denies with no purpose and never touches the object store or writes custody', async () => {
    await expect(service.downloadContent('ev-1', 'org-1', undefined, { kind: 'system' })).rejects.toBeInstanceOf(ForbiddenException);
    await expect(service.downloadContent('ev-1', 'org-1', '   ', { kind: 'system' })).rejects.toBeInstanceOf(ForbiddenException);
    expect(repository.findById).not.toHaveBeenCalled();
    expect(objectStore.getObject).not.toHaveBeenCalled();
    expect(repository.createCustodyEvent).not.toHaveBeenCalled();
  });

  it('AC4: with a purpose, returns the content and writes a VIEWED custody event carrying the purpose', async () => {
    const row = buildEvidenceRow();
    const content = Buffer.from('the actual bytes', 'utf8');
    vi.mocked(repository.findById).mockResolvedValue(row);
    vi.mocked(objectStore.getObject).mockResolvedValue(content);
    vi.mocked(repository.createCustodyEvent).mockResolvedValue(buildCustodyRow({ action: 'VIEWED' }));

    const result = await service.downloadContent(row.id, row.organisationId, 'fraud investigation', { kind: 'user', id: 'user-1' });

    expect(result.content).toBe(content);
    const custodyArgs = vi.mocked(repository.createCustodyEvent).mock.calls[0][0];
    expect(custodyArgs.action).toBe('VIEWED');
    expect(custodyArgs.actorId).toBe('user-1');
    expect((custodyArgs.detail as Record<string, unknown>).purpose).toBe('fraud investigation');
  });
});
