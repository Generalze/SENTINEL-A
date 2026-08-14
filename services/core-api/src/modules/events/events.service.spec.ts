import { Prisma, type Event as EventRow } from '@prisma/client';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { EventsPublisherService } from './events-publisher.service';
import type { EventsRepository } from './events.repository';
import { EventsService } from './events.service';
import { makeNormalisedEvent } from './test-fixtures';

function buildRow(overrides: Partial<EventRow> = {}): EventRow {
  const event = makeNormalisedEvent();
  return {
    id: 'row-1',
    eventId: event.event_id,
    schemaVersion: 1,
    organisationId: event.organisation_id,
    siteId: event.site_id,
    zoneId: null,
    sourceType: event.source_type,
    sourceId: event.source_id,
    sourceTrust: event.source_trust,
    eventType: event.event_type,
    confidence: event.confidence,
    occurredAt: new Date(event.occurred_at),
    ingestedAt: new Date(event.ingested_at),
    location: {},
    trackIds: [],
    evidenceRefs: [],
    metadata: {},
    traceId: event.trace_id,
    idempotencyKey: 'key-1',
    duplicateOfEventId: null,
    receivedCount: 1,
    publishedAt: null,
    createdAt: new Date(),
    ...overrides,
  };
}

function makeRepository(): EventsRepository {
  return {
    findByIdempotencyKey: vi.fn(),
    findById: vi.fn(),
    createCanonical: vi.fn(),
    recordDuplicateDelivery: vi.fn(),
    markPublished: vi.fn(),
    findUnpublishedOlderThan: vi.fn(),
    list: vi.fn(),
  } as unknown as EventsRepository;
}

function makePublisher(): EventsPublisherService {
  return { tryPublish: vi.fn() } as unknown as EventsPublisherService;
}

describe('EventsService.ingest', () => {
  let repository: EventsRepository;
  let publisher: EventsPublisherService;
  let service: EventsService;

  beforeEach(() => {
    repository = makeRepository();
    publisher = makePublisher();
    service = new EventsService(repository, publisher);
  });

  it('persists a brand-new event, publishes it, and marks it published on success', async () => {
    const event = makeNormalisedEvent();
    const row = buildRow({ eventId: event.event_id });
    vi.mocked(repository.findByIdempotencyKey).mockResolvedValue(null);
    vi.mocked(repository.createCanonical).mockResolvedValue(row);
    vi.mocked(publisher.tryPublish).mockResolvedValue(true);

    const result = await service.ingest(event);

    expect(repository.createCanonical).toHaveBeenCalledWith(event, expect.any(String));
    expect(publisher.tryPublish).toHaveBeenCalledWith(row.id, event);
    expect(repository.markPublished).toHaveBeenCalledWith(row.id, expect.any(Date));
    expect(result).toEqual({ duplicate: false, event: expect.objectContaining({ id: row.id, published_at: expect.any(String) }) });
  });

  it('persists the event but leaves published_at null when the publish attempt fails (NATS down)', async () => {
    const event = makeNormalisedEvent();
    const row = buildRow({ eventId: event.event_id, publishedAt: null });
    vi.mocked(repository.findByIdempotencyKey).mockResolvedValue(null);
    vi.mocked(repository.createCanonical).mockResolvedValue(row);
    vi.mocked(publisher.tryPublish).mockResolvedValue(false);

    const result = await service.ingest(event);

    expect(repository.markPublished).not.toHaveBeenCalled();
    expect(result).toEqual({ duplicate: false, event: expect.objectContaining({ published_at: null }) });
  });

  it('returns duplicate:true and links the delivery when an idempotency key already exists', async () => {
    const event = makeNormalisedEvent();
    const canonical = buildRow({ eventId: event.event_id, receivedCount: 2 });
    vi.mocked(repository.findByIdempotencyKey).mockResolvedValue(canonical);

    const result = await service.ingest(event);

    expect(repository.createCanonical).not.toHaveBeenCalled();
    expect(repository.recordDuplicateDelivery).toHaveBeenCalledWith(canonical.id, event);
    expect(publisher.tryPublish).not.toHaveBeenCalled();
    expect(result).toEqual({ duplicate: true, original_event_id: canonical.eventId });
  });

  it('treats a unique-constraint race on idempotency_key as a duplicate instead of a 500', async () => {
    const event = makeNormalisedEvent();
    const winner = buildRow({ eventId: event.event_id });
    const conflict = new Prisma.PrismaClientKnownRequestError('Unique constraint failed on the fields: (`idempotency_key`)', {
      code: 'P2002',
      clientVersion: '6.19.3',
      meta: { target: ['idempotency_key'] },
    });

    vi.mocked(repository.findByIdempotencyKey).mockResolvedValueOnce(null).mockResolvedValueOnce(winner);
    vi.mocked(repository.createCanonical).mockRejectedValue(conflict);

    const result = await service.ingest(event);

    expect(repository.recordDuplicateDelivery).toHaveBeenCalledWith(winner.id, event);
    expect(result).toEqual({ duplicate: true, original_event_id: winner.eventId });
  });

  it('rethrows non-idempotency-key database errors instead of masking them as a duplicate', async () => {
    const event = makeNormalisedEvent();
    const otherError = new Prisma.PrismaClientKnownRequestError('Some other constraint failed', {
      code: 'P2002',
      clientVersion: '6.19.3',
      meta: { target: ['some_other_column'] },
    });
    vi.mocked(repository.findByIdempotencyKey).mockResolvedValue(null);
    vi.mocked(repository.createCanonical).mockRejectedValue(otherError);

    await expect(service.ingest(event)).rejects.toBe(otherError);
  });
});
