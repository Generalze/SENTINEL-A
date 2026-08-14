import type { Event as EventRow } from '@prisma/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EventsPublishSweepService } from './events-publish-sweep.service';
import type { EventsPublisherService } from './events-publisher.service';
import type { EventsRepository } from './events.repository';
import { makeNormalisedEvent } from './test-fixtures';

function buildRow(id: string): EventRow {
  const event = makeNormalisedEvent();
  return {
    id,
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
    idempotencyKey: null,
    duplicateOfEventId: null,
    receivedCount: 1,
    publishedAt: null,
    createdAt: new Date(),
  };
}

function makeRepository(): EventsRepository {
  return {
    findUnpublishedOlderThan: vi.fn(),
    markPublished: vi.fn(),
  } as unknown as EventsRepository;
}

function makePublisher(): EventsPublisherService {
  return { tryPublish: vi.fn() } as unknown as EventsPublisherService;
}

describe('EventsPublishSweepService', () => {
  let repository: EventsRepository;
  let publisher: EventsPublisherService;
  let service: EventsPublishSweepService;

  beforeEach(() => {
    repository = makeRepository();
    publisher = makePublisher();
    service = new EventsPublishSweepService(repository, publisher);
  });

  afterEach(() => {
    service.onModuleDestroy();
    vi.useRealTimers();
  });

  it('republishes overdue rows and marks each one published on success', async () => {
    vi.mocked(repository.findUnpublishedOlderThan).mockResolvedValue([buildRow('a'), buildRow('b')]);
    vi.mocked(publisher.tryPublish).mockResolvedValue(true);

    const count = await service.sweep();

    expect(count).toBe(2);
    expect(repository.markPublished).toHaveBeenCalledTimes(2);
    expect(repository.markPublished).toHaveBeenCalledWith('a');
    expect(repository.markPublished).toHaveBeenCalledWith('b');
  });

  it('does not mark a row published when the retry publish still fails', async () => {
    vi.mocked(repository.findUnpublishedOlderThan).mockResolvedValue([buildRow('a')]);
    vi.mocked(publisher.tryPublish).mockResolvedValue(false);

    const count = await service.sweep();

    expect(count).toBe(0);
    expect(repository.markPublished).not.toHaveBeenCalled();
  });

  it('queries with a cutoff ~15s in the past (UNPUBLISHED_RETRY_AFTER_MS)', async () => {
    vi.mocked(repository.findUnpublishedOlderThan).mockResolvedValue([]);
    const before = Date.now();

    await service.sweep();

    const [cutoff] = vi.mocked(repository.findUnpublishedOlderThan).mock.calls[0];
    const impliedAgeMs = before - cutoff.getTime();
    expect(impliedAgeMs).toBeGreaterThanOrEqual(15_000 - 50);
    expect(impliedAgeMs).toBeLessThan(15_000 + 2_000);
  });

  it('does not run overlapping sweeps: a second call while one is in-flight is a no-op', async () => {
    let resolveFirstPublish: (value: boolean) => void = () => {};
    const pending = new Promise<boolean>((resolve) => {
      resolveFirstPublish = resolve;
    });
    vi.mocked(repository.findUnpublishedOlderThan).mockResolvedValue([buildRow('a')]);
    vi.mocked(publisher.tryPublish).mockReturnValue(pending);

    const first = service.sweep();
    const second = await service.sweep();

    expect(second).toBe(0);
    resolveFirstPublish(true);
    expect(await first).toBe(1);
  });

  it('starts and stops a periodic timer that invokes sweep()', () => {
    vi.useFakeTimers();
    const sweepSpy = vi.spyOn(service, 'sweep').mockResolvedValue(0);

    service.onModuleInit();
    expect(sweepSpy).not.toHaveBeenCalled();

    vi.advanceTimersByTime(10_000);
    expect(sweepSpy).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(10_000);
    expect(sweepSpy).toHaveBeenCalledTimes(2);

    service.onModuleDestroy();
    vi.advanceTimersByTime(30_000);
    expect(sweepSpy).toHaveBeenCalledTimes(2);
  });
});
