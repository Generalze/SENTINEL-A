import { Inject, Injectable } from '@nestjs/common';
import { deriveIdempotencyKey, type NormalisedEvent } from '@sentinel/contracts';
import { EventsPublisherService } from './events-publisher.service';
import { EventsRepository, isIdempotencyKeyConflict } from './events.repository';
import { toStoredEventResponse } from './events.mapper';
import { IDEMPOTENCY_WINDOW_MS } from './events.constants';
import type { EventsListFilter, EventsListResult, IngestResult } from './events.types';

/**
 * Orchestrates ingest (§64.1 idempotency + §76 publish-after-commit) and
 * tenant-scoped reads. Holds no direct Prisma access — all persistence
 * goes through EventsRepository, whose class doc is the source of truth
 * for the two permitted mutations against the Event model.
 */
@Injectable()
export class EventsService {
  constructor(
    @Inject(EventsRepository) private readonly repository: EventsRepository,
    @Inject(EventsPublisherService) private readonly publisher: EventsPublisherService,
  ) {}

  async ingest(event: NormalisedEvent): Promise<IngestResult> {
    // WP-14/C1: organisation + site lead the idempotency key, and every
    // lookup below is scoped to the event's organisation, so a colliding
    // source/event id from another tenant can never mask this event.
    const idempotencyKey = deriveIdempotencyKey(
      event.organisation_id,
      event.site_id,
      event.source_id,
      event.event_id,
      event.occurred_at,
      IDEMPOTENCY_WINDOW_MS,
    );

    const existing = await this.repository.findByIdempotencyKey(event.organisation_id, idempotencyKey);
    if (existing) {
      await this.repository.recordDuplicateDelivery(existing.id, event);
      return { duplicate: true, original_event_id: existing.eventId };
    }

    let canonical;
    try {
      canonical = await this.repository.createCanonical(event, idempotencyKey);
    } catch (error) {
      // Two concurrent deliveries can both miss the findFirst above and
      // race to insert; the loser hits the DB's composite unique constraint
      // on (organisation_id, idempotency_key). Treat that exactly like a
      // duplicate found up front — never surface a 500 on replay (AC1).
      if (isIdempotencyKeyConflict(error)) {
        const winner = await this.repository.findByIdempotencyKey(event.organisation_id, idempotencyKey);
        if (winner) {
          await this.repository.recordDuplicateDelivery(winner.id, event);
          return { duplicate: true, original_event_id: winner.eventId };
        }
      }
      throw error;
    }

    // Publish after the DB commit (the create() above already committed).
    // Failure here does not lose the event: published_at stays null and
    // the retry sweep picks it up.
    const published = await this.publisher.tryPublish(canonical.id, event);
    if (published) {
      const publishedAt = new Date();
      await this.repository.markPublished(canonical.id, publishedAt);
      canonical = { ...canonical, publishedAt };
    }

    return { duplicate: false, event: toStoredEventResponse(canonical) };
  }

  async list(filter: EventsListFilter): Promise<EventsListResult> {
    const { items, nextCursor } = await this.repository.list(filter);
    return { items: items.map(toStoredEventResponse), next_cursor: nextCursor };
  }
}
