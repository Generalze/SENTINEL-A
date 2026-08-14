import { Inject, Injectable, Logger, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { EventsPublisherService } from './events-publisher.service';
import { EventsRepository } from './events.repository';
import { mapRowToNormalisedEvent } from './events.mapper';
import { SWEEP_BATCH_SIZE, SWEEP_INTERVAL_MS, UNPUBLISHED_RETRY_AFTER_MS } from './events.constants';

/**
 * §76 reliability sweep: republishes any Event row whose `published_at` is
 * still NULL after {@link UNPUBLISHED_RETRY_AFTER_MS}. Runs on a plain
 * `setInterval` (cleared on shutdown) rather than a queue/cron dependency
 * — this is a best-effort catch-up mechanism, not the primary delivery
 * path (that's the synchronous publish attempt right after DB commit in
 * EventsService.ingest).
 */
@Injectable()
export class EventsPublishSweepService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(EventsPublishSweepService.name);
  private timer: ReturnType<typeof globalThis.setInterval> | undefined;
  private sweeping = false;

  constructor(
    @Inject(EventsRepository) private readonly repository: EventsRepository,
    @Inject(EventsPublisherService) private readonly publisher: EventsPublisherService,
  ) {}

  onModuleInit(): void {
    // Referenced via `globalThis` (rather than the bare identifier) because
    // this repo's shared root ESLint config does not register timer
    // globals for `no-undef` — see common/http-types.ts for the same
    // pattern re: NodeJS. Also keeps this in sync with `vi.useFakeTimers()`
    // in tests, which patches `globalThis.setInterval`.
    this.timer = globalThis.setInterval(() => {
      void this.sweep();
    }, SWEEP_INTERVAL_MS);
    // Don't let the sweep timer alone keep the process alive (e.g. in tests).
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      globalThis.clearInterval(this.timer);
      this.timer = undefined;
    }
  }

  /** Runs one sweep pass. Exposed directly so tests don't have to wait on the timer. */
  async sweep(): Promise<number> {
    if (this.sweeping) {
      return 0;
    }
    this.sweeping = true;
    try {
      const cutoff = new Date(Date.now() - UNPUBLISHED_RETRY_AFTER_MS);
      const overdue = await this.repository.findUnpublishedOlderThan(cutoff, SWEEP_BATCH_SIZE);
      let republished = 0;
      // Sequential on purpose: bounded batch size, avoid hammering NATS with a burst.
      for (const row of overdue) {
        const published = await this.publisher.tryPublish(row.id, mapRowToNormalisedEvent(row));
        if (published) {
          await this.repository.markPublished(row.id);
          republished += 1;
        }
      }
      if (overdue.length > 0) {
        this.logger.log(`Publish retry sweep: republished ${republished}/${overdue.length} overdue event(s)`);
      }
      return republished;
    } finally {
      this.sweeping = false;
    }
  }
}
