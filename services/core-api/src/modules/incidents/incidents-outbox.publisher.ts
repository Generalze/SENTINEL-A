import { Inject, Injectable, Logger, type OnApplicationBootstrap, type OnModuleDestroy } from '@nestjs/common';
import { JSONCodec } from 'nats';
import { isSafeSubjectToken } from '../../common/messaging/subject-token';
import {
  OUTBOX_PUBLISH_INTERVAL_MS,
  OUTBOX_PUBLISH_SCHEDULER,
  type OutboxPublishScheduler,
} from '../../common/scheduling/outbox-publish.scheduler';
import { NatsProvider } from '../../infra/nats.provider';
import { incidentUpdatedSubject } from './incidents.constants';
import { IncidentsRepository } from './incidents.repository';

/** Repairs best-effort realtime delivery from the transactional incident outbox. */
@Injectable()
export class IncidentsOutboxPublisher implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(IncidentsOutboxPublisher.name);
  private readonly codec = JSONCodec<unknown>();
  private sweeping = false;

  constructor(
    @Inject(IncidentsRepository) private readonly repository: IncidentsRepository,
    @Inject(NatsProvider) private readonly nats: NatsProvider,
    @Inject(OUTBOX_PUBLISH_SCHEDULER) private readonly scheduler: OutboxPublishScheduler,
  ) {}

  /**
   * TI-02 — THE SCHEDULER OWNS BOTH EXECUTIONS.
   *
   * This used to `await this.sweep()` here and only then create its own
   * `setInterval`. The behaviour was right for production and there was no
   * seam at all: no injection token, so nothing could decline either the boot
   * sweep or the repeat. Every live suite that booted `AppModule` therefore
   * drained this outbox — and the query has NO organisation filter, because in
   * production one deployment serves every tenant — so each unrelated boot
   * claimed and marked published other suites' pending rows.
   *
   * Production behaviour is unchanged: `runImmediately` is `true`, the real
   * scheduler awaits that sweep before installing the timer, and the cadence is
   * still the same hard-wired 5s constant, now named once in
   * `OUTBOX_PUBLISH_INTERVAL_MS`. What changed is only who owns the two
   * executions.
   */
  async onApplicationBootstrap(): Promise<void> {
    await this.scheduler.start(
      async () => {
        try {
          await this.sweep();
        } catch (error: unknown) {
          // A failed sweep must never take the application down with it, and
          // must never stop the cadence: the next tick tries again.
          this.logger.error(`Incident outbox sweep failed: ${error instanceof Error ? error.message : String(error)}`);
        }
      },
      OUTBOX_PUBLISH_INTERVAL_MS,
      { runImmediately: true },
    );
  }

  onModuleDestroy(): void {
    this.scheduler.stop();
  }

  async sweep(limit = 100): Promise<number> {
    if (this.sweeping) return 0;
    this.sweeping = true;
    try {
      if (!this.nats.isConfigured()) return 0;
      const rows = await this.repository.pendingOutbox(limit);
      let published = 0;
      for (const row of rows) {
        // WP-17/C7-06: this loop `break`s on failure, so an unpublishable row
        // would stall every tenant's incident updates behind it. A row whose
        // scope cannot form a valid subject is skipped (left unpublished and
        // logged) rather than allowed to block the queue — same rule as the
        // Field outbox publisher.
        if (!isSafeSubjectToken(row.organisationId)) {
          this.logger.error(`Incident outbox row ${row.id} has an unsafe subject scope (org=${row.organisationId}); refusing to publish`);
          continue;
        }
        try {
          const nc = await this.nats.getConnection();
          nc.publish(incidentUpdatedSubject(row.organisationId), this.codec.encode(row.payload));
          await nc.flush();
          if (await this.repository.markOutboxPublished(row.id)) published += 1;
        } catch (error) {
          this.logger.warn(`Incident outbox publish failed for ${row.id}: ${error instanceof Error ? error.message : String(error)}`);
          break;
        }
      }
      return published;
    } finally {
      this.sweeping = false;
    }
  }
}
