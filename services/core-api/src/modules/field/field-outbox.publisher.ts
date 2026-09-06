import { Inject, Injectable, Logger, type OnApplicationBootstrap, type OnModuleDestroy } from '@nestjs/common';
import { JSONCodec } from 'nats';
import { isSafeSubjectToken } from '../../common/messaging/subject-token';
import {
  OUTBOX_PUBLISH_INTERVAL_MS,
  OUTBOX_PUBLISH_SCHEDULER,
  type OutboxPublishScheduler,
} from '../../common/scheduling/outbox-publish.scheduler';
import { NatsProvider } from '../../infra/nats.provider';
import { PrismaService } from '../../prisma/prisma.service';
import { fieldUpdatedSubject } from './field.constants';

@Injectable()
export class FieldOutboxPublisher implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(FieldOutboxPublisher.name);
  private readonly codec = JSONCodec<unknown>();
  private sweeping = false;

  constructor(
    @Inject(PrismaService) private readonly prisma: PrismaService,
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
          this.logger.error(`Field outbox sweep failed: ${error instanceof Error ? error.message : String(error)}`);
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
      const rows = await this.prisma.fieldOutbox.findMany({ where: { publishedAt: null }, orderBy: { createdAt: 'asc' }, take: limit });
      let published = 0;
      for (const row of rows) {
        // WP-17/D3: defence in depth. `site_id` is already rejected at the API
        // boundary when it is not a safe subject token, so this row cannot
        // exist in practice. If one ever does, skip it (leaving it unpublished
        // and loudly logged) rather than building a subject whose arity the
        // stored id controls — and `continue`, not `break`, so one poisoned
        // row cannot stall delivery for every other tenant.
        if (!isSafeSubjectToken(row.organisationId) || !isSafeSubjectToken(row.siteId)) {
          this.logger.error(`Field outbox row ${row.id} has an unsafe subject scope (org=${row.organisationId} site=${row.siteId}); refusing to publish`);
          continue;
        }
        try {
          const nc = await this.nats.getConnection();
          nc.publish(fieldUpdatedSubject(row.organisationId, row.siteId), this.codec.encode(row.payload));
          await nc.flush();
          const marked = await this.prisma.fieldOutbox.updateMany({ where: { id: row.id, publishedAt: null }, data: { publishedAt: new Date() } });
          if (marked.count === 1) published += 1;
        } catch (error) {
          this.logger.warn(`Field outbox publish failed for ${row.id}: ${error instanceof Error ? error.message : String(error)}`);
          break;
        }
      }
      return published;
    } finally {
      this.sweeping = false;
    }
  }
}
