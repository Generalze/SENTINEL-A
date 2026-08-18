import { Inject, Injectable, Logger, type OnApplicationBootstrap, type OnModuleDestroy } from '@nestjs/common';
import { JSONCodec } from 'nats';
import { isSafeSubjectToken } from '../../common/messaging/subject-token';
import { NatsProvider } from '../../infra/nats.provider';
import { PrismaService } from '../../prisma/prisma.service';
import { fieldUpdatedSubject } from './field.constants';

@Injectable()
export class FieldOutboxPublisher implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(FieldOutboxPublisher.name);
  private readonly codec = JSONCodec<unknown>();
  private timer: ReturnType<typeof globalThis.setInterval> | undefined;
  private sweeping = false;

  constructor(@Inject(PrismaService) private readonly prisma: PrismaService, @Inject(NatsProvider) private readonly nats: NatsProvider) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.sweep();
    this.timer = globalThis.setInterval(() => {
      void this.sweep().catch((error: unknown) => {
        this.logger.error(`Field outbox sweep failed: ${error instanceof Error ? error.message : String(error)}`);
      });
    }, 5_000);
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      globalThis.clearInterval(this.timer);
      this.timer = undefined;
    }
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
