import { Inject, Injectable, Logger, type OnApplicationBootstrap, type OnModuleDestroy } from '@nestjs/common';
import { JSONCodec } from 'nats';
import { isSafeSubjectToken } from '../../common/messaging/subject-token';
import { NatsProvider } from '../../infra/nats.provider';
import { incidentUpdatedSubject } from './incidents.constants';
import { IncidentsRepository } from './incidents.repository';

/** Repairs best-effort realtime delivery from the transactional incident outbox. */
@Injectable()
export class IncidentsOutboxPublisher implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(IncidentsOutboxPublisher.name);
  private readonly codec = JSONCodec<unknown>();
  private timer: ReturnType<typeof globalThis.setInterval> | undefined;
  private sweeping = false;

  constructor(@Inject(IncidentsRepository) private readonly repository: IncidentsRepository, @Inject(NatsProvider) private readonly nats: NatsProvider) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.sweep();
    this.timer = globalThis.setInterval(() => {
      void this.sweep().catch((error: unknown) => {
        this.logger.error(`Incident outbox sweep failed: ${error instanceof Error ? error.message : String(error)}`);
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
