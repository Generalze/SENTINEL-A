import { Inject, Injectable, Logger, type OnApplicationBootstrap, type OnModuleDestroy } from '@nestjs/common';
import { JSONCodec } from 'nats';
import { isSafeSubjectToken } from '../../common/messaging/subject-token';
import { NatsProvider } from '../../infra/nats.provider';
import { PrismaService } from '../../prisma/prisma.service';
import { messageUpdatedSubject } from './field-messaging.constants';

/**
 * WP-18: drains the transactional outbox onto NATS, one subject per entitled
 * recipient.
 *
 * Publishing here proves nothing about delivery. It moves a content-free signal
 * onto the internal bus; whether the recipient's own transport accepted it is a
 * separate question answered by the consumer (C8-01), and only that answer may
 * advance a recipient row to DELIVERED.
 */
@Injectable()
export class FieldMessagingOutboxPublisher implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(FieldMessagingOutboxPublisher.name);
  private readonly codec = JSONCodec<unknown>();
  private timer: ReturnType<typeof globalThis.setInterval> | undefined;
  private sweeping = false;

  constructor(
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(NatsProvider) private readonly nats: NatsProvider,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.sweep();
    this.timer = globalThis.setInterval(() => {
      void this.sweep().catch((error: unknown) => {
        this.logger.error(`Field message outbox sweep failed: ${error instanceof Error ? error.message : String(error)}`);
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
      const rows = await this.prisma.incidentFieldMessageOutbox.findMany({
        where: { publishedAt: null },
        orderBy: { createdAt: 'asc' },
        take: limit,
      });

      let published = 0;
      for (const row of rows) {
        // WP-17/C7-03 defence in depth: both dynamic tokens must be safe before
        // a subject is built. Skip rather than break, so one poisoned row
        // cannot stall delivery for every other recipient.
        if (!isSafeSubjectToken(row.organisationId) || !isSafeSubjectToken(row.recipientUserId)) {
          this.logger.error(`Field message outbox row ${row.id} has an unsafe subject scope; refusing to publish`);
          continue;
        }
        try {
          const nc = await this.nats.getConnection();
          nc.publish(messageUpdatedSubject(row.organisationId, row.recipientUserId), this.codec.encode(row.payload));
          await nc.flush();
          const marked = await this.prisma.incidentFieldMessageOutbox.updateMany({
            where: { id: row.id, publishedAt: null },
            data: { publishedAt: new Date() },
          });
          if (marked.count === 1) published += 1;
        } catch (error) {
          this.logger.warn(`Field message outbox publish failed for ${row.id}: ${error instanceof Error ? error.message : String(error)}`);
          break;
        }
      }
      return published;
    } finally {
      this.sweeping = false;
    }
  }
}
