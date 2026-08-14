import { Inject, Injectable, Logger, type OnModuleInit } from '@nestjs/common';
import { JSONCodec, RetentionPolicy, StorageType, nanos } from 'nats';
import type { NormalisedEvent } from '@sentinel/contracts';
import { NatsProvider } from '../../infra/nats.provider';
import { PUBLISH_TIMEOUT_MS, STREAM_MAX_AGE_MS, STREAM_NAME, SUBJECT_WILDCARD } from './events.constants';

export function buildSubject(organisationId: string, siteId: string): string {
  return `sentinel.events.${organisationId}.${siteId}`;
}

/**
 * Ensures the `SENTINEL_EVENTS` JetStream stream exists (idempotently) and
 * publishes accepted events to it. Publishing is always best-effort and
 * never throws: the caller persists the event first and treats publish as
 * a follow-up step (§76) — a publish failure is recovered by the retry
 * sweep (events-publish-sweep.service.ts), not by failing the request.
 */
@Injectable()
export class EventsPublisherService implements OnModuleInit {
  private readonly logger = new Logger(EventsPublisherService.name);
  private readonly codec = JSONCodec<NormalisedEvent>();
  private streamEnsured = false;

  constructor(@Inject(NatsProvider) private readonly nats: NatsProvider) {}

  async onModuleInit(): Promise<void> {
    // Best-effort at boot: if NATS is down right now, `tryPublish` (or the
    // retry sweep) will call `ensureStream` again on the next attempt.
    await this.ensureStream().catch((error: unknown) => {
      this.logger.warn(`Could not ensure JetStream stream "${STREAM_NAME}" on boot: ${errorMessage(error)}`);
    });
  }

  private async ensureStream(): Promise<void> {
    if (this.streamEnsured || !this.nats.isConfigured()) {
      return;
    }
    const nc = await this.nats.getConnection();
    const jsm = await nc.jetstreamManager();
    try {
      await jsm.streams.info(STREAM_NAME);
    } catch (error) {
      if (!(error instanceof Error) || error.message !== 'stream not found') {
        throw error;
      }
      await jsm.streams.add({
        name: STREAM_NAME,
        subjects: [SUBJECT_WILDCARD],
        storage: StorageType.File,
        retention: RetentionPolicy.Limits,
        max_age: nanos(STREAM_MAX_AGE_MS),
      });
    }
    this.streamEnsured = true;
  }

  /**
   * Publishes `event` (the full normalised event JSON) to
   * `sentinel.events.{organisation_id}.{site_id}`. Returns whether the
   * publish succeeded; never throws.
   */
  async tryPublish(id: string, event: NormalisedEvent): Promise<boolean> {
    if (!this.nats.isConfigured()) {
      return false;
    }
    try {
      await this.ensureStream();
      const nc = await this.nats.getConnection();
      const js = nc.jetstream();
      const subject = buildSubject(event.organisation_id, event.site_id);
      await js.publish(subject, this.codec.encode(event), { msgID: id, timeout: PUBLISH_TIMEOUT_MS });
      return true;
    } catch (error) {
      this.logger.warn(`JetStream publish failed for event ${id}: ${errorMessage(error)}`);
      return false;
    }
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
