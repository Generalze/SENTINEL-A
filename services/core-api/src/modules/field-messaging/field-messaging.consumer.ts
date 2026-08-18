import { Inject, Injectable, Logger, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { canTransition } from '@sentinel/contracts';
import type { Msg } from 'nats';
import { NatsProvider } from '../../infra/nats.provider';
import { withRetryBackoff, type BackoffOptions } from '../realtime/backoff.util';
import { RealtimeGateway } from '../realtime/realtime.gateway';
import {
  FIELD_MESSAGE_SUBJECT_SEGMENTS,
  NATS_SUBJECT_FIELD_MESSAGE,
  SUBJECT_MESSAGE_ORG_ID_SEGMENT_INDEX,
  SUBJECT_RECIPIENT_SEGMENT_INDEX,
  WS_EVENT_FIELD_MESSAGE_UPDATED,
} from '../realtime/realtime.constants';
import { FieldMessagingRepository } from './field-messaging.repository';

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * WP-18 realtime delivery.
 *
 * This consumer lives in the field-messaging module rather than the realtime
 * bridge because delivery SEMANTICS belong to this domain: the realtime module
 * owns the socket, this module owns what a receipt means. It therefore uses the
 * gateway to emit, but decides for itself whether the result is evidence.
 *
 * C8-01, the load-bearing rule: only a socket-level acknowledgement from one of
 * the recipient's OWN authenticated connections advances a row to DELIVERED.
 * Receiving this NATS message proves the internal bus worked and nothing more,
 * so no state changes on that basis. If the recipient has no live socket, or
 * none answers, the row correctly stays REQUESTED.
 */
@Injectable()
export class FieldMessagingConsumer implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(FieldMessagingConsumer.name);
  private stopped = false;
  /** Test-only seam, mirroring RealtimeNatsBridgeService. */
  private backoffOptions: BackoffOptions | undefined;

  constructor(
    @Inject(NatsProvider) private readonly nats: NatsProvider,
    @Inject(RealtimeGateway) private readonly gateway: RealtimeGateway,
    @Inject(FieldMessagingRepository) private readonly repository: FieldMessagingRepository,
  ) {}

  onModuleInit(): void {
    if (!this.nats.isConfigured()) {
      this.logger.warn('NATS not configured; field message notifications will not be delivered');
      return;
    }
    void this.runSubscriptionLoop();
  }

  onModuleDestroy(): void {
    this.stopped = true;
  }

  setBackoffOptionsForTesting(options: BackoffOptions): void {
    this.backoffOptions = options;
  }

  private async runSubscriptionLoop(): Promise<void> {
    while (!this.stopped) {
      const sub = await withRetryBackoff({
        isStopped: () => this.stopped,
        options: this.backoffOptions,
        attempt: async () => {
          const nc = await this.nats.getConnection();
          const subscription = nc.subscribe(NATS_SUBJECT_FIELD_MESSAGE);
          this.logger.log(`subscribed to ${NATS_SUBJECT_FIELD_MESSAGE}`);
          return subscription;
        },
        onAttemptError: (error, attemptNumber, delayMs) => {
          this.logger.warn(`subscribe to ${NATS_SUBJECT_FIELD_MESSAGE} failed (attempt ${attemptNumber}): ${errorMessage(error)} — retrying in ${delayMs}ms`);
        },
      });

      if (!sub || this.stopped) return;

      for await (const msg of sub) {
        if (this.stopped) break;
        await this.handleMessage(msg);
      }

      if (this.stopped) return;
      this.logger.warn(`subscription to ${NATS_SUBJECT_FIELD_MESSAGE} ended; resubscribing`);
    }
  }

  /** Exposed for the live integration spec, which drives one message deterministically. */
  async handleMessage(msg: Msg): Promise<void> {
    // Exact arity or nothing (C7-08). A surplus segment must never let an
    // index-based read pick the wrong recipient.
    const segments = msg.subject.split('.');
    if (segments.length !== FIELD_MESSAGE_SUBJECT_SEGMENTS || segments.some((part) => part.length === 0)) {
      this.logger.warn(`dropping message on ${msg.subject}: expected exactly ${FIELD_MESSAGE_SUBJECT_SEGMENTS} non-empty subject segments`);
      return;
    }
    const organisationId = segments[SUBJECT_MESSAGE_ORG_ID_SEGMENT_INDEX];
    const recipientUserId = segments[SUBJECT_RECIPIENT_SEGMENT_INDEX];
    if (!organisationId || !recipientUserId) return;

    let raw: unknown;
    try {
      raw = msg.json();
    } catch (error) {
      this.logger.warn(`dropping malformed (non-JSON) message on ${msg.subject}: ${errorMessage(error)}`);
      return;
    }

    const payload = this.project(raw);
    if (!payload) {
      this.logger.warn(`dropping field message notification on ${msg.subject}: no message_id`);
      return;
    }

    const received = await this.gateway.emitToUserAwaitingReceipt(organisationId, recipientUserId, WS_EVENT_FIELD_MESSAGE_UPDATED, payload);
    if (!received) {
      // No live socket, or none acknowledged. The row stays REQUESTED, which is
      // the honest state: nothing has evidence of reaching the recipient.
      return;
    }

    await this.repository.recordTransportDelivery(organisationId, payload.incident_id, payload.message_id, recipientUserId, (from) =>
      canTransition(from as Parameters<typeof canTransition>[0], 'DELIVERED'),
    );
  }

  /**
   * Identifiers only. A per-user room's audience equals the entitled set, so a
   * message id may ride it — body, media and sender identity never may.
   */
  private project(raw: unknown): { kind: string; incident_id: string; message_id: string } | null {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null;
    const record = raw as Record<string, unknown>;
    const messageId = record.message_id;
    const incidentId = record.incident_id;
    if (typeof messageId !== 'string' || typeof incidentId !== 'string') return null;
    return { kind: WS_EVENT_FIELD_MESSAGE_UPDATED, incident_id: incidentId, message_id: messageId };
  }
}
