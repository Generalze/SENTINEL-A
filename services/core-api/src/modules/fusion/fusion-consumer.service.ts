/**
 * Durable JetStream consumer for Fusion (WP-05 deliverable #4).
 *
 * Subscribes to `sentinel.events.>` on the WP-04-owned `SENTINEL_EVENTS`
 * stream under the durable name `fusion-v1` and feeds every event through
 * `FusionService.applyEvent`.
 *
 * WHY DURABLE
 * -----------
 * A durable consumer keeps its acknowledgement position server-side, so a
 * core-api restart resumes exactly where it left off: no event is silently
 * skipped (which would lose evidence from a threat assessment) and none is
 * blindly reprocessed as new (idempotency would absorb that anyway, but the
 * durable position means we do not have to rely on it for correctness of the
 * common case).
 *
 * ACKNOWLEDGEMENT POLICY
 * ----------------------
 *   ack()  — the event was applied, was a recognised duplicate, or was
 *            deliberately ignored by the rule table. All three are "fusion is
 *            done with this message".
 *   term() — the payload does not satisfy the Normalised Event Contract.
 *            Redelivering it would fail identically forever, so it is
 *            terminated and logged loudly rather than left to poison the
 *            consumer. Fusion is a read-side consumer: it must never be the
 *            thing that blocks the event pipeline.
 *   nak()  — a transient failure (database unavailable, write contention).
 *            JetStream redelivers, and idempotency makes the retry safe.
 *
 * The loop processes messages one at a time. Fusion state is per correlation
 * window and order-sensitive in its transition log, so sequential processing
 * keeps the stored history matching delivery order; throughput is not the
 * binding constraint at M1 volumes.
 */

import { Inject, Injectable, Logger, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { AckPolicy, DeliverPolicy, JSONCodec, nanos, type ConsumerMessages, type JsMsg } from 'nats';
import { NormalisedEventSchema } from '@sentinel/contracts';
import { NatsProvider } from '../../infra/nats.provider';
import {
  CONSUMER_ACK_WAIT_MS,
  CONSUMER_MAX_DELIVER,
  EVENTS_STREAM_NAME,
  EVENTS_SUBJECT_FILTER,
  FUSION_DURABLE_NAME,
} from './fusion.constants';
import { FusionService } from './fusion.service';

/** Delay before JetStream redelivers a message we could not process transiently. */
const NAK_DELAY_MS = 2000;

export interface FusionConsumerOptions {
  /**
   * Durable consumer name. Defaults to FUSION_DURABLE_NAME (`fusion-v1`).
   * Overridable so integration tests can run isolated consumers against the
   * shared live stack without competing with the service's own durable for
   * messages.
   */
  durableName?: string;
  /**
   * When true the consumer starts from new messages only instead of the
   * stream's full history. The service always uses `false` (deliver all);
   * tests use `true` so a run is not slowed by replaying every event another
   * work package left in the stream.
   */
  deliverNewOnly?: boolean;
}

@Injectable()
export class FusionConsumerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(FusionConsumerService.name);
  private readonly codec = JSONCodec<unknown>();
  private messages: ConsumerMessages | undefined;
  private loop: Promise<void> | undefined;
  private stopping = false;

  constructor(
    @Inject(NatsProvider) private readonly nats: NatsProvider,
    @Inject(FusionService) private readonly fusion: FusionService,
  ) {}

  async onModuleInit(): Promise<void> {
    // Never block or fail boot on messaging: the HTTP API and the database
    // are independently useful, and NatsProvider reconnects lazily.
    await this.start().catch((error: unknown) => {
      this.logger.error(`Fusion consumer failed to start: ${errorMessage(error)}`);
    });
  }

  async onModuleDestroy(): Promise<void> {
    await this.stop();
  }

  /**
   * Ensures the durable consumer exists and begins consuming. Resolves once
   * the subscription is live, so a caller (or a test) can publish immediately
   * afterwards and know the message will be picked up.
   */
  async start(options: FusionConsumerOptions = {}): Promise<void> {
    if (this.messages) {
      return;
    }
    if (!this.nats.isConfigured()) {
      this.logger.warn('NATS is not configured; fusion consumer will not start');
      return;
    }

    const durableName = options.durableName ?? FUSION_DURABLE_NAME;
    const nc = await this.nats.getConnection();
    const jsm = await nc.jetstreamManager();

    try {
      await jsm.consumers.info(EVENTS_STREAM_NAME, durableName);
    } catch {
      // Not found (or not inspectable): create it. `add` is itself idempotent
      // for an identical configuration, so a concurrent starter is harmless.
      await jsm.consumers.add(EVENTS_STREAM_NAME, {
        durable_name: durableName,
        ack_policy: AckPolicy.Explicit,
        deliver_policy: options.deliverNewOnly ? DeliverPolicy.New : DeliverPolicy.All,
        filter_subject: EVENTS_SUBJECT_FILTER,
        ack_wait: nanos(CONSUMER_ACK_WAIT_MS),
        max_deliver: CONSUMER_MAX_DELIVER,
      });
    }

    const consumer = await nc.jetstream().consumers.get(EVENTS_STREAM_NAME, durableName);
    this.messages = await consumer.consume();
    this.stopping = false;
    this.loop = this.run(this.messages);
    this.logger.log(`Fusion consumer "${durableName}" consuming ${EVENTS_SUBJECT_FILTER}`);
  }

  async stop(): Promise<void> {
    this.stopping = true;
    if (this.messages) {
      this.messages.stop();
      this.messages = undefined;
    }
    if (this.loop) {
      await this.loop.catch(() => undefined);
      this.loop = undefined;
    }
  }

  private async run(messages: ConsumerMessages): Promise<void> {
    try {
      for await (const message of messages) {
        if (this.stopping) {
          break;
        }
        await this.handle(message);
      }
    } catch (error) {
      if (!this.stopping) {
        this.logger.error(`Fusion consumer loop ended unexpectedly: ${errorMessage(error)}`);
      }
    }
  }

  /** Exposed for direct unit testing of the ack/term/nak decision. */
  async handle(message: JsMsg): Promise<void> {
    let raw: unknown;
    try {
      raw = this.codec.decode(message.data);
    } catch (error) {
      this.logger.error(`Terminating unparseable message on ${message.subject}: ${errorMessage(error)}`);
      message.term();
      return;
    }

    const parsed = NormalisedEventSchema.safeParse(raw);
    if (!parsed.success) {
      this.logger.error(
        `Terminating message on ${message.subject}: payload is not a valid NormalisedEvent (${parsed.error.issues
          .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
          .join('; ')})`,
      );
      message.term();
      return;
    }

    try {
      const result = await this.fusion.applyEvent(parsed.data);
      message.ack();
      if (result.outcome === 'applied' && result.stateChanged) {
        this.logger.log(
          `hypothesis ${result.hypothesisId}: state ${result.previousState} -> ${result.state} on event ${result.eventId}`,
        );
      }
    } catch (error) {
      this.logger.error(`Retrying event on ${message.subject}: ${errorMessage(error)}`);
      message.nak(NAK_DELAY_MS);
    }
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
