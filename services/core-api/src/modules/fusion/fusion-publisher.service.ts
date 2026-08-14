/**
 * Publishes fusion output to NATS (WP-05 deliverables #4 and #5).
 *
 *   sentinel.fusion.hypothesis.{organisation_id}          — every update
 *   sentinel.fusion.incident-candidate.{organisation_id}  — latched crossings
 *
 * The subject is tenant-suffixed so a downstream consumer can subscribe to
 * exactly one organisation and never be exposed to another tenant's traffic
 * by accident.
 *
 * PUBLISHING NEVER THROWS. It is a follow-up to a committed database write,
 * exactly as the events module treats its own publish (§76): the hypothesis
 * is already durable before anything goes on the wire, so a NATS outage must
 * degrade delivery, not roll back an assessment or stall the consumer. Failed
 * publishes are logged; the durable record in `fusion_hypotheses` remains the
 * source of truth and the HTTP API keeps serving it.
 *
 * A note on ownership: this module CREATES `SENTINEL_FUSION` (subjects
 * `sentinel.fusion.>`, which is this work package's lane) but never touches
 * `SENTINEL_EVENTS`, which WP-04 owns.
 */

import { Inject, Injectable, Logger, type OnModuleInit } from '@nestjs/common';
import { JSONCodec, RetentionPolicy, StorageType, nanos } from 'nats';
import { NatsProvider } from '../../infra/nats.provider';
import {
  FUSION_STREAM_MAX_AGE_MS,
  FUSION_STREAM_NAME,
  FUSION_SUBJECT_WILDCARD,
  PUBLISH_TIMEOUT_MS,
  hypothesisSubject,
  incidentCandidateSubject,
} from './fusion.constants';
import type { HypothesisUpdateMessage, IncidentCandidateMessage } from './fusion.types';

@Injectable()
export class FusionPublisherService implements OnModuleInit {
  private readonly logger = new Logger(FusionPublisherService.name);
  private readonly codec = JSONCodec<HypothesisUpdateMessage | IncidentCandidateMessage>();
  private streamEnsured = false;

  constructor(@Inject(NatsProvider) private readonly nats: NatsProvider) {}

  async onModuleInit(): Promise<void> {
    await this.ensureStream().catch((error: unknown) => {
      this.logger.warn(`Could not ensure JetStream stream "${FUSION_STREAM_NAME}" on boot: ${errorMessage(error)}`);
    });
  }

  /** Idempotent: creates the stream only if it is genuinely absent. */
  private async ensureStream(): Promise<void> {
    if (this.streamEnsured || !this.nats.isConfigured()) {
      return;
    }
    const nc = await this.nats.getConnection();
    const jsm = await nc.jetstreamManager();
    try {
      await jsm.streams.info(FUSION_STREAM_NAME);
    } catch (error) {
      if (!(error instanceof Error) || error.message !== 'stream not found') {
        throw error;
      }
      await jsm.streams.add({
        name: FUSION_STREAM_NAME,
        subjects: [FUSION_SUBJECT_WILDCARD],
        storage: StorageType.File,
        retention: RetentionPolicy.Limits,
        max_age: nanos(FUSION_STREAM_MAX_AGE_MS),
      });
    }
    this.streamEnsured = true;
  }

  async publishHypothesisUpdate(message: HypothesisUpdateMessage): Promise<boolean> {
    return this.publish(
      hypothesisSubject(message.hypothesis.organisation_id),
      message,
      `hypothesis ${message.hypothesis.hypothesis_id}`,
      // One update per (hypothesis, triggering event): a redelivery that
      // somehow reaches this point is collapsed by JetStream's own dedupe
      // window rather than producing a second update on the wire.
      `${message.hypothesis.hypothesis_id}:${message.triggering_event_id}`,
    );
  }

  async publishIncidentCandidate(message: IncidentCandidateMessage): Promise<boolean> {
    return this.publish(
      incidentCandidateSubject(message.organisation_id),
      message,
      `incident-candidate ${message.incident_candidate_id} (emission ${message.emission_number})`,
      // Emission number is part of the id so a re-escalation is a genuinely
      // new message while a duplicate of the same emission is suppressed.
      `${message.incident_candidate_id}:${message.emission_number}`,
    );
  }

  private async publish(
    subject: string,
    message: HypothesisUpdateMessage | IncidentCandidateMessage,
    description: string,
    msgId: string,
  ): Promise<boolean> {
    if (!this.nats.isConfigured()) {
      return false;
    }
    try {
      await this.ensureStream();
      const nc = await this.nats.getConnection();
      const js = nc.jetstream();
      await js.publish(subject, this.codec.encode(message), { msgID: msgId, timeout: PUBLISH_TIMEOUT_MS });
      return true;
    } catch (error) {
      this.logger.warn(`Fusion publish to ${subject} failed for ${description}: ${errorMessage(error)}`);
      return false;
    }
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
