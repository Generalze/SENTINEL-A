import { Inject, Injectable, Logger, type OnApplicationBootstrap, type OnModuleDestroy } from '@nestjs/common';
import { AckPolicy, DeliverPolicy, JSONCodec, nanos, type ConsumerMessages, type JsMsg } from 'nats';
import { z } from 'zod';
import { NatsProvider } from '../../infra/nats.provider';
import {
  INCIDENT_CANDIDATE_SUBJECT,
  INCIDENT_CONSUMER_ACK_WAIT_MS,
  INCIDENT_CONSUMER_DURABLE,
  INCIDENT_CONSUMER_MAX_DELIVER,
  INCIDENTS_STREAM_NAME,
} from './incidents.constants';
import { IncidentsService } from './incidents.service';

const CandidateSchema = z.object({
  schema_version: z.literal(1),
  incident_candidate_id: z.string().uuid(),
  hypothesis_id: z.string().uuid(),
  organisation_id: z.string().min(1),
  site_id: z.string().min(1),
  zone_id: z.string().nullable(),
  threat_state: z.union([z.literal(0), z.literal(1), z.literal(2), z.literal(3), z.literal(4), z.literal(5)]),
  detection_confidence: z.number().min(0).max(1),
  threat_probability: z.number().min(0).max(1),
  potential_impact: z.enum(['LOW', 'MODERATE', 'HIGH', 'EXTREME']),
  operational_severity: z.enum(['SEV1', 'SEV2', 'SEV3', 'SEV4', 'SEV5']),
  supporting_event_ids: z.array(z.string()),
  contradicting_event_ids: z.array(z.string()),
  confidence_explanation: z.string(),
  rule_or_model_versions: z.array(z.string()),
  re_escalation: z.boolean(),
  emission_number: z.number().int().positive(),
  triggering_event_id: z.string(),
  emitted_at: z.string().datetime(),
});

/** Durable, sequential consumer: ack only after incident orchestration commits. */
@Injectable()
export class IncidentsConsumer implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(IncidentsConsumer.name);
  private readonly codec = JSONCodec<unknown>();
  private messages: ConsumerMessages | undefined;
  private loop: Promise<void> | undefined;
  private stopping = false;

  constructor(
    @Inject(NatsProvider) private readonly nats: NatsProvider,
    @Inject(IncidentsService) private readonly incidents: IncidentsService,
  ) {}

  async onApplicationBootstrap(): Promise<void> {
    // FusionPublisher creates SENTINEL_FUSION in its onModuleInit hook. Wait
    // until all modules have completed that phase before looking up the
    // dependent stream; otherwise a fast incident consumer can start first,
    // log "stream not found", and never begin consuming.
    await this.start().catch((error: unknown) => this.logger.error(`Incident consumer failed to start: ${message(error)}`));
  }

  async onModuleDestroy(): Promise<void> {
    this.stopping = true;
    this.messages?.stop();
    if (this.loop) await this.loop.catch(() => undefined);
  }

  async start(): Promise<void> {
    if (this.messages || !this.nats.isConfigured()) return;
    const nc = await this.nats.getConnection();
    const jsm = await nc.jetstreamManager();
    try {
      await jsm.consumers.info(INCIDENTS_STREAM_NAME, INCIDENT_CONSUMER_DURABLE);
    } catch {
      await jsm.consumers.add(INCIDENTS_STREAM_NAME, {
        durable_name: INCIDENT_CONSUMER_DURABLE,
        ack_policy: AckPolicy.Explicit,
        deliver_policy: DeliverPolicy.All,
        filter_subject: INCIDENT_CANDIDATE_SUBJECT,
        ack_wait: nanos(INCIDENT_CONSUMER_ACK_WAIT_MS),
        max_deliver: INCIDENT_CONSUMER_MAX_DELIVER,
      });
    }
    const consumer = await nc.jetstream().consumers.get(INCIDENTS_STREAM_NAME, INCIDENT_CONSUMER_DURABLE);
    this.messages = await consumer.consume();
    this.stopping = false;
    this.loop = this.run(this.messages);
  }

  private async run(messages: ConsumerMessages): Promise<void> {
    try {
      for await (const msg of messages) {
        if (this.stopping) break;
        await this.handle(msg);
      }
    } catch (error) {
      if (!this.stopping) this.logger.error(`Incident consumer loop ended: ${message(error)}`);
    }
  }

  /** Public test seam: poison payloads terminate, transient orchestration failures nak. */
  async handle(msg: JsMsg): Promise<void> {
    let raw: unknown;
    try {
      raw = this.codec.decode(msg.data);
    } catch (error) {
      this.logger.error(`Terminating unparseable incident candidate: ${message(error)}`);
      msg.term();
      return;
    }
    const parsed = CandidateSchema.safeParse(raw);
    if (!parsed.success) {
      this.logger.error(`Terminating invalid incident candidate: ${parsed.error.issues.map((issue) => issue.message).join('; ')}`);
      msg.term();
      return;
    }
    const subjectOrganisationId = organisationIdFromCandidateSubject(msg.subject);
    if (!subjectOrganisationId || subjectOrganisationId !== parsed.data.organisation_id) {
      this.logger.error(`Terminating incident candidate with subject/payload organisation mismatch on ${msg.subject}`);
      msg.term();
      return;
    }
    try {
      await this.incidents.handleCandidate(parsed.data);
      msg.ack();
    } catch (error) {
      this.logger.error(`Retrying incident candidate: ${message(error)}`);
      msg.nak(2000);
    }
  }
}

/** Candidate subjects are exactly sentinel.fusion.incident-candidate.{org}. */
export function organisationIdFromCandidateSubject(subject: string): string | null {
  const segments = subject.split('.');
  return segments.length === 4 && segments[0] === 'sentinel' && segments[1] === 'fusion' && segments[2] === 'incident-candidate' && segments[3]
    ? segments[3]
    : null;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
