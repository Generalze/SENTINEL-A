import { Inject, Injectable, Logger, type OnApplicationBootstrap, type OnModuleDestroy } from '@nestjs/common';
import { AckPolicy, DeliverPolicy, JSONCodec, nanos, type ConsumerMessages, type JsMsg } from 'nats';
import { z } from 'zod';
import { NatsProvider } from '../../infra/nats.provider';
import { HYPOTHESIS_UPDATE_CONSUMER_DURABLE, HYPOTHESIS_UPDATE_SUBJECT, INCIDENTS_STREAM_NAME, INCIDENT_CONSUMER_ACK_WAIT_MS, INCIDENT_CONSUMER_MAX_DELIVER } from './incidents.constants';
import { IncidentNotReadyError, IncidentsService } from './incidents.service';

const HypothesisUpdateSchema = z.object({
  schema_version: z.literal(1), emitted_at: z.string().datetime(), triggering_event_id: z.string().min(1), hypothesis_version: z.number().int().nonnegative(),
  hypothesis: z.object({
    hypothesis_id: z.string().uuid(), organisation_id: z.string().min(1), site_id: z.string().min(1), state: z.number().int().min(0).max(5),
    operational_severity: z.enum(['SEV1', 'SEV2', 'SEV3', 'SEV4', 'SEV5']), threat_probability: z.number().min(0).max(1),
    supporting_event_ids: z.array(z.string()), contradicting_event_ids: z.array(z.string()),
  }),
});

function organisationIdFromHypothesisSubject(subject: string): string | null {
  const p = subject.split('.');
  return p.length === 4 && p[0] === 'sentinel' && p[1] === 'fusion' && p[2] === 'hypothesis' && p[3] ? p[3] : null;
}

/** Keeps the state-2 candidate latch intact while advancing its Incident from later Fusion updates. */
@Injectable()
export class IncidentsHypothesisConsumer implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(IncidentsHypothesisConsumer.name);
  private readonly codec = JSONCodec<unknown>();
  private messages: ConsumerMessages | undefined;
  private loop: Promise<void> | undefined;
  private stopping = false;

  constructor(@Inject(NatsProvider) private readonly nats: NatsProvider, @Inject(IncidentsService) private readonly incidents: IncidentsService) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.start().catch((error: unknown) => this.logger.error(`Hypothesis update consumer failed to start: ${message(error)}`));
  }

  async onModuleDestroy(): Promise<void> {
    this.stopping = true;
    this.messages?.stop();
    await this.loop?.catch(() => undefined);
  }

  private async start(): Promise<void> {
    if (this.messages || !this.nats.isConfigured()) return;
    const nc = await this.nats.getConnection();
    const jsm = await nc.jetstreamManager();
    try { await jsm.consumers.info(INCIDENTS_STREAM_NAME, HYPOTHESIS_UPDATE_CONSUMER_DURABLE); } catch {
      await jsm.consumers.add(INCIDENTS_STREAM_NAME, {
        durable_name: HYPOTHESIS_UPDATE_CONSUMER_DURABLE, ack_policy: AckPolicy.Explicit, deliver_policy: DeliverPolicy.All,
        filter_subject: HYPOTHESIS_UPDATE_SUBJECT, ack_wait: nanos(INCIDENT_CONSUMER_ACK_WAIT_MS), max_deliver: INCIDENT_CONSUMER_MAX_DELIVER,
      });
    }
    const consumer = await nc.jetstream().consumers.get(INCIDENTS_STREAM_NAME, HYPOTHESIS_UPDATE_CONSUMER_DURABLE);
    this.messages = await consumer.consume();
    this.stopping = false;
    this.loop = this.run(this.messages);
  }

  private async run(messages: ConsumerMessages): Promise<void> {
    try { for await (const msg of messages) { if (this.stopping) break; await this.handle(msg); } }
    catch (error) { if (!this.stopping) this.logger.error(`Hypothesis update consumer loop ended: ${message(error)}`); }
  }

  async handle(msg: JsMsg): Promise<void> {
    let raw: unknown;
    try { raw = this.codec.decode(msg.data); } catch { msg.term(); return; }
    const parsed = HypothesisUpdateSchema.safeParse(raw);
    const subjectOrganisationId = organisationIdFromHypothesisSubject(msg.subject);
    if (!parsed.success || !subjectOrganisationId || subjectOrganisationId !== parsed.data.hypothesis.organisation_id) {
      this.logger.error(`Terminating invalid or cross-tenant hypothesis update on ${msg.subject}`);
      msg.term(); return;
    }
    try { await this.incidents.handleHypothesisUpdate(parsed.data); msg.ack(); }
    catch (error) {
      const retry = error instanceof IncidentNotReadyError ? 'incident not ready; retrying hypothesis update' : 'Retrying hypothesis update';
      this.logger.warn(`${retry}: ${message(error)}`); msg.nak(2000);
    }
  }
}

function message(error: unknown): string { return error instanceof Error ? error.message : String(error); }

export { organisationIdFromHypothesisSubject };
