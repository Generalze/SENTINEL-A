import { Inject, Injectable, Logger, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import type { Msg } from 'nats';
import { NatsProvider } from '../../infra/nats.provider';
import { type BackoffOptions, withRetryBackoff } from './backoff.util';
import { pickWhitelistedFields } from './payload-whitelist.util';
import { RealtimeGateway } from './realtime.gateway';
import { NATS_SUBJECT_HYPOTHESIS, NATS_SUBJECT_INCIDENT, SUBJECT_ORG_ID_SEGMENT_INDEX, WS_EVENT_HYPOTHESIS_UPDATED, WS_EVENT_INCIDENT_UPDATED } from './realtime.constants';

interface SubjectRoute {
  readonly subject: string;
  readonly event: string;
}

const ROUTES: readonly SubjectRoute[] = [
  { subject: NATS_SUBJECT_HYPOTHESIS, event: WS_EVENT_HYPOTHESIS_UPDATED },
  { subject: NATS_SUBJECT_INCIDENT, event: WS_EVENT_INCIDENT_UPDATED },
];

function orgIdFromSubject(subject: string): string | undefined {
  const parts = subject.split('.');
  const orgId = parts[SUBJECT_ORG_ID_SEGMENT_INDEX];
  return parts.length > SUBJECT_ORG_ID_SEGMENT_INDEX && orgId && orgId.length > 0 ? orgId : undefined;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Deliverable #3: bridges NATS -> the org-scoped WS rooms. Subscribes
 * (plain, non-JetStream — see `realtime.constants.ts`) to both
 * `sentinel.fusion.hypothesis.>` and `sentinel.incidents.updated.>`, and
 * forwards each message to `org:{organisation_id}` (parsed from the
 * concrete subject the message arrived on) as `hypothesis.updated` /
 * `incident.updated`, whitelist-filtered.
 *
 * Deliverable #5: never crashes the API when NATS is down or restarts.
 * Establishing each subscription goes through `withRetryBackoff`
 * (exponential backoff, capped) so a NATS outage at boot is retried
 * forever rather than failing app startup or giving up. If an established
 * subscription's message loop ends unexpectedly (e.g. the underlying
 * connection drops on a NATS restart), that is treated exactly like an
 * initial failure and retried the same way — WS clients themselves are
 * untouched by any of this (their socket.io connection to this API is
 * independent of the API's connection to NATS).
 */
@Injectable()
export class RealtimeNatsBridgeService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RealtimeNatsBridgeService.name);
  private stopped = false;
  /** Test-only seam (see realtime-nats-bridge.service.spec.ts) — keeps retries fast without touching the pure backoff util. */
  private backoffOptions: BackoffOptions | undefined;

  constructor(
    @Inject(NatsProvider) private readonly nats: NatsProvider,
    @Inject(RealtimeGateway) private readonly gateway: RealtimeGateway,
  ) {}

  onModuleInit(): void {
    if (!this.nats.isConfigured()) {
      this.logger.warn('NATS not configured; realtime bridge will not receive fusion/incident updates');
      return;
    }
    for (const route of ROUTES) {
      void this.runSubscriptionLoop(route);
    }
  }

  onModuleDestroy(): void {
    this.stopped = true;
  }

  /** Test-only: overrides the default backoff timing so retry tests don't wait for real delays. */
  setBackoffOptionsForTesting(options: BackoffOptions): void {
    this.backoffOptions = options;
  }

  private async runSubscriptionLoop(route: SubjectRoute): Promise<void> {
    while (!this.stopped) {
      const sub = await withRetryBackoff({
        isStopped: () => this.stopped,
        options: this.backoffOptions,
        attempt: async () => {
          const nc = await this.nats.getConnection();
          const subscription = nc.subscribe(route.subject);
          this.logger.log(`subscribed to ${route.subject}`);
          return subscription;
        },
        onAttemptError: (error, attemptNumber, delayMs) => {
          this.logger.warn(`subscribe to ${route.subject} failed (attempt ${attemptNumber}): ${errorMessage(error)} — retrying in ${delayMs}ms`);
        },
      });

      if (!sub || this.stopped) {
        return;
      }

      for await (const msg of sub) {
        if (this.stopped) {
          break;
        }
        this.handleMessage(route, msg);
      }

      if (this.stopped) {
        return;
      }
      this.logger.warn(`subscription to ${route.subject} ended (NATS connection likely dropped); resubscribing`);
    }
  }

  private handleMessage(route: SubjectRoute, msg: Msg): void {
    const organisationId = orgIdFromSubject(msg.subject);
    if (!organisationId) {
      this.logger.warn(`dropping message on ${msg.subject}: could not determine organisation_id from subject`);
      return;
    }

    let raw: unknown;
    try {
      raw = msg.json();
    } catch (error) {
      this.logger.warn(`dropping malformed (non-JSON) message on ${msg.subject}: ${errorMessage(error)}`);
      return;
    }

    const payload = pickWhitelistedFields(raw, organisationId);
    this.gateway.broadcastToOrg(organisationId, route.event, payload);
  }
}
