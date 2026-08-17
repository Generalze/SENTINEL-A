import { Inject, Injectable, Logger, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import type { Msg } from 'nats';
import { NatsProvider } from '../../infra/nats.provider';
import { type BackoffOptions, withRetryBackoff } from './backoff.util';
import { pickFieldRealtimeFields, pickWhitelistedFields } from './payload-whitelist.util';
import { RealtimeGateway } from './realtime.gateway';
import {
  fieldOrgWideRoom,
  fieldSiteRoom,
  FIELD_SUBJECT_SEGMENTS,
  NATS_SUBJECT_FIELD,
  NATS_SUBJECT_HYPOTHESIS,
  NATS_SUBJECT_INCIDENT,
  ORG_SUBJECT_SEGMENTS,
  SUBJECT_ORG_ID_SEGMENT_INDEX,
  SUBJECT_SITE_ID_SEGMENT_INDEX,
  WS_EVENT_FIELD_UPDATED,
  WS_EVENT_HYPOTHESIS_UPDATED,
  WS_EVENT_INCIDENT_UPDATED,
} from './realtime.constants';

/** `org` fans out to the whole organisation room; `field` fans out to site-scoped Field rooms (WP-17/D2). */
type RouteScope = 'org' | 'field';

interface SubjectRoute {
  readonly subject: string;
  readonly event: string;
  readonly scope: RouteScope;
  /** Exact number of dot-separated segments a subject on this route must have (C7-08). */
  readonly segments: number;
}

const ROUTES: readonly SubjectRoute[] = [
  { subject: NATS_SUBJECT_HYPOTHESIS, event: WS_EVENT_HYPOTHESIS_UPDATED, scope: 'org', segments: ORG_SUBJECT_SEGMENTS },
  { subject: NATS_SUBJECT_INCIDENT, event: WS_EVENT_INCIDENT_UPDATED, scope: 'org', segments: ORG_SUBJECT_SEGMENTS },
  { subject: NATS_SUBJECT_FIELD, event: WS_EVENT_FIELD_UPDATED, scope: 'field', segments: FIELD_SUBJECT_SEGMENTS },
];

/**
 * C7-08: parses a subject only if it has exactly the arity its route declares.
 * The subscriptions themselves now use single-token wildcards, so a surplus
 * segment should never arrive; this is the second half of failing closed, and
 * it means an index-based read can never silently pick a token out of a subject
 * shaped differently from the one the builders produce.
 */
function segmentsOfExactArity(subject: string, expected: number): readonly string[] | undefined {
  const parts = subject.split('.');
  if (parts.length !== expected) {
    return undefined;
  }
  return parts.every((part) => part.length > 0) ? parts : undefined;
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
      this.logger.warn('NATS not configured; realtime bridge will not receive fusion/incident/field updates');
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
    // C7-08: exact arity or nothing. A Field message is site-scoped or it is
    // not delivered — there is deliberately no organisation-wide fallback,
    // because falling back would turn a malformed subject into the exact
    // cross-site fanout this route exists to remove.
    const segments = segmentsOfExactArity(msg.subject, route.segments);
    if (!segments) {
      this.logger.warn(`dropping message on ${msg.subject}: expected exactly ${route.segments} non-empty subject segments`);
      return;
    }

    const organisationId = segments[SUBJECT_ORG_ID_SEGMENT_INDEX];
    const siteId = route.scope === 'field' ? segments[SUBJECT_SITE_ID_SEGMENT_INDEX] : undefined;
    if (!organisationId || (route.scope === 'field' && !siteId)) {
      this.logger.warn(`dropping message on ${msg.subject}: could not determine scope from subject`);
      return;
    }

    let raw: unknown;
    try {
      raw = msg.json();
    } catch (error) {
      this.logger.warn(`dropping malformed (non-JSON) message on ${msg.subject}: ${errorMessage(error)}`);
      return;
    }

    if (route.scope === 'field' && siteId) {
      this.gateway.broadcastToRooms(
        [fieldSiteRoom(organisationId, siteId), fieldOrgWideRoom(organisationId)],
        route.event,
        pickFieldRealtimeFields(raw, organisationId, siteId),
      );
      return;
    }

    this.gateway.broadcastToOrg(organisationId, route.event, pickWhitelistedFields(raw, organisationId));
  }
}
