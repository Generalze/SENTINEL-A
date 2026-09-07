/**
 * WP-30 — TALKING TO CENTRAL, AND THE TWO ROUTES THAT MUST NOT BE CONFUSED.
 *
 * A scenario reaches central two different ways, and which one it uses is a
 * substantive choice rather than a convenience:
 *
 *   THROUGH THE WAN (`ENDPOINTS.centralThroughWan`)
 *       What a client behind the severable link experiences. Subject to the
 *       wan-link's mode, so this is the route a phase-8 request takes and the
 *       route whose response can be destroyed. Anything a scenario claims
 *       about client experience must go this way.
 *
 *   DIRECTLY (`ENDPOINTS.centralDirect`)
 *       The harness's OUT-OF-BAND channel, over a published port that bypasses
 *       every user-defined network. This is how the harness asks what central
 *       actually committed while the WAN is down. A witness that lost its view
 *       of the system at the exact moment of the outage would be no witness at
 *       all.
 *
 * Using the direct route to SEND an operation a scenario then treats as having
 * come from the field would be forging the very thing under test, so the two
 * are separate methods with separate names rather than a base-URL parameter.
 *
 * EVERY SCENARIO OWNS ITS OWN NAMESPACE.
 * --------------------------------------
 * `uniqueNamespace()` mints a fresh `(organisation, site, user, device)` tuple
 * per scenario. Nothing here depends on execution order, nothing cleans up
 * after anything else, and two scenarios running in either order — or the same
 * scenario run twice against a database somebody forgot to tear down —
 * converge on the same result. This is the discipline that made the M2 live
 * suites survivable and it is not relaxed for a heavyweight suite.
 */

import { randomUUID } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { seedIdentity } from '../../../services/core-api/src/modules/identity/seed';
import { ENDPOINTS } from './topology';

export interface Namespace {
  readonly organisationId: string;
  readonly siteId: string;
  readonly zoneId: string;
  /**
   * A seeded human operator, used with the dev-auth header.
   *
   * NOT A DEVICE. Nothing in this harness constructs an authenticated device
   * context, injects a device key, or signs on a device's behalf — those are
   * the exact defects Proof C and Proof D exist to detect, and a harness that
   * committed them would be manufacturing the evidence it was built to gather.
   * The `operator` role is what grants `event.ingest`; that is the whole
   * reason it is this role and not another.
   */
  readonly operatorUserId: string;
  readonly sourceId: string;
}

export function uniqueNamespace(label: string): Namespace {
  // A UUID, not a counter and not a timestamp. A counter collides across
  // parallel workers; a timestamp collides when two scenarios start inside the
  // same millisecond, which is exactly what happens when a suite starts.
  const id = randomUUID().replace(/-/g, '').slice(0, 12);
  const suffix = `${label}_${id}`;
  return {
    organisationId: `wp30_org_${suffix}`,
    siteId: `wp30_site_${suffix}`,
    zoneId: `wp30_zone_${suffix}`,
    operatorUserId: `wp30_operator_${suffix}`,
    sourceId: `wp30_source_${suffix}`,
  };
}

/**
 * Seed the namespace directly into the harness database.
 *
 * DIRECTLY, because there is no other way: every identity endpoint on central
 * is guarded, and `DevAuthGuard` resolves its principal by looking the header's
 * user id up in the database — so the first user cannot be created through an
 * API that requires a user to exist. proof-a solves this the same way, by
 * calling `seedIdentity` against Prisma.
 *
 * The reuse of `seedIdentity` is the point rather than a shortcut. A harness
 * that wrote its own INSERTs would encode a second, drifting opinion about
 * what an organisation, a site and a role assignment are, and would keep
 * passing after the real one changed shape.
 *
 * The caller owns the client's lifetime: opening one per scenario would leave
 * a connection per test against a database the suite is also restarting.
 */
export async function seedNamespace(prisma: PrismaClient, namespace: Namespace): Promise<void> {
  await seedIdentity(prisma, {
    organisation: { id: namespace.organisationId, name: 'WP-30 WAN-loss harness' },
    site: { id: namespace.siteId, name: 'WP-30 site' },
    zones: [{ id: namespace.zoneId, name: 'WP-30 zone' }],
    users: [
      {
        id: namespace.operatorUserId,
        email: `${namespace.operatorUserId}@wp30.test`,
        displayName: 'WP-30 operator',
        clearance: 5,
        role: 'operator',
        siteScoped: true,
      },
    ],
  });
}

/** A Prisma client bound to the HARNESS database, never the shared dev one. */
export function harnessPrisma(): PrismaClient {
  return new PrismaClient({ datasources: { db: { url: ENDPOINTS.databaseUrl } } });
}

/**
 * A §40 normalised event, complete and valid.
 *
 * `occurredAt` is supplied by the caller and threaded into the payload because
 * it is part of central's idempotency key — `deriveIdempotencyKey(org, site,
 * source, event_id, occurred_at, window)`. A retry that re-generated it would
 * derive a DIFFERENT key, central would treat the replay as a new event, and
 * the scenario would "prove" duplicate suppression by never asking for it.
 * That is the single easiest way to write a phase-8 test that passes while
 * testing nothing, so the value is an explicit parameter rather than a default.
 */
export function buildEvent(
  namespace: Namespace,
  eventId: string,
  occurredAt: string,
): Record<string, unknown> {
  return {
    event_id: eventId,
    schema_version: 1,
    organisation_id: namespace.organisationId,
    site_id: namespace.siteId,
    zone_id: namespace.zoneId,
    source_type: 'field',
    source_id: namespace.sourceId,
    source_trust: 'trusted',
    event_type: 'wp30.wan_loss.probe',
    confidence: 0.9,
    occurred_at: occurredAt,
    ingested_at: occurredAt,
    location: {},
    track_ids: [],
    evidence_refs: [],
    metadata: { harness: 'wp30-wan-loss' },
    trace_id: `wp30-${eventId}`,
  };
}

/**
 * THE HONEST OUTCOME TYPE.
 *
 * `UNKNOWN` is a first-class result, not an error. When the response is
 * destroyed on the return path the client genuinely does not know whether its
 * operation took effect, and any type that forced that into `success` or
 * `failure` would be a lie told by the harness before a single assertion ran.
 *
 * Note what `UNKNOWN` does NOT contain: a status, a body, or an
 * `original_event_id`. There is nothing to put there. A scenario that reaches
 * `UNKNOWN` must go and ASK central what happened — which is exactly the
 * recovery behaviour Proof D is about.
 */
export type SubmitOutcome =
  | { kind: 'COMMITTED'; status: number; body: unknown; at: string }
  | { kind: 'REFUSED'; status: number; body: unknown; at: string }
  | { kind: 'UNKNOWN'; transportError: string; at: string };

/**
 * THE CLIENT TIMEOUT, WHICH IS NOT A TEST WAIT — AND THE ONE PLACE IN THIS
 * HARNESS WHERE THE DISTINCTION HAS TO BE ARGUED RATHER THAN ASSUMED.
 *
 * `fetch` has no default timeout. Against the wan-link's `blackhole` mode —
 * where the request is never forwarded and no response is ever sent — a
 * submission with no bound hangs until the test runner kills it. That is not a
 * hypothetical: it is exactly how the partner-case scenario first failed.
 *
 * Bounding it is not a concession to timing. It is the correct model of the
 * situation: a client behind a swallowed WAN learns nothing from the network
 * and must eventually decide for itself that it has no answer. A real Field or
 * Edge client will need precisely this bound in production, for precisely this
 * reason. What matters is that the bound produces an OUTCOME (`UNKNOWN`) and
 * that no assertion anywhere reads how long it took to get there — the
 * scenarios assert what the client concluded and what central holds, never a
 * duration.
 *
 * 15 seconds is generous relative to any request central actually serves —
 * including a cold first query while Prisma opens its pool — so a slow CI
 * runner produces a slow pass, never a false `UNKNOWN`.
 */
const CLIENT_TIMEOUT_MS = 15_000;

async function submit(baseUrl: string, namespace: Namespace, event: Record<string, unknown>): Promise<SubmitOutcome> {
  // `AbortController` + `setTimeout` rather than `AbortSignal.timeout`: both
  // are registered globals in this repository's shared ESLint config, and a
  // test harness has no business being the reason that config changes.
  const controller = new AbortController();
  const bound = setTimeout(() => controller.abort(), CLIENT_TIMEOUT_MS);
  try {
    const response = await fetch(`${baseUrl}/api/v1/events`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-dev-user-id': namespace.operatorUserId,
      },
      body: JSON.stringify(event),
      signal: controller.signal,
    });
    const at = new Date().toISOString();
    const body = await response.json().catch(() => null);
    // 2xx is a decision central made and communicated. A 4xx is ALSO a decision
    // it made and communicated, and lumping the two together as "not UNKNOWN"
    // would lose the distinction Proof D cares most about — a refusal is a
    // system still enforcing, which is the opposite of a system that failed.
    return response.ok
      ? { kind: 'COMMITTED', status: response.status, body, at }
      : { kind: 'REFUSED', status: response.status, body, at };
  } catch (error) {
    // A transport failure is the ONLY thing that produces UNKNOWN. The client
    // reached no conclusion — the socket died, or it gave up waiting for an
    // answer that never came. Whether central committed is, from here,
    // genuinely unknowable, and saying so is the honest result.
    return {
      kind: 'UNKNOWN',
      transportError: error instanceof Error ? (error.cause instanceof Error ? error.cause.message : error.message) : String(error),
      at: new Date().toISOString(),
    };
  } finally {
    // Always cleared. A pending timer holding a reference to an AbortController
    // keeps the event loop alive, and a suite that would not exit is a suite
    // that looks like a hang rather than a pass.
    clearTimeout(bound);
  }
}

/** Submit as a client BEHIND the WAN. Subject to the wan-link's mode. */
export async function submitThroughWan(namespace: Namespace, event: Record<string, unknown>): Promise<SubmitOutcome> {
  return submit(ENDPOINTS.centralThroughWan, namespace, event);
}

/** Submit out-of-band. Used only where a scenario needs a baseline, never to forge field traffic. */
export async function submitDirect(namespace: Namespace, event: Record<string, unknown>): Promise<SubmitOutcome> {
  return submit(ENDPOINTS.centralDirect, namespace, event);
}

export interface StoredEvent {
  readonly id: string;
  readonly event_id: string;
  readonly received_count: number;
  readonly published_at: string | null;
}

/**
 * ASK CENTRAL WHAT IT ACTUALLY HOLDS. The out-of-band route, always.
 *
 * This is the query behind the domain invariant every honest-disjunction
 * assertion in this suite is anchored to: whatever the client believes, the
 * number of CANONICAL events central holds for a given `event_id` must never
 * exceed one. Duplicate deliveries are recorded — that is what
 * `received_count` counts, and preserving the fact that a redelivery happened
 * is deliberate — but they never become a second effect.
 */
export async function canonicalEvents(namespace: Namespace, eventId: string): Promise<StoredEvent[]> {
  const url = new URL(`${ENDPOINTS.centralDirect}/api/v1/events`);
  url.searchParams.set('site_id', namespace.siteId);
  url.searchParams.set('limit', '100');
  const response = await fetch(url, { headers: { 'x-dev-user-id': namespace.operatorUserId } });
  if (!response.ok) {
    throw new Error(`central list failed: HTTP ${response.status} ${await response.text()}`);
  }
  const body = (await response.json()) as { items: StoredEvent[] };
  return body.items.filter((item) => item.event_id === eventId);
}
