/**
 * Fusion correlation (WP-05 deliverable #1, architecture §65.2).
 *
 * Pure and transparent — no ML, no learned similarity, no hidden state
 * (§65.1). Everything here is a deterministic function of the event's own
 * fields, so any operator can be told exactly why two events were correlated
 * and reproduce the answer by hand.
 *
 * FUSION v1 CORRELATION KEY
 * -------------------------
 *   (organisation_id, site_id, zone_id ?? 'site-wide',
 *    15-minute tumbling window over occurred_at)
 *
 * Of the §65.2 correlation dimensions, v1 uses exactly two:
 *   - "Common organisation/site/zone"  -> the first three components.
 *   - "Time overlap and sequence"      -> the tumbling window.
 * The remaining dimensions (route connectivity, shared tracks, shared
 * credential, campaign similarity, operational schedule) are deliberately
 * NOT used for grouping in v1. Source independence/trust and contradictory
 * evidence ARE used, but inside the threat-state core rather than as
 * grouping keys. Cross-site correlation is explicitly out of scope for this
 * work package.
 *
 * WHY TUMBLING AND NOT SLIDING
 * ----------------------------
 * A tumbling window gives every event exactly one window, computed from the
 * event alone with no reference to any other event or to any existing
 * hypothesis. That is what makes the key safe to use as a UNIQUE database
 * column and makes ingestion order irrelevant: replaying the same events in
 * any order, in one batch or across a restart, produces the same grouping.
 * A sliding/session window would make an event's group depend on what else
 * had already arrived, which is not reproducible under redelivery.
 *
 * The accepted trade-off is a boundary effect: two events 30 seconds apart
 * can fall either side of a window edge and form two hypotheses. v1 accepts
 * this in exchange for determinism; a later milestone can add explicit
 * hypothesis merging, which is a strictly additive change.
 */

import { CORRELATION_WINDOW_MS, SITE_WIDE_ZONE } from '../fusion.constants';

/** The identifying fields of an event that participate in correlation. */
export interface CorrelationInput {
  readonly organisation_id: string;
  readonly site_id: string;
  readonly zone_id?: string | null;
  /** ISO-8601 timestamp; the event's own `occurred_at`, never ingest time. */
  readonly occurred_at: string;
}

export interface CorrelationKey {
  readonly organisationId: string;
  readonly siteId: string;
  /** The raw zone id as delivered (may be null). */
  readonly zoneId: string | null;
  /** `zoneId ?? 'site-wide'` — what actually appears in the key. */
  readonly zoneKey: string;
  /** Inclusive start of the tumbling window. */
  readonly windowStart: Date;
  /** Exclusive end of the tumbling window. */
  readonly windowEnd: Date;
  /** Serialised, stable form used as the database UNIQUE key. */
  readonly key: string;
}

/**
 * Floors `occurredAt` to the start of its tumbling window.
 *
 * Windows are anchored at the Unix epoch, so they are absolute wall-clock
 * buckets (…10:00, 10:15, 10:30…) shared by every tenant and every process —
 * there is no per-hypothesis or per-tenant phase to get out of sync.
 * Pre-epoch timestamps floor downward correctly because `Math.floor` is used
 * rather than truncation.
 */
export function windowStartFor(occurredAt: Date, windowMs: number = CORRELATION_WINDOW_MS): Date {
  return new Date(Math.floor(occurredAt.getTime() / windowMs) * windowMs);
}

/**
 * Derives the full correlation key for an event.
 *
 * Throws on an unparseable `occurred_at` rather than silently bucketing to
 * an "Invalid Date": a mis-timed event must be visibly rejected, never
 * quietly correlated into the wrong window.
 */
export function deriveCorrelationKey(
  input: CorrelationInput,
  windowMs: number = CORRELATION_WINDOW_MS,
): CorrelationKey {
  const occurredAt = new Date(input.occurred_at);
  if (Number.isNaN(occurredAt.getTime())) {
    throw new Error(`Cannot correlate event: occurred_at is not a valid timestamp (${input.occurred_at})`);
  }

  const zoneId = input.zone_id ?? null;
  const zoneKey = zoneId ?? SITE_WIDE_ZONE;
  const windowStart = windowStartFor(occurredAt, windowMs);
  const windowEnd = new Date(windowStart.getTime() + windowMs);

  return {
    organisationId: input.organisation_id,
    siteId: input.site_id,
    zoneId,
    zoneKey,
    windowStart,
    windowEnd,
    key: serialiseCorrelationKey(input.organisation_id, input.site_id, zoneKey, windowStart),
  };
}

/**
 * U+001F, the ASCII "unit separator", is the delimiter between correlation-key
 * components rather than a printable character such as `|` or `:`.
 * Organisation/site/zone ids are externally supplied strings, and a printable
 * delimiter would let a caller craft an id containing it so that two different
 * tuples serialise to the same key — a cross-tenant collision on a UNIQUE
 * column. A control character cannot appear in these ids, which reach us as
 * contract-validated non-empty strings from URLs and configuration.
 */
const KEY_SEPARATOR = '\u001f';

/** Serialises the tuple into the string stored in `fusion_hypotheses.correlation_key`. */
export function serialiseCorrelationKey(
  organisationId: string,
  siteId: string,
  zoneKey: string,
  windowStart: Date,
): string {
  return [organisationId, siteId, zoneKey, windowStart.toISOString()].join(KEY_SEPARATOR);
}

/** Human-readable form for logs and explanations (never used as a database key). */
export function describeCorrelationKey(key: CorrelationKey): string {
  return `${key.organisationId}/${key.siteId}/${key.zoneKey} @ ${key.windowStart.toISOString()}..${key.windowEnd.toISOString()}`;
}
