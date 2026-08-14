import { SCHEMA_VERSION, type NormalisedEvent } from '@sentinel/contracts';
import type { EventTemplate } from '../scenario.js';

export interface EventTemplateInput {
  readonly event_id: string;
  readonly source_id: string;
  readonly source_type: NormalisedEvent['source_type'];
  readonly source_trust?: NormalisedEvent['source_trust'];
  readonly event_type: string;
  readonly confidence: number;
  /** Offset (ms, relative to run start) this event's occurred_at reflects. */
  readonly offset_ms: number;
  /** Zone name, resolved via the {ZONE:name} placeholder. Omit for a site-wide event. */
  readonly zone?: string;
  readonly track_ids?: string[];
  readonly metadata?: Record<string, unknown>;
  /** ingested_at = occurred_at + this many ms. Defaults to 200 (WP-10). */
  readonly ingest_lag_ms?: number;
}

/**
 * Builds one scenario event template. `organisation_id`, `site_id`,
 * `zone_id` and `trace_id` are left as placeholders resolved by the runner;
 * `occurred_at`/`ingested_at` are expressed as `{NOW+offset}` placeholders so
 * they anchor to the actual run-start timestamp rather than a fixed date.
 */
export function eventTemplate(input: EventTemplateInput): EventTemplate {
  const ingestLagMs = input.ingest_lag_ms ?? 200;

  return {
    event_id: input.event_id,
    schema_version: SCHEMA_VERSION,
    organisation_id: '{ORG}',
    site_id: '{SITE}',
    zone_id: input.zone ? `{ZONE:${input.zone}}` : null,
    source_type: input.source_type,
    source_id: input.source_id,
    source_trust: input.source_trust ?? 'trusted',
    event_type: input.event_type,
    confidence: input.confidence,
    occurred_at: `{NOW+${input.offset_ms}}`,
    ingested_at: `{NOW+${input.offset_ms + ingestLagMs}}`,
    location: {},
    track_ids: input.track_ids ?? [],
    evidence_refs: [],
    metadata: input.metadata ?? {},
    trace_id: '{TRACE}',
  };
}
