import type { NormalisedEvent } from '@sentinel/contracts';

/**
 * Test-only fixture builder for a valid NormalisedEvent. Not a *.spec.ts /
 * *.test.ts file itself, so vitest does not try to run it as a suite.
 */
let counter = 0;

export function makeNormalisedEvent(overrides: Partial<NormalisedEvent> = {}): NormalisedEvent {
  counter += 1;
  const occurredAt = overrides.occurred_at ?? new Date(Date.now() - 1000).toISOString();
  const base: NormalisedEvent = {
    event_id: `evt_test_${Date.now()}_${counter}`,
    schema_version: 1,
    organisation_id: 'org_test',
    site_id: 'site_test',
    zone_id: null,
    source_type: 'camera',
    source_id: 'camera-1',
    source_trust: 'trusted',
    event_type: 'motion.detected',
    confidence: 0.9,
    occurred_at: occurredAt,
    ingested_at: new Date().toISOString(),
    location: {},
    track_ids: [],
    evidence_refs: [],
    metadata: {},
    trace_id: `trace_${Date.now()}_${counter}`,
  };
  return { ...base, ...overrides };
}
