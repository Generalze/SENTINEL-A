import { describe, expect, it } from 'vitest';
import { resolveEventTemplate, resolvePlaceholders, type EventTemplate, type ScenarioContext } from './scenario.js';

function testContext(overrides?: Partial<ScenarioContext>): ScenarioContext {
  return {
    orgId: 'org_test',
    siteId: 'site_test',
    zoneIds: { vault_corridor: 'zone_vault_corridor' },
    traceId: 'trace_test_001',
    runStart: new Date('2026-01-01T00:00:00.000Z'),
    ...overrides,
  };
}

describe('resolvePlaceholders', () => {
  it('resolves {ORG}, {SITE} and {TRACE}', () => {
    const ctx = testContext();
    expect(resolvePlaceholders('{ORG}', ctx)).toBe('org_test');
    expect(resolvePlaceholders('{SITE}', ctx)).toBe('site_test');
    expect(resolvePlaceholders('{TRACE}', ctx)).toBe('trace_test_001');
  });

  it('resolves {ZONE:name} via the zoneIds map', () => {
    const ctx = testContext();
    expect(resolvePlaceholders('{ZONE:vault_corridor}', ctx)).toBe('zone_vault_corridor');
  });

  it('throws when a {ZONE:name} placeholder has no mapping', () => {
    const ctx = testContext({ zoneIds: {} });
    expect(() => resolvePlaceholders('{ZONE:vault_corridor}', ctx)).toThrow(/unknown zone placeholder/i);
  });

  it('resolves {NOW+offset} to an ISO timestamp relative to run start', () => {
    const ctx = testContext();
    expect(resolvePlaceholders('{NOW+0}', ctx)).toBe('2026-01-01T00:00:00.000Z');
    expect(resolvePlaceholders('{NOW+4000}', ctx)).toBe('2026-01-01T00:00:04.000Z');
  });

  it('resolves {NOW-offset} to a timestamp before run start', () => {
    const ctx = testContext();
    expect(resolvePlaceholders('{NOW-1000}', ctx)).toBe('2025-12-31T23:59:59.000Z');
  });

  it('resolves multiple placeholders embedded within one string', () => {
    const ctx = testContext();
    expect(resolvePlaceholders('org={ORG} site={SITE}', ctx)).toBe('org=org_test site=site_test');
  });

  it('leaves plain text without placeholders untouched', () => {
    const ctx = testContext();
    expect(resolvePlaceholders('plain text', ctx)).toBe('plain text');
  });
});

describe('resolveEventTemplate', () => {
  const template: EventTemplate = {
    event_id: 'evt_test-001',
    schema_version: 1,
    organisation_id: '{ORG}',
    site_id: '{SITE}',
    zone_id: '{ZONE:vault_corridor}',
    source_type: 'camera',
    source_id: 'CAM-01',
    source_trust: 'trusted',
    event_type: 'person_detected',
    confidence: 0.78,
    occurred_at: '{NOW+0}',
    ingested_at: '{NOW+200}',
    location: {},
    track_ids: ['P-1'],
    evidence_refs: [],
    metadata: { note: 'near {ZONE:vault_corridor}' },
    trace_id: '{TRACE}',
  };

  it('deep-resolves placeholders in top-level fields and nested metadata', () => {
    const ctx = testContext();
    const resolved = resolveEventTemplate(template, ctx) as Record<string, unknown>;

    expect(resolved.organisation_id).toBe('org_test');
    expect(resolved.site_id).toBe('site_test');
    expect(resolved.zone_id).toBe('zone_vault_corridor');
    expect(resolved.trace_id).toBe('trace_test_001');
    expect(resolved.occurred_at).toBe('2026-01-01T00:00:00.000Z');
    expect(resolved.ingested_at).toBe('2026-01-01T00:00:00.200Z');
    expect(resolved.metadata).toEqual({ note: 'near zone_vault_corridor' });
    // Non-string fields pass through unchanged.
    expect(resolved.confidence).toBe(0.78);
    expect(resolved.track_ids).toEqual(['P-1']);
  });

  it('never leaves placeholder syntax in the resolved output', () => {
    const ctx = testContext();
    const resolved = JSON.stringify(resolveEventTemplate(template, ctx));
    expect(resolved).not.toMatch(/\{ORG\}|\{SITE\}|\{TRACE\}|\{ZONE:|\{NOW/);
  });
});
