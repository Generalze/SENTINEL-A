import { describe, expect, it } from 'vitest';
import { NormalisedEventSchema } from '@sentinel/contracts';
import { resolveEventTemplate, type ScenarioContext } from '../scenario.js';
import {
  ALL_SCENARIOS,
  duplicateDeliveryV1,
  getScenario,
  proofAIntrusionContradictionV1,
  proofAIntrusionV1,
  singleSourceNoiseV1,
} from './index.js';

function testContext(): ScenarioContext {
  return {
    orgId: 'org_test',
    siteId: 'site_test',
    zoneIds: {
      vault_corridor: 'zone_vault_corridor',
      perimeter_west: 'zone_perimeter_west',
      lobby: 'zone_lobby',
    },
    traceId: 'trace_test_001',
    runStart: new Date('2026-01-01T00:00:00.000Z'),
  };
}

describe('scenario library validates against contracts (acceptance criterion 1)', () => {
  it('the library is non-empty', () => {
    expect(ALL_SCENARIOS.length).toBeGreaterThan(0);
  });

  it.each(ALL_SCENARIOS.map((s, i) => [`${s.name}@${s.version} [variant ${i}]`, s] as const))(
    '%s: every step resolves to a valid NormalisedEvent',
    (_label, scenario) => {
      const ctx = testContext();
      expect(scenario.steps.length).toBeGreaterThan(0);

      for (const step of scenario.steps) {
        const resolved = resolveEventTemplate(step.event, ctx);
        const parsed = NormalisedEventSchema.safeParse(resolved);
        if (!parsed.success) {
          throw new Error(
            `${scenario.name}@${scenario.version} step at ${step.at_offset_ms}ms failed contracts validation: ` +
              parsed.error.message
          );
        }
      }
    }
  );

  it('rejects an event template that resolves to something invalid (guard test)', () => {
    const ctx = testContext();
    const badTemplate = { ...proofAIntrusionV1.steps[0].event, confidence: 1.5 };
    const resolved = resolveEventTemplate(badTemplate, ctx);
    expect(NormalisedEventSchema.safeParse(resolved).success).toBe(false);
  });

  it('throws a clear error for an unknown scenario name', () => {
    expect(() => getScenario('does-not-exist')).toThrow(/unknown scenario/i);
  });

  describe('proof-a-intrusion@1', () => {
    it('has the 4 base steps from §32.1 / §80 in order', () => {
      expect(proofAIntrusionV1.steps).toHaveLength(4);
      expect(proofAIntrusionV1.steps.map((s) => s.event.event_type)).toEqual([
        'person_detected',
        'access_denied_attempt',
        'loitering_detected',
        'field.hostile_observation',
      ]);
      expect(proofAIntrusionV1.steps.map((s) => s.at_offset_ms)).toEqual([0, 4_000, 9_000, 14_000]);
    });

    it('draws on at least 3 distinct source types (camera, access, field)', () => {
      const sourceTypes = new Set(proofAIntrusionV1.steps.map((s) => s.event.source_type));
      expect(sourceTypes).toEqual(new Set(['camera', 'access', 'field']));
    });

    it('resolves placeholders correctly for org/site/zone/trace', () => {
      const ctx = testContext();
      const resolved = resolveEventTemplate(proofAIntrusionV1.steps[0].event, ctx) as Record<string, unknown>;
      expect(resolved.organisation_id).toBe('org_test');
      expect(resolved.site_id).toBe('site_test');
      expect(resolved.zone_id).toBe('zone_vault_corridor');
      expect(resolved.trace_id).toBe('trace_test_001');
    });

    it('getScenario(..., { contradiction: true }) returns the contradiction variant', () => {
      expect(getScenario('proof-a-intrusion', { contradiction: true })).toBe(proofAIntrusionContradictionV1);
      expect(getScenario('proof-a-intrusion')).toBe(proofAIntrusionV1);
    });

    it('the contradiction variant appends exactly one honest, valid access grant', () => {
      expect(proofAIntrusionContradictionV1.steps).toHaveLength(5);
      expect(proofAIntrusionContradictionV1.steps.slice(0, 4)).toEqual(proofAIntrusionV1.steps);

      const extra = proofAIntrusionContradictionV1.steps[4];
      expect(extra.event.event_type).toBe('access_granted_valid');
      expect(extra.event.source_id).toBe('ACC-02');
      expect(extra.event.metadata).toMatchObject({ schedule_match: true });
      expect(extra.event.confidence).toBe(0.97);
      // The simulator emits this honestly; it does not tag any resolved "kind".
      expect(extra.event.metadata).not.toHaveProperty('kind');
    });
  });

  describe('single-source-noise@1', () => {
    it('has 6 supporting events all from the same single source', () => {
      expect(singleSourceNoiseV1.steps).toHaveLength(6);
      const sourceIds = new Set(singleSourceNoiseV1.steps.map((s) => s.event.source_id));
      expect(sourceIds.size).toBe(1);
    });

    it('offsets are strictly increasing', () => {
      const offsets = singleSourceNoiseV1.steps.map((s) => s.at_offset_ms);
      for (let i = 1; i < offsets.length; i++) {
        expect(offsets[i]).toBeGreaterThan(offsets[i - 1]);
      }
    });
  });

  describe('duplicate-delivery@1', () => {
    it('posts the identical event 3 times (same event_id and occurred_at)', () => {
      expect(duplicateDeliveryV1.steps).toHaveLength(3);
      const eventIds = new Set(duplicateDeliveryV1.steps.map((s) => s.event.event_id));
      expect(eventIds.size).toBe(1);
      const occurredAts = new Set(duplicateDeliveryV1.steps.map((s) => s.event.occurred_at));
      expect(occurredAts.size).toBe(1);
    });

    it('sends the 3 deliveries at different offsets', () => {
      const offsets = duplicateDeliveryV1.steps.map((s) => s.at_offset_ms);
      expect(new Set(offsets).size).toBe(3);
    });
  });
});
