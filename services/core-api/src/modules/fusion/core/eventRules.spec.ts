import { describe, expect, it } from 'vitest';
import { FUSION_RULES_VERSION } from '../fusion.constants';
import { makeEvent } from '../test-support';
import {
  EVENT_TYPE_RULES,
  HIGH_IMPACT_FAMILIES,
  RULES_BY_EVENT_TYPE,
  derivePotentialImpact,
  mapEventToSignal,
} from './eventRules';

function mapType(eventType: string, overrides: Parameters<typeof makeEvent>[0] = {}) {
  return mapEventToSignal(makeEvent({ event_type: eventType, ...overrides }));
}

describe('EVENT_TYPE_RULES table integrity', () => {
  it('contains no duplicate event types (enforced at module load)', () => {
    expect(RULES_BY_EVENT_TYPE.size).toBe(EVENT_TYPE_RULES.length);
  });

  it('gives every rule a non-empty rationale, so review can read the table alone', () => {
    for (const rule of EVENT_TYPE_RULES) {
      expect(rule.rationale.length).toBeGreaterThan(20);
    }
  });

  it('permits humanAuthorised on field-report rules only', () => {
    const withHumanFlag = EVENT_TYPE_RULES.filter((rule) => rule.humanAuthorisedFromMetadataFlag !== undefined);
    expect(withHumanFlag.map((rule) => rule.eventType).sort()).toEqual([
      'field.hostile_observation',
      'field.report.hostile',
    ]);
    for (const rule of withHumanFlag) {
      expect(rule.humanAuthorisedFromMetadataFlag).toBe('human_authorised');
      expect(rule.impactFamily).toBe('FIELD');
    }
  });

  it('guards only the valid-access contradiction, and only on schedule_match', () => {
    const guarded = EVENT_TYPE_RULES.filter((rule) => rule.requiresMetadataFlag !== undefined);
    expect(guarded.map((rule) => rule.eventType).sort()).toEqual(['access.granted.valid', 'access_granted_valid']);
    for (const rule of guarded) {
      expect(rule.requiresMetadataFlag).toBe('schedule_match');
      expect(rule.kind).toBe('CONTRADICTING');
    }
  });
});

describe('mapEventToSignal — SUPPORTING rules', () => {
  it.each([
    ['person_detected', 'PRESENCE'],
    ['loitering_detected', 'BEHAVIOUR'],
    ['motion_detected', 'MOTION'],
    ['access_denied_attempt', 'ACCESS'],
    ['zone.restricted.entry', 'ACCESS'],
    ['object.threat_like', 'THREAT_LIKE'],
    ['violence.possible', 'VIOLENCE'],
    ['field.hostile_observation', 'FIELD'],
    ['field.report.hostile', 'FIELD'],
  ])('maps %s to a SUPPORTING signal in the %s impact family', (eventType, family) => {
    const mapping = mapType(eventType);
    expect(mapping.outcome).toBe('signal');
    if (mapping.outcome !== 'signal') return;
    expect(mapping.signal.kind).toBe('SUPPORTING');
    expect(mapping.impactFamily).toBe(family);
  });

  it('copies identity, trust and confidence straight from the event, never from the table', () => {
    const event = makeEvent({
      event_type: 'loitering_detected',
      event_id: 'evt_carry_through',
      source_id: 'cam-77',
      source_type: 'camera',
      source_trust: 'degraded',
      confidence: 0.42,
    });
    const mapping = mapEventToSignal(event);
    expect(mapping.outcome).toBe('signal');
    if (mapping.outcome !== 'signal') return;
    expect(mapping.signal).toMatchObject({
      signalId: 'evt_carry_through',
      sourceId: 'cam-77',
      sourceType: 'camera',
      sourceTrust: 'degraded',
      confidence: 0.42,
    });
  });
});

describe('mapEventToSignal — CONTRADICTING rule', () => {
  it.each(['access_granted_valid', 'access.granted.valid'])(
    'maps %s WITH schedule_match to a CONTRADICTING signal',
    (eventType) => {
      const mapping = mapType(eventType, { metadata: { schedule_match: true } });
      expect(mapping.outcome).toBe('signal');
      if (mapping.outcome !== 'signal') return;
      expect(mapping.signal.kind).toBe('CONTRADICTING');
      // A contradicting signal contributes no impact family — only supporting
      // evidence may raise potential impact.
      expect(mapping.impactFamily).toBeNull();
    },
  );

  it.each([
    ['absent', {}],
    ['false', { schedule_match: false }],
    ['a truthy non-true value', { schedule_match: 'yes' }],
  ])('produces no signal when schedule_match is %s (condition_not_met, recorded)', (_label, metadata) => {
    const mapping = mapType('access_granted_valid', { metadata });
    expect(mapping.outcome).toBe('ignored');
    if (mapping.outcome !== 'ignored') return;
    expect(mapping.reason).toBe('condition_not_met');
    expect(mapping.rule?.eventType).toBe('access_granted_valid');
  });
});

describe('mapEventToSignal — humanAuthorised', () => {
  it('sets humanAuthorised from metadata.human_authorised === true on a field report', () => {
    const mapping = mapType('field.hostile_observation', {
      source_type: 'field',
      metadata: { human_authorised: true },
    });
    expect(mapping.outcome).toBe('signal');
    if (mapping.outcome !== 'signal') return;
    expect(mapping.signal.humanAuthorised).toBe(true);
  });

  it('leaves humanAuthorised false on a field report without the flag', () => {
    const mapping = mapType('field.hostile_observation', { source_type: 'field', metadata: {} });
    expect(mapping.outcome).toBe('signal');
    if (mapping.outcome !== 'signal') return;
    expect(mapping.signal.humanAuthorised).toBe(false);
  });

  it('refuses to set humanAuthorised for an event type whose rule does not declare it', () => {
    // A camera claiming human authorisation must not reach the core's
    // diversity-cap exception.
    const mapping = mapType('person_detected', { metadata: { human_authorised: true } });
    expect(mapping.outcome).toBe('signal');
    if (mapping.outcome !== 'signal') return;
    expect(mapping.signal.humanAuthorised).toBe(false);
  });
});

describe('mapEventToSignal — life safety', () => {
  it('sets lifeSafety from metadata.life_safety === true, for any mapped event type', () => {
    for (const eventType of ['violence.possible', 'person_detected', 'motion_detected']) {
      const mapping = mapType(eventType, { metadata: { life_safety: true } });
      expect(mapping.outcome).toBe('signal');
      if (mapping.outcome !== 'signal') continue;
      expect(mapping.signal.lifeSafety).toBe(true);
    }
  });

  it('leaves lifeSafety false when the flag is absent or not exactly true', () => {
    expect(mapType('violence.possible', { metadata: {} })).toMatchObject({
      signal: { lifeSafety: false },
    });
    expect(mapType('violence.possible', { metadata: { life_safety: 'true' } })).toMatchObject({
      signal: { lifeSafety: false },
    });
  });
});

describe('mapEventToSignal — unknown event types', () => {
  it('produces no signal and reports no_rule, so the event is ignored but recorded', () => {
    const mapping = mapType('weather.forecast.updated');
    expect(mapping.outcome).toBe('ignored');
    if (mapping.outcome !== 'ignored') return;
    expect(mapping.reason).toBe('no_rule');
    expect(mapping.rule).toBeNull();
  });

  it('matches event types exactly — no prefix or substring matching', () => {
    expect(mapType('person_detected_v2').outcome).toBe('ignored');
    expect(mapType('zone.restricted.entry.attempt').outcome).toBe('ignored');
  });
});

describe('rule version stamping', () => {
  it('stamps the current rule-table version on every mapping outcome', () => {
    expect(mapType('person_detected').ruleVersion).toBe(FUSION_RULES_VERSION);
    expect(mapType('unknown.type').ruleVersion).toBe(FUSION_RULES_VERSION);
    expect(mapType('access_granted_valid').ruleVersion).toBe(FUSION_RULES_VERSION);
  });

  it('pins the version string, so a table change without a bump fails here', () => {
    expect(FUSION_RULES_VERSION).toBe('fusion-rules-1.0.0');
  });
});

describe('derivePotentialImpact (M1 placeholder rule)', () => {
  it('returns MODERATE when no high-impact family has contributed', () => {
    expect(derivePotentialImpact([])).toBe('MODERATE');
    expect(derivePotentialImpact(['PRESENCE', 'MOTION', 'BEHAVIOUR'])).toBe('MODERATE');
  });

  it.each(HIGH_IMPACT_FAMILIES)('returns HIGH once the %s family is present', (family) => {
    expect(derivePotentialImpact(['PRESENCE', family])).toBe('HIGH');
  });

  it('is monotonic: adding families can never lower the impact', () => {
    expect(derivePotentialImpact(['ACCESS'])).toBe('HIGH');
    expect(derivePotentialImpact(['ACCESS', 'PRESENCE', 'MOTION'])).toBe('HIGH');
  });

  it('never produces LOW or EXTREME in M1', () => {
    const everyFamily = EVENT_TYPE_RULES.map((rule) => rule.impactFamily);
    expect(['MODERATE', 'HIGH']).toContain(derivePotentialImpact(everyFamily));
    expect(['MODERATE', 'HIGH']).toContain(derivePotentialImpact([]));
  });
});
