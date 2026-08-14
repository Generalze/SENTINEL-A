import type { Hypothesis as HypothesisRow, HypothesisTransition as HypothesisTransitionRow } from '@prisma/client';
import { HypothesisSchema } from '@sentinel/contracts';
import { describe, expect, it } from 'vitest';
import { FUSION_RULE_VERSIONS, HYPOTHESIS_TYPE } from './fusion.constants';
import {
  decodeCursor,
  encodeCursor,
  readProcessedSignals,
  toHypothesisDetailView,
  toHypothesisView,
  toOperationalSeverity,
  toPotentialImpact,
  toThreatState,
} from './fusion.mapper';

function row(overrides: Partial<HypothesisRow> = {}): HypothesisRow {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    incidentCandidateId: '22222222-2222-4222-8222-222222222222',
    type: HYPOTHESIS_TYPE,
    organisationId: 'org-1',
    siteId: 'site-1',
    zoneId: 'zone-1',
    zoneKey: 'zone-1',
    correlationKey: 'key',
    windowStart: new Date('2026-08-14T10:00:00.000Z'),
    windowEnd: new Date('2026-08-14T10:15:00.000Z'),
    state: 3,
    detectionConfidence: 0.84,
    threatProbability: 0.75,
    potentialImpact: 'HIGH',
    operationalSeverity: 'SEV3',
    sourceDiversity: 2,
    supportingEventIds: ['evt_a', 'evt_b'],
    contradictingEventIds: ['evt_c'],
    confidenceExplanation: 'because reasons',
    ruleVersions: [...FUSION_RULE_VERSIONS],
    signals: [],
    ignoredSignals: [],
    supportingImpactFamilies: ['PRESENCE'],
    incidentCandidateLatched: true,
    incidentCandidateDeEscalated: false,
    incidentCandidateEmissions: 1,
    transitionCount: 2,
    version: 4,
    createdAt: new Date('2026-08-14T10:01:00.000Z'),
    updatedAt: new Date('2026-08-14T10:09:00.000Z'),
    ...overrides,
  } as HypothesisRow;
}

function transitionRow(overrides: Partial<HypothesisTransitionRow> = {}): HypothesisTransitionRow {
  return {
    id: '33333333-3333-4333-8333-333333333333',
    hypothesisId: '11111111-1111-4111-8111-111111111111',
    organisationId: 'org-1',
    fromState: 0,
    toState: 2,
    eventId: 'evt_a',
    reason: 'recomputed from aggregate threat probability 0.500',
    ruleVersions: [...FUSION_RULE_VERSIONS],
    sequence: 0,
    occurredAt: new Date('2026-08-14T10:01:00.000Z'),
    createdAt: new Date('2026-08-14T10:01:01.000Z'),
    ...overrides,
  } as HypothesisTransitionRow;
}

describe('toHypothesisView — §11.4 structural guarantee', () => {
  it('always emits BOTH evidence arrays, even when each is empty', () => {
    const view = toHypothesisView(row({ supportingEventIds: [], contradictingEventIds: [] }));
    expect(view).toHaveProperty('supporting_event_ids');
    expect(view).toHaveProperty('contradicting_event_ids');
    expect(view.supporting_event_ids).toEqual([]);
    expect(view.contradicting_event_ids).toEqual([]);
  });

  it('emits contradicting evidence even when only supporting evidence exists', () => {
    const view = toHypothesisView(row({ supportingEventIds: ['evt_a'], contradictingEventIds: [] }));
    expect(Object.keys(view)).toContain('contradicting_event_ids');
  });

  it('always emits the confidence explanation and all four separated values', () => {
    const view = toHypothesisView(row());
    expect(view.confidence_explanation).toBe('because reasons');
    expect(view.detection_confidence).toBe(0.84);
    expect(view.threat_probability).toBe(0.75);
    expect(view.potential_impact).toBe('HIGH');
    expect(view.operational_severity).toBe('SEV3');
  });

  it('copies the arrays rather than aliasing the row, so a caller cannot mutate stored state', () => {
    const source = row();
    const view = toHypothesisView(source);
    view.supporting_event_ids.push('injected');
    expect(source.supportingEventIds).toEqual(['evt_a', 'evt_b']);
  });
});

describe('toHypothesisView — contract conformance', () => {
  it('satisfies the @sentinel/contracts Hypothesis schema (§65.3)', () => {
    const parsed = HypothesisSchema.safeParse(toHypothesisView(row()));
    expect(parsed.success).toBe(true);
  });

  it('carries the correlation context and the human-readable state name', () => {
    const view = toHypothesisView(row());
    expect(view.organisation_id).toBe('org-1');
    expect(view.site_id).toBe('site-1');
    expect(view.zone_id).toBe('zone-1');
    expect(view.zone_key).toBe('zone-1');
    expect(view.correlation_window_start).toBe('2026-08-14T10:00:00.000Z');
    expect(view.correlation_window_end).toBe('2026-08-14T10:15:00.000Z');
    expect(view.state_name).toBe('PROBABLE_THREAT');
  });

  it('reports latch state so a consumer can tell a first escalation from a re-escalation', () => {
    expect(toHypothesisView(row({ incidentCandidateEmissions: 0 })).incident_candidate_emitted).toBe(false);
    expect(toHypothesisView(row({ incidentCandidateEmissions: 2 })).incident_candidate_emitted).toBe(true);
    expect(toHypothesisView(row({ incidentCandidateEmissions: 2 })).incident_candidate_emissions).toBe(2);
  });
});

describe('toHypothesisDetailView', () => {
  it('includes the append-only transition log with reasons and rule versions', () => {
    const detail = toHypothesisDetailView(row(), [transitionRow(), transitionRow({ sequence: 1, fromState: 2, toState: 3 })]);
    expect(detail.transitions).toHaveLength(2);
    expect(detail.transitions[0]).toMatchObject({ sequence: 0, from_state: 0, to_state: 2, from_state_name: 'NORMAL', to_state_name: 'SUSPICIOUS' });
    expect(detail.transitions[0].reason.length).toBeGreaterThan(0);
    expect(detail.transitions[1].rule_or_model_versions).toEqual([...FUSION_RULE_VERSIONS]);
    // Contradiction surfacing survives into the detail view too.
    expect(detail.contradicting_event_ids).toEqual(['evt_c']);
  });
});

describe('column narrowing', () => {
  it('accepts every legal value', () => {
    for (const state of [0, 1, 2, 3, 4, 5]) {
      expect(toThreatState(state)).toBe(state);
    }
    expect(toPotentialImpact('EXTREME')).toBe('EXTREME');
    expect(toOperationalSeverity('SEV1')).toBe('SEV1');
  });

  it('throws rather than silently understating a corrupt row', () => {
    expect(() => toThreatState(6)).toThrow(/outside 0\.\.5/);
    expect(() => toThreatState(-1)).toThrow(/outside 0\.\.5/);
    expect(() => toPotentialImpact('CATASTROPHIC')).toThrow(/not a known value/);
    expect(() => toOperationalSeverity('SEV0')).toThrow(/not a known value/);
  });
});

describe('readProcessedSignals', () => {
  it('tolerates a null or non-array JSON column', () => {
    expect(readProcessedSignals(null)).toEqual([]);
    expect(readProcessedSignals({})).toEqual([]);
    expect(readProcessedSignals([{ signalId: 's1' }])).toHaveLength(1);
  });
});

describe('cursor pagination', () => {
  it('round-trips a cursor', () => {
    const cursor = { updatedAt: '2026-08-14T10:09:00.000Z', id: 'abc' };
    expect(decodeCursor(encodeCursor(cursor))).toEqual(cursor);
  });

  it('rejects a malformed cursor', () => {
    expect(() => decodeCursor('not-base64-json')).toThrow(/invalid cursor/i);
    expect(() => decodeCursor(Buffer.from('{"id":"a"}').toString('base64url'))).toThrow(/invalid cursor/i);
  });
});
