import { describe, it, expect } from 'vitest';
import {
  ThreatStateSchema,
  THREAT_STATE_NAMES,
  PotentialImpactSchema,
  OperationalSeveritySchema,
  ThreatAssessmentSchema,
  HypothesisSchema,
} from './threat';

describe('ThreatStateSchema', () => {
  it('accepts every state 0-5', () => {
    for (const state of [0, 1, 2, 3, 4, 5] as const) {
      expect(ThreatStateSchema.parse(state)).toBe(state);
      expect(THREAT_STATE_NAMES[state]).toBeTypeOf('string');
    }
  });

  it('rejects a state below the boundary (-1)', () => {
    expect(() => ThreatStateSchema.parse(-1)).toThrow();
  });

  it('rejects a state above the boundary (6)', () => {
    expect(() => ThreatStateSchema.parse(6)).toThrow();
  });

  it('rejects a non-integer state', () => {
    expect(() => ThreatStateSchema.parse(2.5)).toThrow();
  });
});

describe('PotentialImpactSchema / OperationalSeveritySchema', () => {
  it('accepts all documented potential-impact values', () => {
    for (const v of ['LOW', 'MODERATE', 'HIGH', 'EXTREME']) {
      expect(PotentialImpactSchema.parse(v)).toBe(v);
    }
  });

  it('rejects an undocumented potential-impact value', () => {
    expect(() => PotentialImpactSchema.parse('CATASTROPHIC')).toThrow();
  });

  it('accepts all documented operational-severity values', () => {
    for (const v of ['SEV1', 'SEV2', 'SEV3', 'SEV4', 'SEV5']) {
      expect(OperationalSeveritySchema.parse(v)).toBe(v);
    }
  });

  it('rejects a lowercase operational-severity value', () => {
    expect(() => OperationalSeveritySchema.parse('sev1')).toThrow();
  });
});

describe('ThreatAssessmentSchema', () => {
  const base = {
    schema_version: 1 as const,
    assessment_id: 'assess_001',
    organisation_id: 'org_abc',
    site_id: 'site_xyz',
    threat_state: 3 as const,
    detection_confidence: 0.9,
    threat_probability: 0.6,
    potential_impact: 'HIGH' as const,
    operational_severity: 'SEV2' as const,
    assessed_at: '2026-08-14T10:00:00Z',
    trace_id: 'trace_001',
  };

  it('accepts a fully valid assessment keeping the four values separate', () => {
    const result = ThreatAssessmentSchema.parse(base);
    expect(result.detection_confidence).toBe(0.9);
    expect(result.threat_probability).toBe(0.6);
    expect(result.potential_impact).toBe('HIGH');
    expect(result.operational_severity).toBe('SEV2');
  });

  it('accepts boundary confidence/probability values of exactly 0 and 1', () => {
    expect(() =>
      ThreatAssessmentSchema.parse({ ...base, detection_confidence: 0, threat_probability: 1 })
    ).not.toThrow();
  });

  it('rejects detection_confidence above 1', () => {
    expect(() => ThreatAssessmentSchema.parse({ ...base, detection_confidence: 1.01 })).toThrow();
  });

  it('rejects threat_probability below 0', () => {
    expect(() => ThreatAssessmentSchema.parse({ ...base, threat_probability: -0.01 })).toThrow();
  });

  it('rejects an out-of-range threat_state', () => {
    expect(() => ThreatAssessmentSchema.parse({ ...base, threat_state: 6 })).toThrow();
  });

  it('rejects a missing trace_id', () => {
    const rest: Record<string, unknown> = { ...base };
    delete rest.trace_id;
    expect(() => ThreatAssessmentSchema.parse(rest)).toThrow();
  });

  it('a highly-confident low-severity assessment and a moderately-confident extreme-impact one are both valid (confidence != severity)', () => {
    const confidentButMinor = {
      ...base,
      detection_confidence: 0.99,
      threat_probability: 0.1,
      potential_impact: 'LOW' as const,
      operational_severity: 'SEV5' as const,
    };
    const moderateButExtreme = {
      ...base,
      detection_confidence: 0.55,
      threat_probability: 0.55,
      potential_impact: 'EXTREME' as const,
      operational_severity: 'SEV1' as const,
    };
    expect(() => ThreatAssessmentSchema.parse(confidentButMinor)).not.toThrow();
    expect(() => ThreatAssessmentSchema.parse(moderateButExtreme)).not.toThrow();
  });
});

describe('HypothesisSchema', () => {
  const base = {
    schema_version: 1 as const,
    hypothesis_id: 'hyp_001',
    incident_candidate_id: 'cand_001',
    type: 'intrusion',
    state: 2 as const,
    source_diversity: 1,
    detection_confidence: 0.7,
    threat_probability: 0.45,
    potential_impact: 'MODERATE' as const,
    operational_severity: 'SEV3' as const,
    confidence_explanation: 'One trusted camera signal, no corroboration yet.',
    created_at: '2026-08-14T10:00:00Z',
    updated_at: '2026-08-14T10:05:00Z',
  };

  it('defaults supporting_event_ids, contradicting_event_ids and rule_or_model_versions to []', () => {
    const result = HypothesisSchema.parse(base);
    expect(result.supporting_event_ids).toEqual([]);
    expect(result.contradicting_event_ids).toEqual([]);
    expect(result.rule_or_model_versions).toEqual([]);
  });

  it('accepts a fully-populated hypothesis with both supporting and contradicting evidence', () => {
    const full = {
      ...base,
      supporting_event_ids: ['evt_1', 'evt_2'],
      contradicting_event_ids: ['evt_3'],
      rule_or_model_versions: ['rules-v1.2.0'],
    };
    const result = HypothesisSchema.parse(full);
    expect(result.supporting_event_ids).toHaveLength(2);
    expect(result.contradicting_event_ids).toHaveLength(1);
  });

  it('rejects a negative source_diversity', () => {
    expect(() => HypothesisSchema.parse({ ...base, source_diversity: -1 })).toThrow();
  });

  it('accepts a boundary source_diversity of 0', () => {
    expect(() => HypothesisSchema.parse({ ...base, source_diversity: 0 })).not.toThrow();
  });

  it('rejects an empty confidence_explanation', () => {
    expect(() => HypothesisSchema.parse({ ...base, confidence_explanation: '' })).toThrow();
  });

  it('rejects updated_at earlier than created_at', () => {
    expect(() =>
      HypothesisSchema.parse({ ...base, created_at: '2026-08-14T10:05:00Z', updated_at: '2026-08-14T10:00:00Z' })
    ).toThrow();
  });

  it('rejects a missing hypothesis_id', () => {
    const rest: Record<string, unknown> = { ...base };
    delete rest.hypothesis_id;
    expect(() => HypothesisSchema.parse(rest)).toThrow();
  });
});
