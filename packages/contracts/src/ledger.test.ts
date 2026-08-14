import { describe, it, expect } from 'vitest';
import { DecisionLedgerEntrySchema } from './ledger';

describe('DecisionLedgerEntrySchema', () => {
  const base = {
    schema_version: 1 as const,
    entry_id: 'ledger_001',
    organisation_id: 'org_abc',
    decided_at: '2026-08-14T10:00:00Z',
    decision_type: 'response_authorisation',
    inputs_snapshot: { hypothesis_id: 'hyp_001', threat_state: 3 },
    policy_version: 'policy-v1.0.0',
    confidence: null,
    action_taken: 'dispatch_field_team',
    outcome: null,
    trace_id: 'trace_001',
  };

  it('accepts a minimal entry, defaulting version/evidence/approval arrays to []', () => {
    const result = DecisionLedgerEntrySchema.parse(base);
    expect(result.rule_or_model_versions).toEqual([]);
    expect(result.evidence_for).toEqual([]);
    expect(result.evidence_against).toEqual([]);
    expect(result.approvals).toEqual([]);
    expect(result.confidence).toBeNull();
    expect(result.outcome).toBeNull();
  });

  it('accepts a fully-populated entry with evidence for and against plus a two-person approval', () => {
    const full = {
      ...base,
      rule_or_model_versions: ['rules-v1.2.0', 'model-v0.9.1'],
      evidence_for: ['evt_1', 'evt_2'],
      evidence_against: ['evt_3'],
      confidence: 0.72,
      approvals: [
        { user_id: 'user_1', role: 'shift_supervisor', at: '2026-08-14T10:01:00Z' },
        { user_id: 'user_2', role: 'commander', at: '2026-08-14T10:02:00Z' },
      ],
      outcome: 'threat_contained',
    };
    const result = DecisionLedgerEntrySchema.parse(full);
    expect(result.evidence_for).toHaveLength(2);
    expect(result.evidence_against).toHaveLength(1);
    expect(result.approvals).toHaveLength(2);
    expect(result.approvals[0]?.role).toBe('shift_supervisor');
  });

  it('accepts boundary confidence values of exactly 0 and 1', () => {
    expect(() => DecisionLedgerEntrySchema.parse({ ...base, confidence: 0 })).not.toThrow();
    expect(() => DecisionLedgerEntrySchema.parse({ ...base, confidence: 1 })).not.toThrow();
  });

  it('rejects confidence above 1', () => {
    expect(() => DecisionLedgerEntrySchema.parse({ ...base, confidence: 1.01 })).toThrow();
  });

  it('rejects an approval entry missing role', () => {
    const invalid = {
      ...base,
      approvals: [{ user_id: 'user_1', at: '2026-08-14T10:01:00Z' }],
    };
    expect(() => DecisionLedgerEntrySchema.parse(invalid)).toThrow();
  });

  it('rejects a missing entry_id', () => {
    const rest: Record<string, unknown> = { ...base };
    delete rest.entry_id;
    expect(() => DecisionLedgerEntrySchema.parse(rest)).toThrow();
  });

  it('rejects an omitted (as opposed to null) confidence field', () => {
    const rest: Record<string, unknown> = { ...base };
    delete rest.confidence;
    expect(() => DecisionLedgerEntrySchema.parse(rest)).toThrow();
  });

  it('rejects an omitted (as opposed to null) outcome field', () => {
    const rest: Record<string, unknown> = { ...base };
    delete rest.outcome;
    expect(() => DecisionLedgerEntrySchema.parse(rest)).toThrow();
  });
});
