import { describe, expect, it } from 'vitest';
import { canonicalJson, computeContentHash, sha256Hex, type HashableLedgerEntry } from './ledger.hash';

function baseEntry(overrides: Partial<HashableLedgerEntry> = {}): HashableLedgerEntry {
  return {
    schema_version: 1,
    entry_id: 'entry-1',
    organisation_id: 'org-1',
    decided_at: '2026-08-14T10:00:01.000Z',
    decision_type: 'constitution.evaluate',
    inputs_snapshot: { action: 'tracking.exceptional.enable' },
    rule_or_model_versions: ['constitution-engine@1'],
    policy_version: 'sentinel-constitution-1.0.0',
    evidence_for: ['allow.default'],
    evidence_against: [],
    confidence: null,
    approvals: [{ user_id: 'u-1', role: 'security.officer', at: '2026-08-14T09:59:00.000Z' }],
    action_taken: 'ALLOW',
    outcome: null,
    trace_id: 'trace-1',
    supersedes_entry_id: null,
    ...overrides,
  };
}

describe('canonicalJson', () => {
  it('sorts object keys recursively regardless of input order', () => {
    const a = canonicalJson({ b: 1, a: { d: 2, c: 3 } });
    const b = canonicalJson({ a: { c: 3, d: 2 }, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":{"c":3,"d":2},"b":1}');
  });

  it('preserves array order (order is meaningful, e.g. evidence lists)', () => {
    expect(canonicalJson(['x', 'y'])).not.toBe(canonicalJson(['y', 'x']));
  });

  it('drops undefined values from objects, like JSON.stringify does', () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });
});

describe('sha256Hex', () => {
  it('is a deterministic function of its input', () => {
    expect(sha256Hex('hello')).toBe(sha256Hex('hello'));
    expect(sha256Hex('hello')).not.toBe(sha256Hex('world'));
    // Known SHA-256 of "hello", cross-checked against a reference implementation.
    expect(sha256Hex('hello')).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824');
  });
});

describe('computeContentHash', () => {
  it('is deterministic for the same entry', () => {
    const entry = baseEntry();
    expect(computeContentHash(entry)).toBe(computeContentHash(entry));
  });

  it('is independent of inputs_snapshot key order', () => {
    const a = computeContentHash(baseEntry({ inputs_snapshot: { x: 1, y: 2 } }));
    const b = computeContentHash(baseEntry({ inputs_snapshot: { y: 2, x: 1 } }));
    expect(a).toBe(b);
  });

  it('changes when any single field changes', () => {
    const base = computeContentHash(baseEntry());
    const variants: HashableLedgerEntry[] = [
      baseEntry({ entry_id: 'entry-2' }),
      baseEntry({ organisation_id: 'org-2' }),
      baseEntry({ decided_at: '2026-08-14T10:00:02.000Z' }),
      baseEntry({ decision_type: 'other.type' }),
      baseEntry({ inputs_snapshot: { action: 'other.action' } }),
      baseEntry({ rule_or_model_versions: [] }),
      baseEntry({ policy_version: 'sentinel-constitution-2.0.0' }),
      baseEntry({ evidence_for: [] }),
      baseEntry({ evidence_against: ['deny.something'] }),
      baseEntry({ confidence: 0.5 }),
      baseEntry({ approvals: [] }),
      baseEntry({ action_taken: 'DENY' }),
      baseEntry({ outcome: 'confirmed_threat' }),
      baseEntry({ trace_id: 'trace-2' }),
      baseEntry({ supersedes_entry_id: 'entry-0' }),
    ];
    for (const variant of variants) {
      expect(computeContentHash(variant)).not.toBe(base);
    }
  });
});
