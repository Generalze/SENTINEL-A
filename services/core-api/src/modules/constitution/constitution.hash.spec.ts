import { describe, expect, it } from 'vitest';

import {
  canonicalJson,
  policyBodyContentSha256,
  policyContentSha256,
  sha256Hex,
} from './constitution.hash';
import { SENTINEL_BASELINE_POLICY, policyBody } from './constitution.policy';

describe('canonicalJson', () => {
  it('is independent of object key order', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe(canonicalJson({ a: 2, b: 1 }));
    expect(canonicalJson({ outer: { z: 1, a: { y: 2, b: 3 } } })).toBe(
      canonicalJson({ outer: { a: { b: 3, y: 2 }, z: 1 } }),
    );
  });

  it('preserves array order, which is meaningful in a policy', () => {
    expect(canonicalJson(['b', 'a'])).not.toBe(canonicalJson(['a', 'b']));
  });

  it('drops undefined members exactly as JSON.stringify does', () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });
});

describe('policyContentSha256', () => {
  it('is stable across a JSON round-trip through storage', () => {
    const stored = policyBody(SENTINEL_BASELINE_POLICY);
    expect(policyBodyContentSha256(stored)).toBe(policyContentSha256(SENTINEL_BASELINE_POLICY));
  });

  it('is stable across key reordering by the database', () => {
    const stored = policyBody(SENTINEL_BASELINE_POLICY);
    const reordered = Object.fromEntries(Object.entries(stored).reverse());
    expect(policyBodyContentSha256(reordered)).toBe(
      policyContentSha256(SENTINEL_BASELINE_POLICY),
    );
  });

  it('changes when any part of the policy changes', () => {
    const mutated = JSON.parse(JSON.stringify(SENTINEL_BASELINE_POLICY)) as Record<
      string,
      unknown
    >;
    const categories = mutated['categories'] as Record<string, Record<string, unknown>>;
    const category = categories['exceptional_tracking_powers'];
    if (category !== undefined) category['approval'] = 'ONE';

    expect(policyBodyContentSha256(mutated)).not.toBe(
      policyContentSha256(SENTINEL_BASELINE_POLICY),
    );
  });

  it('produces a 64-character lowercase hex digest', () => {
    expect(policyContentSha256(SENTINEL_BASELINE_POLICY)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('matches a known SHA-256 vector', () => {
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});
