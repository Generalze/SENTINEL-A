import { describe, expect, it } from 'vitest';
import { assertSafeSubjectToken, isSafeSubjectToken, MAX_SUBJECT_TOKEN_LENGTH } from './subject-token';

describe('subject token safety (WP-17/D3)', () => {
  it('accepts the id shapes this service actually mints', () => {
    expect(isSafeSubjectToken('0f8fad5b-d9cb-469f-a165-70867728950e')).toBe(true);
    expect(isSafeSubjectToken('site-live')).toBe(true);
    expect(isSafeSubjectToken('e2e_siteA_1755000000000')).toBe(true);
    expect(isSafeSubjectToken('org_wp09_label_1_2')).toBe(true);
  });

  it('rejects the NATS separator and wildcards, which would re-shape or widen the subject', () => {
    // `sentinel.field.updated.{org}.{site}` with site = 'a.b' would make the
    // bridge read 'a' as the site and deliver into another site's room.
    expect(isSafeSubjectToken('a.b')).toBe(false);
    expect(isSafeSubjectToken('*')).toBe(false);
    expect(isSafeSubjectToken('>')).toBe(false);
    expect(isSafeSubjectToken('site-a.>')).toBe(false);
  });

  it('rejects whitespace, empty strings, and non-strings', () => {
    expect(isSafeSubjectToken('site a')).toBe(false);
    expect(isSafeSubjectToken(' site-a')).toBe(false);
    expect(isSafeSubjectToken('site-a\n')).toBe(false);
    expect(isSafeSubjectToken('')).toBe(false);
    expect(isSafeSubjectToken(null)).toBe(false);
    expect(isSafeSubjectToken(undefined)).toBe(false);
    expect(isSafeSubjectToken(42)).toBe(false);
    expect(isSafeSubjectToken({ toString: () => 'site-a' })).toBe(false);
  });

  it('bounds the token length', () => {
    expect(isSafeSubjectToken('a'.repeat(MAX_SUBJECT_TOKEN_LENGTH))).toBe(true);
    expect(isSafeSubjectToken('a'.repeat(MAX_SUBJECT_TOKEN_LENGTH + 1))).toBe(false);
  });

  it('assertSafeSubjectToken throws with the offending label, and passes a safe token', () => {
    expect(() => assertSafeSubjectToken('a.b', 'site_id')).toThrow(/site_id/);
    expect(() => assertSafeSubjectToken('site-a', 'site_id')).not.toThrow();
  });
});
