import { describe, expect, it } from 'vitest';
import { canonicalJson, sha256Hex } from './evidence.hash';

describe('sha256Hex', () => {
  it('matches an independently known SHA-256 vector for an empty buffer', () => {
    expect(sha256Hex(Buffer.from(''))).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('matches an independently known SHA-256 vector for "abc"', () => {
    expect(sha256Hex(Buffer.from('abc', 'utf8'))).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('is deterministic for the same bytes and differs for different bytes', () => {
    const a = sha256Hex(Buffer.from('hello', 'utf8'));
    const b = sha256Hex(Buffer.from('hello', 'utf8'));
    const c = sha256Hex(Buffer.from('hello!', 'utf8'));
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });
});

describe('canonicalJson', () => {
  it('produces identical output regardless of key insertion order, at any nesting depth', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe(canonicalJson({ a: 2, b: 1 }));
    expect(canonicalJson({ outer: { z: 1, a: { y: 2, b: 3 } } })).toBe(canonicalJson({ outer: { a: { b: 3, y: 2 }, z: 1 } }));
  });

  it('preserves array element order (order is meaningful, unlike object keys)', () => {
    expect(canonicalJson(['b', 'a'])).not.toBe(canonicalJson(['a', 'b']));
    expect(canonicalJson([{ b: 1, a: 2 }, 'x'])).toBe('[{"a":2,"b":1},"x"]');
  });

  it('drops undefined values from objects exactly like JSON.stringify does', () => {
    expect(canonicalJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });
});
