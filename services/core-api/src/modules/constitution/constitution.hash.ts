/**
 * SENTINEL — canonical policy hashing (§5.1: policies are versioned and audited; §62.1: the
 * ledger records which policy produced a decision).
 *
 * The stored `content_sha256` must depend only on the *meaning* of a policy, never on the
 * incidental key order that a JSON round-trip through Postgres `jsonb` produces. So the hash
 * is taken over a canonical serialisation: object keys sorted, array order preserved (array
 * order is meaningful in a policy — it is how grants and prohibitions are written).
 *
 * Cryptographic signing of policies is explicitly out of scope for WP-06 (Milestone 2); this
 * hash is the tamper-evidence and audit anchor available now.
 */

import { createHash } from 'node:crypto';
import type { Policy } from './constitution.engine';

/**
 * Deterministic JSON with recursively sorted object keys.
 *
 * `undefined` values (and functions/symbols, which cannot appear in a parsed policy) are
 * dropped from objects exactly as `JSON.stringify` drops them, so a body that round-trips
 * through the database hashes identically to the in-memory object it came from.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalise(value));
}

function canonicalise(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((item) => canonicalise(item));

  const source = value as Record<string, unknown>;
  const canonical: Record<string, unknown> = {};
  for (const key of Object.keys(source).sort()) {
    const entry = canonicalise(source[key]);
    if (entry !== undefined) canonical[key] = entry;
  }
  return canonical;
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/** The content hash stored in `constitution_policies.content_sha256`. */
export function policyContentSha256(policy: Policy): string {
  return sha256Hex(canonicalJson(policy));
}

/** Same hash, computed over a raw stored body (before it is parsed into a `Policy`). */
export function policyBodyContentSha256(body: unknown): string {
  return sha256Hex(canonicalJson(body));
}
