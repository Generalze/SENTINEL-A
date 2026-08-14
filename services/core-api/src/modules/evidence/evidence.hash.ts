/**
 * SENTINEL — evidence hashing (§48: "cryptographic hash for evidence
 * objects"; §72.2: hash is computed before the object is written to
 * storage; WP-09 deliverable 6: event snapshots are serialised to
 * "canonical JSON").
 *
 * `canonicalJson`/`canonicalise` here are a local copy of
 * `modules/constitution/constitution.hash.ts`'s implementation (same
 * algorithm: object keys sorted recursively, array order preserved,
 * `undefined` dropped exactly as `JSON.stringify` would). Duplicated
 * rather than imported: WP-09's coordination rules scope this module to
 * `modules/evidence` only, and the constitution module is a separate,
 * concurrently-developed lane.
 */

import { createHash } from 'node:crypto';

export function sha256Hex(input: Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Deterministic JSON with recursively sorted object keys; array order is preserved. */
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
