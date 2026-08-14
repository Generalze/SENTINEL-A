/**
 * SENTINEL — Decision Ledger canonical hashing (WP-08; architecture §5.2, §61).
 *
 * The `content_hash` stored on every ledger entry must depend only on the entry's *meaning*,
 * never on incidental key order (e.g. the order `JSON.parse`/Postgres `jsonb` happen to produce
 * on a round trip). So it is computed over a canonical serialisation: object keys sorted
 * recursively, array order preserved (order is meaningful in evidence/version lists).
 *
 * Deliberately self-contained: this mirrors constitution/constitution.hash.ts's canonicalJson
 * approach exactly, but is re-declared locally rather than imported, so the ledger module has
 * no runtime dependency on the constitution module beyond the one authorised LedgerSink wiring
 * change in constitution.module.ts.
 */

import { createHash } from 'node:crypto';

/** Deterministic JSON with recursively sorted object keys. `undefined` values are dropped from
 * objects exactly as `JSON.stringify` drops them. */
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

/**
 * The exact field set hashed for `content_hash`: every `@sentinel/contracts`
 * `DecisionLedgerEntry` field, plus `supersedes_entry_id` (a WP-08 addition that is still part
 * of "what this entry claims"). Deliberately EXCLUDES `content_hash` itself (self-referential)
 * and `previous_hash` (chain linkage/position, not this entry's own content) and the DB-only
 * bookkeeping columns (`created_at`, `seq`).
 *
 * `decided_at` must be the value's canonical `Date#toISOString()` form (exactly 3 fractional
 * digits, "Z" suffix) — the same form a Postgres `timestamptz(3)` round trip reproduces — NOT
 * whatever arbitrary-precision ISO string a caller supplied. Hashing a caller's raw string
 * (which may have 0, 1 or 6+ fractional digits, or omit them entirely) would make
 * `verifyChain` recompute a different hash than the one stored at append time for the exact
 * same, untampered instant, purely from string-formatting drift. See ledger.service.ts's
 * `normaliseDecidedAt`.
 */
export interface HashableLedgerEntry {
  schema_version: number;
  entry_id: string;
  organisation_id: string;
  decided_at: string;
  decision_type: string;
  inputs_snapshot: unknown;
  rule_or_model_versions: readonly string[];
  policy_version: string;
  evidence_for: readonly string[];
  evidence_against: readonly string[];
  confidence: number | null;
  approvals: readonly { user_id: string; role: string; at: string }[];
  action_taken: string;
  outcome: string | null;
  trace_id: string;
  supersedes_entry_id: string | null;
}

/** `content_hash` for one entry: SHA-256 (hex) over the canonical JSON of its hashable fields. */
export function computeContentHash(entry: HashableLedgerEntry): string {
  return sha256Hex(canonicalJson(entry));
}
