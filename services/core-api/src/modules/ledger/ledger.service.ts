/**
 * SENTINEL — Decision Ledger service (WP-08; architecture §5.2, §61, §62.1).
 *
 * The durable, tamper-evident implementation of the `LedgerSink` interface WP-06 defined
 * (constitution/ledger.sink.ts). Every serious decision is appended here as one entry; entries
 * are chained per organisation by content hash so any later mutation of a stored row is
 * detectable (`verifyChain`).
 *
 * APPEND-ONLY SURFACE: this class exposes append/query/verifyChain ONLY — see
 * ledger.append-only.spec.ts, which enforces (as an automated source scan, mirroring
 * events.append-only.spec.ts) that no update/delete path exists anywhere in this module.
 */

import { Inject, Injectable, Logger } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type { Prisma } from '@prisma/client';
import { DecisionLedgerEntrySchema } from '@sentinel/contracts';
import type { BufferingLedgerSink, LedgerSink } from '../constitution/ledger.sink';
import { computeContentHash, type HashableLedgerEntry } from './ledger.hash';
import { LedgerRepository } from './ledger.repository';
import type {
  AppendLedgerEntryInput,
  LedgerApproval,
  LedgerEntry,
  LedgerListFilter,
  LedgerListResult,
  VerifyChainResult,
} from './ledger.types';

/** `entry_id`/`decided_at` are stamped separately when absent (directive #2), so validation
 * accepts the rest of the contracts schema strictly but treats those two as optional here. */
const AppendableEntrySchema = DecisionLedgerEntrySchema.partial({ entry_id: true, decided_at: true });

export class LedgerValidationError extends Error {
  constructor(readonly issues: readonly string[]) {
    super(`Decision Ledger entry failed validation:\n${issues.map((issue) => ` - ${issue}`).join('\n')}`);
    this.name = 'LedgerValidationError';
  }
}

function formatIssues(error: { issues: readonly { path: readonly (string | number)[]; message: string }[] }): string[] {
  return error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`);
}

interface HashableSource {
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
  approvals: readonly LedgerApproval[];
  action_taken: string;
  outcome: string | null;
  trace_id: string;
  supersedes_entry_id: string | null;
}

/**
 * Picks exactly the hashed fields out of a wider source object (a freshly-validated entry at
 * append time, or a persisted `LedgerEntry` at verify time). Built field-by-field rather than
 * via spread so it is impossible to accidentally fold in `content_hash`/`previous_hash`/
 * `created_at` — or any future column — into the hash input.
 */
function hashableFieldsOf(entry: HashableSource): HashableLedgerEntry {
  return {
    schema_version: entry.schema_version,
    entry_id: entry.entry_id,
    organisation_id: entry.organisation_id,
    decided_at: entry.decided_at,
    decision_type: entry.decision_type,
    inputs_snapshot: entry.inputs_snapshot,
    rule_or_model_versions: entry.rule_or_model_versions,
    policy_version: entry.policy_version,
    evidence_for: entry.evidence_for,
    evidence_against: entry.evidence_against,
    confidence: entry.confidence,
    approvals: entry.approvals,
    action_taken: entry.action_taken,
    outcome: entry.outcome,
    trace_id: entry.trace_id,
    supersedes_entry_id: entry.supersedes_entry_id,
  };
}

/**
 * Normalises an ISO datetime string to `Date#toISOString()`'s canonical form (exactly 3
 * fractional digits, "Z" suffix) — the same form a Postgres `timestamptz(3)` round trip
 * reproduces. See ledger.hash.ts's `HashableLedgerEntry` doc for why this matters: hashing a
 * caller-supplied string's raw formatting would make `verifyChain` recompute a different hash
 * than the one stored at append time for the exact same, untampered instant.
 */
function normaliseDecidedAt(decidedAt: string): { date: Date; iso: string } {
  const date = new Date(decidedAt);
  return { date, iso: date.toISOString() };
}

@Injectable()
export class LedgerService implements LedgerSink {
  private readonly logger = new Logger(LedgerService.name);

  constructor(@Inject(LedgerRepository) private readonly repository: LedgerRepository) {}

  /**
   * Validates, stamps and appends one entry (directive #2): `entry_id`/`decided_at` are
   * stamped (crypto.randomUUID() / new Date().toISOString()) when the caller omits them,
   * `content_hash` is computed over the canonicalised entry, and `previous_hash` is established
   * by `LedgerRepository.append` under a per-organisation lock so the chain can never fork
   * under concurrent appends.
   *
   * Returns `void`, matching `LedgerSink` exactly: rejecting is meaningful (an unwritable
   * ledger fails the calling evaluation closed — see ledger.sink.ts), and the created row is
   * available afterwards via `query`/`verifyChain` for callers that need it.
   */
  async append(entry: AppendLedgerEntryInput): Promise<void> {
    const permissive = AppendableEntrySchema.safeParse(entry);
    if (!permissive.success) {
      throw new LedgerValidationError(formatIssues(permissive.error));
    }

    const entryId = permissive.data.entry_id ?? randomUUID();
    const rawDecidedAt = permissive.data.decided_at ?? new Date().toISOString();
    const supersedesEntryId = entry.supersedes_entry_id ?? null;

    const strict = DecisionLedgerEntrySchema.safeParse({
      ...permissive.data,
      entry_id: entryId,
      decided_at: rawDecidedAt,
    });
    if (!strict.success) {
      throw new LedgerValidationError(formatIssues(strict.error));
    }
    const validated = strict.data;
    const { date: decidedAtDate, iso: decidedAtIso } = normaliseDecidedAt(validated.decided_at);

    const contentHash = computeContentHash(
      hashableFieldsOf({
        ...validated,
        decided_at: decidedAtIso,
        supersedes_entry_id: supersedesEntryId,
      }),
    );

    await this.repository.append({
      entryId: validated.entry_id,
      organisationId: validated.organisation_id,
      decidedAt: decidedAtDate,
      decisionType: validated.decision_type,
      inputsSnapshot: validated.inputs_snapshot as Prisma.InputJsonValue,
      ruleOrModelVersions: [...validated.rule_or_model_versions],
      policyVersion: validated.policy_version,
      evidenceFor: [...validated.evidence_for],
      evidenceAgainst: [...validated.evidence_against],
      confidence: validated.confidence,
      approvals: validated.approvals as unknown as Prisma.InputJsonValue,
      actionTaken: validated.action_taken,
      outcome: validated.outcome,
      traceId: validated.trace_id,
      schemaVersion: validated.schema_version,
      contentHash,
      supersedesEntryId,
    });
  }

  /** Deliverable #4: tenant-scoped, filtered, paginated read. */
  async query(filter: LedgerListFilter): Promise<LedgerListResult> {
    const { items, nextCursor } = await this.repository.list(filter);
    return { items, next_cursor: nextCursor };
  }

  /**
   * Deliverable #5: walks the organisation's chain oldest -> newest, recomputing each entry's
   * `content_hash` from its own stored fields and checking that its `previous_hash` matches the
   * preceding entry's `content_hash`. Returns `{ valid: true }`, or the first broken entry's id
   * and why — never continues past the first break (a chain is only as trustworthy as its first
   * intact prefix).
   */
  async verifyChain(organisationId: string): Promise<VerifyChainResult> {
    const entries = await this.repository.listChainOrder(organisationId);
    let expectedPreviousHash: string | null = null;
    let checked = 0;

    for (const entry of entries) {
      checked += 1;
      const recomputedHash = computeContentHash(hashableFieldsOf(entry));

      if (recomputedHash !== entry.content_hash) {
        return {
          valid: false,
          organisation_id: organisationId,
          entries_checked: checked,
          broken_entry_id: entry.entry_id,
          reason:
            `content_hash does not match the entry's own stored content ` +
            `(stored=${entry.content_hash}, recomputed=${recomputedHash}) — the row was altered after it was appended.`,
        };
      }

      if (entry.previous_hash !== expectedPreviousHash) {
        return {
          valid: false,
          organisation_id: organisationId,
          entries_checked: checked,
          broken_entry_id: entry.entry_id,
          reason:
            `previous_hash does not match the preceding entry's content_hash ` +
            `(expected=${expectedPreviousHash ?? 'null'}, stored=${entry.previous_hash ?? 'null'}) — the chain link is broken.`,
        };
      }

      expectedPreviousHash = entry.content_hash;
    }

    return { valid: true, organisation_id: organisationId, entries_checked: checked };
  }

  /**
   * Drains any entries still buffered in the WP-06 stub (`BufferingLedgerSink`) into this
   * durable store, in buffered order, at the moment this service is wired in as the real
   * `LEDGER_SINK` (see constitution.module.ts's factory). No-op when nothing is buffered — the
   * ordinary case, since ConstitutionModule's own boot never appends to the buffer itself, only
   * external callers of `ConstitutionService.evaluate` do. The drain exists as a documented
   * safety net for anything that landed in the buffer before this binding took effect, not a
   * normal-path dependency.
   */
  async drainBuffer(sink: BufferingLedgerSink): Promise<void> {
    const drained = sink.drain();
    if (drained.length === 0) return;

    this.logger.log(
      `draining ${drained.length} buffered Decision Ledger entr${drained.length === 1 ? 'y' : 'ies'} into the durable store`,
    );
    for (const record of drained) {
      // Each buffered DecisionRecord already carries a stamped entry_id/decided_at (set by
      // ConstitutionService.evaluate before it reached the sink), so this reuses the exact same
      // validate -> hash -> chain-link path as any other append; no special-casing needed.
      await this.append(record as unknown as AppendLedgerEntryInput);
    }
  }
}

/** Exposed for tests that need to assert on the exact set of fields a hash covers. */
export type { LedgerEntry };
