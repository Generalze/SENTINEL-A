/**
 * SENTINEL — Decision Ledger DTOs (WP-08).
 *
 * Import note: core-api compiles with `moduleResolution: "node"`, which predates the `exports`
 * map that `@sentinel/contracts` publishes, so a bare `@sentinel/contracts` specifier does not
 * resolve for a TYPE-ONLY import of an ESM-only package's deep path. This mirrors
 * constitution/decision-record.ts's import exactly, for the same reason: the deep path below is
 * erased at compile time, so it adds no runtime coupling. When the lead moves the service to
 * `nodenext`, this becomes `from '@sentinel/contracts'` with no other change.
 */
import type { DecisionLedgerEntry } from '@sentinel/contracts/dist/ledger';

/** One `approvals[]` element — structurally the contracts `Approval` shape. */
export interface LedgerApproval {
  user_id: string;
  role: string;
  at: string;
}

/**
 * Input to `LedgerService.append()`. `entry_id`/`decided_at` are optional: the service stamps
 * them (crypto.randomUUID() / new Date().toISOString()) when absent (directive #2).
 * `supersedes_entry_id` is a WP-08 addition, not part of the `@sentinel/contracts` schema — a
 * correction (e.g. recording a real-world outcome once known) is a new entry that sets it,
 * rather than a rewrite of the entry it corrects.
 */
export type AppendLedgerEntryInput = Omit<DecisionLedgerEntry, 'entry_id' | 'decided_at' | 'approvals'> & {
  entry_id?: string;
  decided_at?: string;
  approvals: readonly LedgerApproval[];
  supersedes_entry_id?: string | null;
};

/** The full stored shape: every contract field plus the WP-08 hash-chain columns. */
export type LedgerEntry = Omit<DecisionLedgerEntry, 'approvals'> & {
  approvals: readonly LedgerApproval[];
  content_hash: string;
  previous_hash: string | null;
  supersedes_entry_id: string | null;
  created_at: string;
};

export interface LedgerListFilter {
  organisationId: string;
  decisionType?: string;
  decidedFrom?: Date;
  decidedTo?: Date;
  limit: number;
  cursor?: string;
}

export interface LedgerListResult {
  items: LedgerEntry[];
  next_cursor: string | null;
}

export interface VerifyChainOk {
  valid: true;
  organisation_id: string;
  entries_checked: number;
}

export interface VerifyChainBroken {
  valid: false;
  organisation_id: string;
  entries_checked: number;
  broken_entry_id: string;
  reason: string;
}

/** `LedgerService.verifyChain` result (directive #5): `{ valid: true }`, or the first broken
 * entry id and why. */
export type VerifyChainResult = VerifyChainOk | VerifyChainBroken;
