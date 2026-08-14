/**
 * SENTINEL — Decision Ledger record for a constitution evaluation (WP-06 mandatory addition 4).
 *
 * Architecture reference: §62.1 — a Decision Ledger entry must let a reviewer reconstruct the
 * outcome without re-running anything: the inputs as they were, the rule versions used, the
 * evidence for and against, the applicable policy version, the approvals, and the action taken.
 *
 * The DTO shape is the canonical `DecisionLedgerEntry` from `@sentinel/contracts`, so WP-08 can
 * bind a real sink without a translation layer.
 *
 * Import note: core-api compiles with `moduleResolution: "node"`, which predates the
 * `exports` map that `@sentinel/contracts` publishes, so the bare specifier does not resolve.
 * The deep path below is a TYPE-ONLY import — it is erased at compile time, so it adds no
 * runtime coupling to an ESM-only package from this CommonJS service. When the lead moves the
 * service to `nodenext`, this becomes `from '@sentinel/contracts'` with no other change.
 */

import type { DecisionLedgerEntry } from '@sentinel/contracts/dist/ledger';
import { canonicalJson } from './constitution.hash';
import {
  CONSTITUTION_ENGINE_VERSION,
  type ConstitutionDecision,
  type ConstitutionRequest,
  type TraceEntry,
} from './constitution.engine';

/** The DTO every evaluation emits. Structurally the `@sentinel/contracts` ledger entry. */
export type DecisionRecord = DecisionLedgerEntry;

export const CONSTITUTION_DECISION_TYPE = 'constitution.evaluate';

export interface DecisionRecordInput {
  readonly request: ConstitutionRequest;
  readonly decision: ConstitutionDecision;
  readonly policyContentSha256: string;
  readonly entryId: string;
  /** ISO-8601. */
  readonly decidedAt: string;
  readonly traceId: string;
}

/**
 * The contract requires several `min(1)` strings. An evaluation must never fail to produce a
 * ledger entry (no code path may skip the sink), so blank inputs are recorded as an explicit
 * marker rather than being allowed to make the entry unrepresentable.
 */
const UNATTRIBUTED = 'unattributed';

function nonEmpty(value: string | undefined, fallback: string): string {
  const trimmed = (value ?? '').trim();
  return trimmed.length > 0 ? trimmed : fallback;
}

function formatTraceEntry(entry: TraceEntry): string {
  const seq = String(entry.seq).padStart(2, '0');
  return (
    `[${seq}] ${entry.check} (${entry.severity}) ${entry.outcome} — ${entry.summary} ` +
    `| values: ${canonicalJson(entry.values)}`
  );
}

/** A reason that argues *for* the decision rather than against it. */
function isSupportingReason(reason: string): boolean {
  return reason.startsWith('allow.') || reason.startsWith('approval.satisfied:');
}

/**
 * Builds the Decision Ledger entry for one evaluation.
 *
 * Pure: the caller supplies the entry id, timestamp and trace id, so the record is
 * deterministic and testable and the engine keeps its no-clock/no-I/O contract.
 */
export function buildDecisionRecord(input: DecisionRecordInput): DecisionRecord {
  const { request, decision } = input;
  const approvals = request.approvals ?? [];

  const passed = decision.trace.filter((entry) => entry.outcome === 'PASS');
  const failed = decision.trace.filter((entry) => entry.outcome === 'FAIL');

  return {
    schema_version: 1,
    entry_id: nonEmpty(input.entryId, UNATTRIBUTED),
    // The ledger entry belongs to the organisation whose authority was exercised: the actor's.
    // The target organisation is preserved in the snapshot, so a cross-organisation attempt is
    // still fully visible.
    organisation_id: nonEmpty(request.actor.organisationId, UNATTRIBUTED),
    decided_at: input.decidedAt,
    decision_type: CONSTITUTION_DECISION_TYPE,
    inputs_snapshot: {
      action: request.action,
      actor: {
        user_id: request.actor.userId,
        roles: [...request.actor.roles],
        organisation_id: request.actor.organisationId,
        clearance: request.actor.clearance,
        purpose: request.actor.purpose ?? null,
        device_trust: request.actor.deviceTrust,
      },
      target: {
        organisation_id: request.target.organisationId,
        site_id: request.target.siteId ?? null,
        classification: request.target.classification,
        classification_level: request.target.classificationLevel,
      },
      approvals: approvals.map((approval) => ({
        user_id: approval.userId,
        claimed_role: approval.role,
        at: approval.at,
      })),
      approver_roles: request.approver_roles ?? {},
      policy_content_sha256: input.policyContentSha256,
    },
    rule_or_model_versions: [
      `${CONSTITUTION_ENGINE_VERSION}`,
      `constitution-policy@${decision.policyVersion}`,
      `constitution-policy-sha256@${input.policyContentSha256}`,
    ],
    policy_version: decision.policyVersion,
    evidence_for: [
      ...decision.reasons.filter(isSupportingReason),
      ...passed.map(formatTraceEntry),
    ],
    evidence_against: [
      ...decision.reasons.filter((reason) => !isSupportingReason(reason)),
      ...failed.map(formatTraceEntry),
    ],
    // Deterministic rule evaluation (§61): the outcome is not a probabilistic judgement, so a
    // confidence score would be a false signal. Recorded as explicitly absent.
    confidence: null,
    approvals: approvals.map((approval) => ({
      user_id: nonEmpty(approval.userId, UNATTRIBUTED),
      role: nonEmpty(approval.role, UNATTRIBUTED),
      at: approval.at,
    })),
    action_taken: decision.decision,
    // The real-world result of the decision is not known at evaluation time; WP-08 closes it.
    outcome: null,
    trace_id: nonEmpty(input.traceId, UNATTRIBUTED),
  };
}
