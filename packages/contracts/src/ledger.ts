import { z } from 'zod';

/**
 * A single approval recorded against a Decision Ledger entry
 * (architecture §5.2 / two-person-approval doctrine, §5.1/§62.1).
 */
const ApprovalSchema = z.object({
  user_id: z.string().min(1),
  role: z.string().min(1),
  at: z.string().datetime(),
});
export type Approval = z.infer<typeof ApprovalSchema>;

/**
 * Decision Ledger entry (architecture §5.2). Every serious decision stores
 * the information available at that moment, the model/rule versions used,
 * evidence for AND against the decision, confidence, the applicable policy
 * version, approvals, the resulting action and (once known) the outcome —
 * enough to explain post-incident review, legal review, model evaluation
 * and regression testing without re-running anything.
 */
export const DecisionLedgerEntrySchema = z.object({
  schema_version: z.literal(1),
  entry_id: z.string().min(1),
  organisation_id: z.string().min(1),
  decided_at: z.string().datetime(),
  decision_type: z.string().min(1),
  inputs_snapshot: z.record(z.unknown()),
  rule_or_model_versions: z.array(z.string()).default([]),
  policy_version: z.string().min(1),
  evidence_for: z.array(z.string()).default([]),
  evidence_against: z.array(z.string()).default([]),
  confidence: z.number().min(0).max(1).nullable(),
  approvals: z.array(ApprovalSchema).default([]),
  action_taken: z.string().min(1),
  outcome: z.string().min(1).nullable(),
  trace_id: z.string().min(1),
});
export type DecisionLedgerEntry = z.infer<typeof DecisionLedgerEntrySchema>;
