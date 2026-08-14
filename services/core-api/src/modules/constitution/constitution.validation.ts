/**
 * SENTINEL — Constitution policy validation (WP-06 mandatory addition 2).
 *
 * A policy can be structurally valid JSON (see `parsePolicy`) and still be an internally
 * incoherent constitution: an action pointing at a category that does not exist, a role
 * granted an action the constitution has never heard of, a prohibited action handed to a role
 * anyway, or a two-person category nobody is authorised to approve.
 *
 * Every one of those is a silent authority bug: the first two make an action undeniably
 * unresolvable (and therefore permanently denied), the third is an attempt to smuggle a
 * prohibition past the evaluator, and the fourth creates a control that can never be
 * satisfied. None of them can be allowed to reach a running service, so validation runs at
 * load time and boot fails on any issue.
 *
 * `evaluate` deliberately does NOT call this: the evaluator stays pure and total, and answers
 * for whatever policy it is given. Validation is a load-time gate, not a per-request cost.
 */

import type { Policy } from './constitution.engine';

export type PolicyValidationCode =
  /** An action maps to a category id that the policy does not define. */
  | 'policy.category_dangling'
  /** A role grants an action that is not registered in `actions`. */
  | 'policy.action_unregistered'
  /** A prohibited action appears in a role's grant list. */
  | 'policy.prohibited_action_granted'
  /** A ONE / TWO_PERSON category declares no approval authority at all. */
  | 'policy.approval_roles_empty'
  /** A category's approval authority names a role the policy does not define. */
  | 'policy.approval_role_unregistered';

export interface PolicyValidationIssue {
  readonly code: PolicyValidationCode;
  readonly message: string;
}

export class PolicyValidationError extends Error {
  readonly issues: readonly PolicyValidationIssue[];
  readonly policyVersion: string;

  constructor(policyVersion: string, issues: readonly PolicyValidationIssue[]) {
    super(
      `Constitution policy ${policyVersion} is invalid (${issues.length} issue(s)): ` +
        issues.map((i) => `${i.code}: ${i.message}`).join('; '),
    );
    this.name = 'PolicyValidationError';
    this.issues = issues;
    this.policyVersion = policyVersion;
  }
}

function has(record: Readonly<Record<string, unknown>>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function sortedKeys(record: Readonly<Record<string, unknown>>): readonly string[] {
  return Object.keys(record).sort();
}

/**
 * Returns every internal-consistency issue in `policy`, in a deterministic order (rule by
 * rule, then alphabetically), or an empty array if the policy is coherent.
 */
export function validatePolicy(policy: Policy): readonly PolicyValidationIssue[] {
  const issues: PolicyValidationIssue[] = [];
  const prohibited = new Set(policy.prohibitedActions);

  // Rule 1 — dangling category references.
  for (const action of sortedKeys(policy.actions)) {
    const categoryId = policy.actions[action] as string;
    if (!has(policy.categories, categoryId)) {
      issues.push({
        code: 'policy.category_dangling',
        message:
          `action '${action}' maps to category '${categoryId}', which the policy does not ` +
          `define; the action's approval requirement could never be resolved.`,
      });
    }
  }

  // Rule 2 — role grants of unregistered actions.
  // Rule 3 — role grants of prohibited actions.
  for (const role of sortedKeys(policy.roles)) {
    const grants = policy.roles[role] ?? [];
    for (const action of [...grants].sort()) {
      if (!has(policy.actions, action)) {
        issues.push({
          code: 'policy.action_unregistered',
          message:
            `role '${role}' grants action '${action}', which is not registered in the policy; ` +
            `a grant of an unknown action can never take effect and hides a typo or a removal.`,
        });
      }
      if (prohibited.has(action)) {
        issues.push({
          code: 'policy.prohibited_action_granted',
          message:
            `role '${role}' grants action '${action}', which is on the prohibition list; a role ` +
            `grant must never appear to authorise a permanently prohibited action.`,
        });
      }
    }
  }

  // Rule 4 — approval authority missing on a category that requires approval.
  // Rule 5 — approval authority naming a role the policy does not define.
  for (const categoryId of sortedKeys(policy.categories)) {
    const category = policy.categories[categoryId];
    if (category === undefined) continue;
    const requiresApproval = category.approval === 'ONE' || category.approval === 'TWO_PERSON';

    if (requiresApproval && category.approval_roles.length === 0) {
      issues.push({
        code: 'policy.approval_roles_empty',
        message:
          `category '${categoryId}' requires approval '${category.approval}' but declares no ` +
          `approval_roles; no approver could ever be authorised, so the control is unsatisfiable.`,
      });
    }

    for (const role of [...category.approval_roles].sort()) {
      if (!has(policy.roles, role)) {
        issues.push({
          code: 'policy.approval_role_unregistered',
          message:
            `category '${categoryId}' names approval role '${role}', which the policy does not ` +
            `define; approval authority must reference a registered role.`,
        });
      }
    }
  }

  return issues;
}

/**
 * Validates `policy` and returns it, or throws `PolicyValidationError`.
 *
 * This is the boot gate: `ConstitutionService.onModuleInit` calls it on the active policy, so
 * an invalid constitution stops the service starting rather than silently degrading it.
 */
export function assertValidPolicy(policy: Policy): Policy {
  const issues = validatePolicy(policy);
  if (issues.length > 0) throw new PolicyValidationError(policy.version, issues);
  return policy;
}
