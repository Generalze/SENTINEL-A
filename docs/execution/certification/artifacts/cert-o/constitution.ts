/**
 * SENTINEL — Constitution Evaluator
 * Architecture references: §5.1 (hardened policy layer), §58.2 (two-person control list),
 * §62.1 (Decision Ledger trace requirements).
 *
 * Design contract
 * ---------------
 * 1. DENY BY DEFAULT. `evaluate` starts from "not authorised" and only reaches ALLOW when
 *    every hard check passes. Anything unknown (unregistered action, unresolved category,
 *    unrecognised classification label, unusable numeric input) fails closed.
 * 2. NO SHORT-CIRCUITING. Every check in `CHECK_SEQUENCE` runs on every evaluation, in a
 *    fixed order, and emits exactly one trace entry. A Decision Ledger entry is therefore
 *    uniform and self-explaining: a reviewer can reconstruct the outcome from the trace
 *    alone, without re-running the evaluator.
 * 3. PURE. `evaluate` reads its inputs, mutates nothing, and is deterministic. No clock,
 *    no I/O, no globals. The result is frozen before it is returned.
 */

/* -------------------------------------------------------------------------- */
/* Domain types                                                               */
/* -------------------------------------------------------------------------- */

export type DeviceTrust =
  | 'TRUSTED'
  | 'DEGRADED'
  | 'SUSPICIOUS'
  | 'QUARANTINED'
  | 'COMPROMISED';

export type Classification =
  | 'PUBLIC'
  | 'INTERNAL'
  | 'SENSITIVE'
  | 'RESTRICTED'
  | 'EVIDENCE'
  | 'SECRETS';

export interface Actor {
  readonly userId: string;
  readonly roles: readonly string[];
  readonly organisationId: string;
  /** 0..5 */
  readonly clearance: number;
  readonly purpose?: string;
  readonly deviceTrust: DeviceTrust;
}

export interface Target {
  readonly organisationId: string;
  readonly siteId?: string;
  readonly classification: Classification;
  /** 0..5 — redundant with `classification`; cross-validated, see CLASSIFICATION_CONSISTENT. */
  readonly classificationLevel: number;
}

export interface Approval {
  readonly userId: string;
  readonly role: string;
  /** ISO-8601 timestamp. Recorded for the ledger; not interpreted by the evaluator. */
  readonly at: string;
}

export interface ConstitutionRequest {
  readonly action: string;
  readonly actor: Actor;
  readonly target: Target;
  readonly approvals?: readonly Approval[];
}

/* -------------------------------------------------------------------------- */
/* Policy representation                                                      */
/* -------------------------------------------------------------------------- */

/** How many *distinct* approvers, other than the actor, an action category demands. */
export type ApprovalRequirement = 'NONE' | 'ONE' | 'TWO_PERSON';

export interface ActionCategory {
  readonly approval: ApprovalRequirement;
  readonly description: string;
}

/**
 * A versioned constitution policy.
 *
 * - `categories`  category id  -> approval requirement (the §58.2 control lists live here)
 * - `actions`     action id    -> category id  (registration; an unregistered action is denied)
 * - `roles`       role id      -> explicit allow list of action ids (no wildcards, by design)
 * - `prohibitedActions`        -> actions that can NEVER be authorised, whatever else holds
 *
 * Registration (`actions`) is deliberately separate from permission (`roles`) and from
 * prohibition (`prohibitedActions`): the constitution can know and classify an action it
 * forbids, and a role grant can never override a prohibition.
 */
export interface Policy {
  readonly version: string;
  readonly categories: Readonly<Record<string, ActionCategory>>;
  readonly actions: Readonly<Record<string, string>>;
  readonly roles: Readonly<Record<string, readonly string[]>>;
  readonly prohibitedActions: readonly string[];
}

/* -------------------------------------------------------------------------- */
/* Decision + trace types                                                     */
/* -------------------------------------------------------------------------- */

export type Decision = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'REQUIRE_TWO_PERSON';

export type CheckOutcome = 'PASS' | 'FAIL';

/**
 * HARD     — a failure forces DENY.
 * APPROVAL — a failure means the request is well-formed and authorised on the merits but
 *            the human control has not been satisfied yet, i.e. REQUIRE_APPROVAL /
 *            REQUIRE_TWO_PERSON rather than DENY.
 */
export type CheckSeverity = 'HARD' | 'APPROVAL';

export type CheckId =
  | 'ACTION_NOT_PROHIBITED'
  | 'ACTION_KNOWN'
  | 'ACTION_CATEGORY_KNOWN'
  | 'ROLE_PERMITS_ACTION'
  | 'ORGANISATION_MATCH'
  | 'CLASSIFICATION_CONSISTENT'
  | 'CLEARANCE_SUFFICIENT'
  | 'DEVICE_TRUST_ACCEPTABLE'
  | 'PURPOSE_PRESENT'
  | 'APPROVAL_SELF_EXCLUSION'
  | 'APPROVAL_DISTINCT_SUFFICIENT';

/** The canonical, ordered set of checks. Every evaluation emits all of them, exactly once. */
export const CHECK_SEQUENCE: readonly CheckId[] = [
  'ACTION_NOT_PROHIBITED',
  'ACTION_KNOWN',
  'ACTION_CATEGORY_KNOWN',
  'ROLE_PERMITS_ACTION',
  'ORGANISATION_MATCH',
  'CLASSIFICATION_CONSISTENT',
  'CLEARANCE_SUFFICIENT',
  'DEVICE_TRUST_ACCEPTABLE',
  'PURPOSE_PRESENT',
  'APPROVAL_SELF_EXCLUSION',
  'APPROVAL_DISTINCT_SUFFICIENT',
];

export type TraceValue = string | number | boolean | null | readonly string[];

export interface TraceEntry {
  /** 1-based position in CHECK_SEQUENCE. */
  readonly seq: number;
  readonly check: CheckId;
  readonly severity: CheckSeverity;
  readonly outcome: CheckOutcome;
  /** Human-readable statement of what was checked and what was found. */
  readonly summary: string;
  /** The concrete values compared, for ledger replay. */
  readonly values: Readonly<Record<string, TraceValue>>;
}

export interface ConstitutionDecision {
  readonly decision: Decision;
  readonly policyVersion: string;
  /** Stable `code: explanation` strings, ordered decision-level first, then check order. */
  readonly reasons: readonly string[];
  readonly trace: readonly TraceEntry[];
}

/* -------------------------------------------------------------------------- */
/* Constants                                                                  */
/* -------------------------------------------------------------------------- */

/** Canonical label -> level mapping. `Partial` so unknown labels resolve to `undefined`. */
export const CLASSIFICATION_LEVELS: Readonly<Partial<Record<Classification, number>>> = {
  PUBLIC: 0,
  INTERNAL: 1,
  SENSITIVE: 2,
  RESTRICTED: 3,
  EVIDENCE: 4,
  SECRETS: 5,
};

export const MAX_CLASSIFICATION_LEVEL = 5;

/** A stated purpose is mandatory at SENSITIVE (2) and above. */
export const PURPOSE_REQUIRED_AT_LEVEL = 2;

/** A SUSPICIOUS device may reach PUBLIC (0) and INTERNAL (1) only. */
export const SUSPICIOUS_DEVICE_MAX_LEVEL = 1;

/* -------------------------------------------------------------------------- */
/* Pure helpers                                                               */
/* -------------------------------------------------------------------------- */

/**
 * Own-property lookup. Guards against inherited keys (`toString`, `constructor`, ...) being
 * mistaken for policy entries — a plain `record[key]` would happily resolve those.
 */
function lookup<T>(record: Readonly<Record<string, T>>, key: string): T | undefined {
  return Object.prototype.hasOwnProperty.call(record, key) ? record[key] : undefined;
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return Array.from(new Set(values)).sort();
}

/**
 * The classification level actually used for every level comparison.
 *
 * `classification` and `classificationLevel` are two representations of one fact, so they can
 * disagree — by mistake or by tampering. This resolves to the MORE RESTRICTIVE of the two, so
 * a request that under-declares the level (e.g. SECRETS at level 0) cannot use the mismatch to
 * slip past the clearance, device-trust or purpose rules. The mismatch itself is separately
 * reported by CLASSIFICATION_CONSISTENT, which denies.
 */
export function effectiveClassificationLevel(target: Target): number {
  const canonical = CLASSIFICATION_LEVELS[target.classification];
  if (canonical === undefined) return MAX_CLASSIFICATION_LEVEL; // unknown label -> strictest
  if (!Number.isFinite(target.classificationLevel)) return MAX_CLASSIFICATION_LEVEL;
  return Math.max(canonical, target.classificationLevel);
}

export function requiredApproverCount(requirement: ApprovalRequirement): number {
  switch (requirement) {
    case 'NONE':
      return 0;
    case 'ONE':
      return 1;
    case 'TWO_PERSON':
      return 2;
    default:
      return 2; // fail closed
  }
}

function deviceTrustAcceptable(trust: DeviceTrust, effectiveLevel: number): boolean {
  switch (trust) {
    case 'TRUSTED':
    case 'DEGRADED':
      return true;
    case 'SUSPICIOUS':
      return effectiveLevel <= SUSPICIOUS_DEVICE_MAX_LEVEL;
    case 'QUARANTINED':
    case 'COMPROMISED':
      return false;
    default:
      return false; // unrecognised trust state -> deny
  }
}

/* -------------------------------------------------------------------------- */
/* Evaluation context + check plumbing                                        */
/* -------------------------------------------------------------------------- */

interface EvaluationContext {
  readonly request: ConstitutionRequest;
  readonly policy: Policy;
  readonly approvals: readonly Approval[];
  readonly canonicalLevel: number | undefined;
  readonly effectiveLevel: number;
  readonly categoryId: string | undefined;
  readonly category: ActionCategory | undefined;
  readonly requirement: ApprovalRequirement;
  /** True when `requirement` came from the fail-closed default, not from the policy. */
  readonly requirementFailClosed: boolean;
  readonly requiredApprovers: number;
}

interface CheckResult {
  readonly check: CheckId;
  readonly severity: CheckSeverity;
  readonly outcome: CheckOutcome;
  readonly summary: string;
  readonly values: Readonly<Record<string, TraceValue>>;
  /** Non-null iff outcome === 'FAIL'. */
  readonly reason: string | null;
}

type CheckFn = (ctx: EvaluationContext) => CheckResult;

function result(
  check: CheckId,
  severity: CheckSeverity,
  passed: boolean,
  summary: string,
  values: Readonly<Record<string, TraceValue>>,
  failureReason: string,
): CheckResult {
  return {
    check,
    severity,
    outcome: passed ? 'PASS' : 'FAIL',
    summary,
    values,
    reason: passed ? null : failureReason,
  };
}

/** Approvals that may count: not the actor's own, and carrying a usable user id. */
function eligibleApproverIds(ctx: EvaluationContext): readonly string[] {
  const actorId = ctx.request.actor.userId;
  return uniqueSorted(
    ctx.approvals
      .filter((a) => a.userId !== actorId && a.userId.trim().length > 0)
      .map((a) => a.userId),
  );
}

function selfApprovalIds(ctx: EvaluationContext): readonly string[] {
  const actorId = ctx.request.actor.userId;
  return uniqueSorted(ctx.approvals.filter((a) => a.userId === actorId).map((a) => a.userId));
}

/* -------------------------------------------------------------------------- */
/* The checks — one function per rule, in CHECK_SEQUENCE order                 */
/* -------------------------------------------------------------------------- */

const checkActionNotProhibited: CheckFn = (ctx) => {
  const action = ctx.request.action;
  const prohibited = ctx.policy.prohibitedActions.includes(action);
  return result(
    'ACTION_NOT_PROHIBITED',
    'HARD',
    !prohibited,
    prohibited
      ? `Action '${action}' is on the prohibition list of policy ${ctx.policy.version}.`
      : `Action '${action}' is not on the prohibition list of policy ${ctx.policy.version}.`,
    {
      action,
      prohibited,
      prohibitedActions: ctx.policy.prohibitedActions,
    },
    `action.prohibited: '${action}' is permanently prohibited by policy ${ctx.policy.version}; ` +
      `no role grant, clearance or approval can authorise it.`,
  );
};

const checkActionKnown: CheckFn = (ctx) => {
  const action = ctx.request.action;
  const known = ctx.categoryId !== undefined;
  return result(
    'ACTION_KNOWN',
    'HARD',
    known,
    known
      ? `Action '${action}' is registered in policy ${ctx.policy.version}.`
      : `Action '${action}' is not registered in policy ${ctx.policy.version}.`,
    {
      action,
      registered: known,
      registeredActionCount: Object.keys(ctx.policy.actions).length,
    },
    `action.unknown: '${action}' is not a registered action in policy ${ctx.policy.version}; ` +
      `unregistered actions are denied by default.`,
  );
};

const checkActionCategoryKnown: CheckFn = (ctx) => {
  const resolved = ctx.category !== undefined;
  return result(
    'ACTION_CATEGORY_KNOWN',
    'HARD',
    resolved,
    resolved
      ? `Action maps to category '${ctx.categoryId ?? ''}' requiring approval '${ctx.requirement}'.`
      : `Action does not resolve to a known category; approval requirement defaulted to ` +
          `'${ctx.requirement}' (fail closed).`,
    {
      action: ctx.request.action,
      category: ctx.categoryId ?? null,
      categoryResolved: resolved,
      approvalRequirement: ctx.requirement,
      requirementFailClosed: ctx.requirementFailClosed,
      requiredDistinctApprovers: ctx.requiredApprovers,
    },
    `policy.category_unresolved: action '${ctx.request.action}' has no resolvable category in ` +
      `policy ${ctx.policy.version}; its approval requirement cannot be established.`,
  );
};

const checkRolePermitsAction: CheckFn = (ctx) => {
  const { action } = ctx.request;
  const roles = ctx.request.actor.roles;
  const permittingRoles = roles.filter((role) => {
    const grants = lookup(ctx.policy.roles, role);
    return grants !== undefined && grants.includes(action);
  });
  const unknownRoles = roles.filter((role) => lookup(ctx.policy.roles, role) === undefined);
  const permitted = permittingRoles.length > 0;
  return result(
    'ROLE_PERMITS_ACTION',
    'HARD',
    permitted,
    permitted
      ? `Role(s) [${permittingRoles.join(', ')}] grant action '${action}'.`
      : `No role held by the actor grants action '${action}'.`,
    {
      action,
      actorRoles: uniqueSorted(roles),
      permittingRoles: uniqueSorted(permittingRoles),
      unknownRoles: uniqueSorted(unknownRoles),
    },
    `role.not_permitted: none of the actor roles [${roles.join(', ')}] grant action '${action}' ` +
      `under policy ${ctx.policy.version}.`,
  );
};

const checkOrganisationMatch: CheckFn = (ctx) => {
  const actorOrg = ctx.request.actor.organisationId;
  const targetOrg = ctx.request.target.organisationId;
  const match = actorOrg === targetOrg;
  return result(
    'ORGANISATION_MATCH',
    'HARD',
    match,
    match
      ? `Actor and target belong to organisation '${actorOrg}'.`
      : `Actor organisation '${actorOrg}' differs from target organisation '${targetOrg}'.`,
    {
      actorOrganisationId: actorOrg,
      targetOrganisationId: targetOrg,
      match,
      targetSiteId: ctx.request.target.siteId ?? null,
    },
    `organisation.mismatch: actor organisation '${actorOrg}' may not act on target ` +
      `organisation '${targetOrg}'; cross-organisation action is denied.`,
  );
};

const checkClassificationConsistent: CheckFn = (ctx) => {
  const { classification, classificationLevel } = ctx.request.target;
  const consistent =
    ctx.canonicalLevel !== undefined && ctx.canonicalLevel === classificationLevel;
  return result(
    'CLASSIFICATION_CONSISTENT',
    'HARD',
    consistent,
    consistent
      ? `Target classification '${classification}' agrees with declared level ${classificationLevel}.`
      : `Target classification '${classification}' does not agree with declared level ` +
          `${String(classificationLevel)}; evaluating at the stricter level ${ctx.effectiveLevel}.`,
    {
      classification,
      declaredClassificationLevel: classificationLevel,
      canonicalClassificationLevel: ctx.canonicalLevel ?? null,
      effectiveClassificationLevel: ctx.effectiveLevel,
      consistent,
    },
    `classification.inconsistent: target declares '${classification}' (canonical level ` +
      `${ctx.canonicalLevel ?? 'unknown'}) but level ${String(classificationLevel)}; ` +
      `a request whose classification fields disagree is denied.`,
  );
};

const checkClearanceSufficient: CheckFn = (ctx) => {
  const clearance = ctx.request.actor.clearance;
  const sufficient = Number.isFinite(clearance) && clearance >= ctx.effectiveLevel;
  return result(
    'CLEARANCE_SUFFICIENT',
    'HARD',
    sufficient,
    sufficient
      ? `Actor clearance ${clearance} >= required level ${ctx.effectiveLevel}.`
      : `Actor clearance ${String(clearance)} < required level ${ctx.effectiveLevel}.`,
    {
      actorClearance: Number.isFinite(clearance) ? clearance : String(clearance),
      declaredClassificationLevel: ctx.request.target.classificationLevel,
      effectiveClassificationLevel: ctx.effectiveLevel,
      classification: ctx.request.target.classification,
      sufficient,
    },
    `clearance.insufficient: actor clearance ${String(clearance)} is below the required ` +
      `classification level ${ctx.effectiveLevel} ('${ctx.request.target.classification}').`,
  );
};

const checkDeviceTrustAcceptable: CheckFn = (ctx) => {
  const trust = ctx.request.actor.deviceTrust;
  const acceptable = deviceTrustAcceptable(trust, ctx.effectiveLevel);
  return result(
    'DEVICE_TRUST_ACCEPTABLE',
    'HARD',
    acceptable,
    acceptable
      ? `Device trust '${trust}' is acceptable for classification level ${ctx.effectiveLevel}.`
      : `Device trust '${trust}' is not acceptable for classification level ${ctx.effectiveLevel}.`,
    {
      deviceTrust: trust,
      effectiveClassificationLevel: ctx.effectiveLevel,
      classification: ctx.request.target.classification,
      suspiciousDeviceMaxLevel: SUSPICIOUS_DEVICE_MAX_LEVEL,
      acceptable,
    },
    trust === 'SUSPICIOUS'
      ? `device.trust_insufficient: a SUSPICIOUS device may only reach classification level ` +
          `${SUSPICIOUS_DEVICE_MAX_LEVEL} (INTERNAL) or below; target is level ${ctx.effectiveLevel} ` +
          `('${ctx.request.target.classification}').`
      : `device.trust_insufficient: device trust '${trust}' is never accepted for a ` +
          `consequential action.`,
  );
};

const checkPurposePresent: CheckFn = (ctx) => {
  const purpose = (ctx.request.actor.purpose ?? '').trim();
  const required = ctx.effectiveLevel >= PURPOSE_REQUIRED_AT_LEVEL;
  const provided = purpose.length > 0;
  const passed = !required || provided;
  return result(
    'PURPOSE_PRESENT',
    'HARD',
    passed,
    required
      ? provided
        ? `Purpose required at level ${ctx.effectiveLevel} and supplied: "${purpose}".`
        : `Purpose required at level ${ctx.effectiveLevel} but not supplied.`
      : `Purpose not required at level ${ctx.effectiveLevel}.`,
    {
      purposeRequired: required,
      purposeProvided: provided,
      purpose: provided ? purpose : null,
      effectiveClassificationLevel: ctx.effectiveLevel,
      purposeRequiredAtLevel: PURPOSE_REQUIRED_AT_LEVEL,
    },
    `purpose.missing: a non-empty purpose is mandatory for targets classified ` +
      `'${ctx.request.target.classification}' (level ${ctx.effectiveLevel} >= ` +
      `${PURPOSE_REQUIRED_AT_LEVEL}).`,
  );
};

const checkApprovalSelfExclusion: CheckFn = (ctx) => {
  const selfIds = selfApprovalIds(ctx);
  const approvalNeeded = ctx.requiredApprovers > 0;
  const passed = !approvalNeeded || selfIds.length === 0;
  return result(
    'APPROVAL_SELF_EXCLUSION',
    'APPROVAL',
    passed,
    approvalNeeded
      ? selfIds.length === 0
        ? `No approval was supplied by the actor themselves.`
        : `Actor '${ctx.request.actor.userId}' supplied their own approval; it is excluded.`
      : `Action requires no approval; approver identity not assessed.`,
    {
      actorUserId: ctx.request.actor.userId,
      approvalRequirement: ctx.requirement,
      requiredDistinctApprovers: ctx.requiredApprovers,
      suppliedApprovalCount: ctx.approvals.length,
      selfApprovalCount: ctx.approvals.filter((a) => a.userId === ctx.request.actor.userId).length,
      selfApproverIds: selfIds,
    },
    `approval.self_approval_not_permitted: actor '${ctx.request.actor.userId}' cannot approve ` +
      `their own action; the self-approval was excluded from the approver count.`,
  );
};

const checkApprovalDistinctSufficient: CheckFn = (ctx) => {
  const eligible = eligibleApproverIds(ctx);
  const passed = eligible.length >= ctx.requiredApprovers;
  return result(
    'APPROVAL_DISTINCT_SUFFICIENT',
    'APPROVAL',
    passed,
    ctx.requiredApprovers === 0
      ? `Action requires no approval.`
      : `Action requires ${ctx.requiredApprovers} distinct approver(s) other than the actor; ` +
          `${eligible.length} supplied.`,
    {
      approvalRequirement: ctx.requirement,
      requiredDistinctApprovers: ctx.requiredApprovers,
      suppliedApprovalCount: ctx.approvals.length,
      suppliedApproverIds: uniqueSorted(ctx.approvals.map((a) => a.userId)),
      eligibleApproverIds: eligible,
      distinctEligibleApprovers: eligible.length,
      actorUserId: ctx.request.actor.userId,
    },
    ctx.requirement === 'TWO_PERSON'
      ? `approval.insufficient_distinct_approvers: two-person control requires ` +
          `${ctx.requiredApprovers} distinct approvers other than the actor; ` +
          `${eligible.length} eligible approval(s) supplied [${eligible.join(', ')}].`
      : `approval.insufficient_distinct_approvers: ${ctx.requiredApprovers} approver(s) other ` +
          `than the actor required; ${eligible.length} eligible approval(s) supplied ` +
          `[${eligible.join(', ')}].`,
  );
};

const CHECKS: readonly CheckFn[] = [
  checkActionNotProhibited,
  checkActionKnown,
  checkActionCategoryKnown,
  checkRolePermitsAction,
  checkOrganisationMatch,
  checkClassificationConsistent,
  checkClearanceSufficient,
  checkDeviceTrustAcceptable,
  checkPurposePresent,
  checkApprovalSelfExclusion,
  checkApprovalDistinctSufficient,
];

/* -------------------------------------------------------------------------- */
/* Evaluator                                                                  */
/* -------------------------------------------------------------------------- */

function buildContext(request: ConstitutionRequest, policy: Policy): EvaluationContext {
  const categoryId = lookup(policy.actions, request.action);
  const category = categoryId === undefined ? undefined : lookup(policy.categories, categoryId);
  // Fail closed: an action whose category cannot be resolved is treated as the strictest
  // requirement. (It also fails ACTION_CATEGORY_KNOWN, so the decision is DENY regardless.)
  const requirement: ApprovalRequirement = category?.approval ?? 'TWO_PERSON';
  return {
    request,
    policy,
    approvals: request.approvals ?? [],
    canonicalLevel: CLASSIFICATION_LEVELS[request.target.classification],
    effectiveLevel: effectiveClassificationLevel(request.target),
    categoryId,
    category,
    requirement,
    requirementFailClosed: category === undefined,
    requiredApprovers: requiredApproverCount(requirement),
  };
}

/**
 * Evaluate a consequential action against the Constitution.
 *
 * Deny by default: the decision is ALLOW only when every hard check passes and the approval
 * requirement is satisfied. Every check runs and is recorded, so the returned `trace` fully
 * explains the outcome for the Decision Ledger.
 */
export function evaluate(request: ConstitutionRequest, policy: Policy): ConstitutionDecision {
  const ctx = buildContext(request, policy);

  const results: readonly CheckResult[] = CHECKS.map((check) => check(ctx));

  const trace: readonly TraceEntry[] = results.map((r, index) =>
    Object.freeze({
      seq: index + 1,
      check: r.check,
      severity: r.severity,
      outcome: r.outcome,
      summary: r.summary,
      values: Object.freeze({ ...r.values }),
    }),
  );

  const hardFailures = results.filter((r) => r.severity === 'HARD' && r.outcome === 'FAIL');
  const approvalFailures = results.filter((r) => r.severity === 'APPROVAL' && r.outcome === 'FAIL');

  let decision: Decision;
  const reasons: string[] = [];

  if (hardFailures.length > 0) {
    decision = 'DENY';
    reasons.push(
      `deny.hard_check_failed: ${hardFailures.length} of ${CHECK_SEQUENCE.length} constitution ` +
        `check(s) failed under policy ${policy.version}; deny-by-default applied.`,
    );
  } else if (approvalFailures.length > 0) {
    decision = ctx.requirement === 'TWO_PERSON' ? 'REQUIRE_TWO_PERSON' : 'REQUIRE_APPROVAL';
    reasons.push(
      `approval.pending: every hard constitution check passed; the action is held pending ` +
        `approval requirement '${ctx.requirement}' (${ctx.requiredApprovers} distinct approver(s) ` +
        `other than the actor).`,
    );
  } else {
    decision = 'ALLOW';
    const eligible = eligibleApproverIds(ctx);
    reasons.push(
      `allow.authorised: action '${request.action}' authorised for actor ` +
        `'${request.actor.userId}' on target organisation '${request.target.organisationId}' ` +
        `under policy ${policy.version}; all ${CHECK_SEQUENCE.length} checks passed.`,
    );
    if (ctx.requiredApprovers > 0) {
      reasons.push(
        `approval.satisfied: approval requirement '${ctx.requirement}' satisfied by ` +
          `${eligible.length} distinct approver(s) [${eligible.join(', ')}], none of whom is the actor.`,
      );
    }
  }

  // Failure reasons follow in check order, so the most fundamental bar (prohibition) is first.
  for (const r of results) {
    if (r.reason !== null) reasons.push(r.reason);
  }

  return Object.freeze({
    decision,
    policyVersion: policy.version,
    reasons: Object.freeze(reasons),
    trace: Object.freeze(trace),
  });
}

/* -------------------------------------------------------------------------- */
/* Baseline SENTINEL policy                                                   */
/* -------------------------------------------------------------------------- */

/** Deep-freezes a policy so a loaded constitution cannot be mutated at runtime. */
function freezePolicy(policy: Policy): Policy {
  Object.freeze(policy.prohibitedActions);
  for (const grants of Object.values(policy.roles)) Object.freeze(grants);
  Object.freeze(policy.roles);
  for (const category of Object.values(policy.categories)) Object.freeze(category);
  Object.freeze(policy.categories);
  Object.freeze(policy.actions);
  return Object.freeze(policy);
}

/**
 * A minimal baseline constitution.
 *
 * The six TWO_PERSON categories are exactly the §58.2 control list. Prohibited actions are
 * registered (so the constitution can name and classify them) but granted to no role.
 */
export const SENTINEL_BASELINE_POLICY: Policy = freezePolicy({
  version: 'sentinel-constitution-1.0.0',

  categories: {
    routine_read: { approval: 'NONE', description: 'Read of operational records.' },
    routine_write: { approval: 'NONE', description: 'Annotation of operational records.' },

    sensitive_data_export: {
      approval: 'ONE',
      description: 'Export of sensitive data outside the platform.',
    },
    account_privilege_change: {
      approval: 'ONE',
      description: 'Change to a user account role or privilege.',
    },

    // §58.2 — two-person control.
    exceptional_tracking_powers: {
      approval: 'TWO_PERSON',
      description: '§58.2 Use of exceptional tracking powers.',
    },
    controlled_reality_high_activation: {
      approval: 'TWO_PERSON',
      description: '§58.2 High-level Controlled Reality activation.',
    },
    disable_critical_security_protection: {
      approval: 'TWO_PERSON',
      description: '§58.2 Disabling a critical security protection.',
    },
    export_restricted_biometric_evidence: {
      approval: 'TWO_PERSON',
      description: '§58.2 Export of restricted biometric evidence.',
    },
    modify_evidence_retention_legal_hold: {
      approval: 'TWO_PERSON',
      description: '§58.2 Modification of evidence retention under legal hold.',
    },
    alter_core_constitution_rules: {
      approval: 'TWO_PERSON',
      description: '§58.2 Alteration of core Constitution rules.',
    },

    irreversible_integrity_destruction: {
      approval: 'TWO_PERSON',
      description: 'Destruction of integrity records (prohibited in this policy).',
    },
  },

  actions: {
    'incident.view': 'routine_read',
    'incident.annotate': 'routine_write',
    'report.export.summary': 'sensitive_data_export',
    'user.role.grant': 'account_privilege_change',

    'tracking.exceptional.enable': 'exceptional_tracking_powers',
    'reality.controlled.activate.high': 'controlled_reality_high_activation',
    'security.protection.disable': 'disable_critical_security_protection',
    'evidence.biometric.export.restricted': 'export_restricted_biometric_evidence',
    'evidence.retention.modify.legalhold': 'modify_evidence_retention_legal_hold',
    'constitution.rules.alter.core': 'alter_core_constitution_rules',

    // Registered so they can be named and classified — but prohibited below.
    'audit.ledger.delete': 'irreversible_integrity_destruction',
    'surveillance.mass.covert.enable': 'exceptional_tracking_powers',
    'evidence.legalhold.destroy': 'modify_evidence_retention_legal_hold',
    'constitution.evaluator.bypass': 'alter_core_constitution_rules',
  },

  roles: {
    viewer: ['incident.view'],
    analyst: ['incident.view', 'incident.annotate', 'report.export.summary'],
    'evidence.custodian': [
      'incident.view',
      'evidence.biometric.export.restricted',
      'evidence.retention.modify.legalhold',
    ],
    'security.officer': [
      'incident.view',
      'tracking.exceptional.enable',
      'reality.controlled.activate.high',
      'security.protection.disable',
    ],
    'platform.admin': ['incident.view', 'user.role.grant'],
    'constitution.steward': ['incident.view', 'constitution.rules.alter.core'],
  },

  prohibitedActions: [
    'audit.ledger.delete',
    'surveillance.mass.covert.enable',
    'evidence.legalhold.destroy',
    'constitution.evaluator.bypass',
  ],
});
