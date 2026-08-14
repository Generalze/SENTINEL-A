/**
 * SENTINEL — Constitution Evaluator
 *
 * Architecture references: §5.1 (hardened, versioned policy layer), §58.2 (two-person control
 * list), §61 (deterministic domain rules — AI may inform, never silently replace), §62.1
 * (permission conjuncts / Decision Ledger trace requirements).
 *
 * Provenance
 * ----------
 * This is the certified CERT-O evaluator
 * (`docs/execution/certification/artifacts/cert-o/constitution.ts`) ported into the service with
 * its semantics intact. The only engine-level change is the addition of the
 * `APPROVAL_ROLE_AUTHORISED` check (WP-06 mandatory addition 1) and the two data fields it
 * needs: `ActionCategory.approval_roles` and `ConstitutionRequest.approver_roles`.
 *
 * Design contract (unchanged from CERT-O)
 * ---------------------------------------
 * 1. DENY BY DEFAULT. `evaluate` starts from "not authorised" and only reaches ALLOW when
 *    every hard check passes. Anything unknown (unregistered action, unresolved category,
 *    unrecognised classification label, unusable numeric input) fails closed.
 * 2. NO SHORT-CIRCUITING. Every check in `CHECK_SEQUENCE` runs on every evaluation, in a
 *    fixed order, and emits exactly one trace entry. A Decision Ledger entry is therefore
 *    uniform and self-explaining: a reviewer can reconstruct the outcome from the trace
 *    alone, without re-running the evaluator.
 * 3. PURE. `evaluate` reads its inputs, mutates nothing, and is deterministic. No clock,
 *    no I/O, no globals. The result is frozen before it is returned.
 *
 * Note on identity (WP-03): the engine never talks to Identity. Approver roles are *resolved
 * data supplied by the caller* (`approver_roles`), which keeps the engine pure and keeps
 * WP-06 free of a build-time dependency on the concurrently-built identity module.
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
  /**
   * The role the approver *claims* to be acting under. Recorded for the ledger; it is NOT
   * the basis of the authority decision — APPROVAL_ROLE_AUTHORISED uses the caller-resolved
   * `approver_roles` map instead, because a self-asserted role is not evidence of authority.
   */
  readonly role: string;
  /** ISO-8601 timestamp. Recorded for the ledger; not interpreted by the evaluator. */
  readonly at: string;
}

/**
 * Roles resolved for approvers, keyed by user id.
 *
 * The caller (an in-process module, or the HTTP layer) resolves these from Identity at call
 * time and hands them to the engine. Naming follows the WP-06 directive verbatim
 * (`approver_roles`), which is why it is snake_case where the surrounding CERT-O types are
 * camelCase.
 */
export type ApproverRoles = Readonly<Record<string, readonly string[]>>;

export interface ConstitutionRequest {
  readonly action: string;
  readonly actor: Actor;
  readonly target: Target;
  readonly approvals?: readonly Approval[];
  /**
   * Resolved roles per approver user id. Absent or missing entries mean "no resolved roles",
   * which fails closed: such an approval cannot be role-authorised and does not count.
   */
  readonly approver_roles?: ApproverRoles;
}

/* -------------------------------------------------------------------------- */
/* Policy representation                                                      */
/* -------------------------------------------------------------------------- */

/** How many *distinct* approvers, other than the actor, an action category demands. */
export type ApprovalRequirement = 'NONE' | 'ONE' | 'TWO_PERSON';

export interface ActionCategory {
  readonly approval: ApprovalRequirement;
  readonly description: string;
  /**
   * Roles that carry approval authority for this category (WP-06 addition 1). An approval
   * only counts when the approver's *resolved* roles intersect this list. Must be non-empty
   * for ONE / TWO_PERSON categories — see `validatePolicy`.
   */
  readonly approval_roles: readonly string[];
  /**
   * WP-14/M2: when true, two-person control additionally requires APPROVER-ROLE
   * DIVERSITY — the eligible approvers must cover at least `requiredApprovers`
   * DISTINCT authorising roles, so two members of the same function cannot
   * collude to satisfy the control. Opt-in per category ("where the policy
   * demands it"): absent/false preserves the certified CERT-O behaviour of
   * counting distinct approver identities only.
   */
  readonly require_role_diversity?: boolean;
}

/**
 * A versioned constitution policy.
 *
 * - `categories`  category id  -> approval requirement + approval authority (§58.2 lists)
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
  | 'APPROVAL_ROLE_AUTHORISED'
  | 'APPROVAL_DISTINCT_SUFFICIENT';

/**
 * The canonical, ordered set of checks. Every evaluation emits all of them, exactly once.
 *
 * APPROVAL_ROLE_AUTHORISED sits between the two CERT-O approval checks on purpose: the
 * exclusions run first (the actor's own approval, then approvals without authority), and the
 * counting check runs last over whatever survived.
 */
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
  'APPROVAL_ROLE_AUTHORISED',
  'APPROVAL_DISTINCT_SUFFICIENT',
];

/** Identifies the evaluator build in the Decision Ledger alongside the policy version. */
export const CONSTITUTION_ENGINE_VERSION = 'constitution-engine-1.1.0';

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
  /** The resolved category's approval authority list; empty when the category is unresolved. */
  readonly approvalRoles: readonly string[];
  /** WP-14/M2: whether the resolved category demands approver-role diversity for two-person control. */
  readonly requireRoleDiversity: boolean;
  /** Caller-resolved roles per approver user id; empty map when the caller supplied none. */
  readonly approverRoles: ApproverRoles;
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

/**
 * WP-14/M2: normalise a user id (trim + case-fold) before any identity
 * comparison. Without this, an approval whose id differs from the actor's only
 * by surrounding whitespace or letter-case would slip past self-exclusion, and
 * two spellings of one person's id would each be counted as a distinct
 * approver — defeating both the self-approval bar and two-person control.
 */
export function normaliseApproverId(id: string): string {
  return id.trim().toLowerCase();
}

/** Approvals that are not the actor's own and carry a usable user id (normalised comparison). */
function candidateApprovals(ctx: EvaluationContext): readonly Approval[] {
  const actorId = normaliseApproverId(ctx.request.actor.userId);
  return ctx.approvals.filter((a) => normaliseApproverId(a.userId) !== actorId && a.userId.trim().length > 0);
}

/** The roles the caller resolved for `userId`; `[]` when none were supplied. Keyed on the normalised id. */
function resolvedRolesFor(ctx: EvaluationContext, userId: string): readonly string[] {
  return lookup(ctx.approverRoles, normaliseApproverId(userId)) ?? lookup(ctx.approverRoles, userId) ?? [];
}

/** The subset of an approver's resolved roles that carry approval authority for the action's category. */
function authorisingRolesFor(ctx: EvaluationContext, userId: string): readonly string[] {
  return resolvedRolesFor(ctx, userId).filter((role) => ctx.approvalRoles.includes(role));
}

/**
 * Does this approver hold approval authority for the action's category?
 *
 * Fails closed twice over: an unresolved category (no approval roles) authorises nobody, and
 * an approver with no resolved roles is authorised for nothing.
 */
function isRoleAuthorisedApprover(ctx: EvaluationContext, userId: string): boolean {
  if (ctx.approvalRoles.length === 0) return false;
  return resolvedRolesFor(ctx, userId).some((role) => ctx.approvalRoles.includes(role));
}

/** Approvals that may count: not the actor's own, usable user id, and role-authorised (deduped on the normalised id). */
function eligibleApproverIds(ctx: EvaluationContext): readonly string[] {
  return uniqueSorted(
    candidateApprovals(ctx)
      .filter((a) => isRoleAuthorisedApprover(ctx, a.userId))
      .map((a) => normaliseApproverId(a.userId)),
  );
}

function selfApprovalIds(ctx: EvaluationContext): readonly string[] {
  const actorId = normaliseApproverId(ctx.request.actor.userId);
  return uniqueSorted(
    ctx.approvals.filter((a) => normaliseApproverId(a.userId) === actorId).map((a) => normaliseApproverId(a.userId)),
  );
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
      selfApprovalCount: ctx.approvals.filter(
        (a) => normaliseApproverId(a.userId) === normaliseApproverId(ctx.request.actor.userId),
      ).length,
      selfApproverIds: selfIds,
    },
    `approval.self_approval_not_permitted: actor '${ctx.request.actor.userId}' cannot approve ` +
      `their own action; the self-approval was excluded from the approver count.`,
  );
};

/**
 * WP-06 addition 1 — approver-role validation (§62.1: authority is an attribute of the
 * approver, not a claim on the approval).
 *
 * Mirrors APPROVAL_SELF_EXCLUSION deliberately: it reports *exclusions*, not the count. Any
 * non-self approval whose resolved roles do not intersect the category's `approval_roles` is
 * excluded from the approver count and fails this check, exactly as a self-approval does.
 * The count itself is then made by APPROVAL_DISTINCT_SUFFICIENT over the survivors.
 */
const checkApprovalRoleAuthorised: CheckFn = (ctx) => {
  const approvalNeeded = ctx.requiredApprovers > 0;
  const candidates = candidateApprovals(ctx);
  const candidateIds = uniqueSorted(candidates.map((a) => normaliseApproverId(a.userId)));
  const authorisedIds = eligibleApproverIds(ctx);
  const unauthorisedIds = candidateIds.filter((id) => !authorisedIds.includes(id));
  const passed = !approvalNeeded || unauthorisedIds.length === 0;
  const blankIdApprovalCount = ctx.approvals.filter(
    (a) => normaliseApproverId(a.userId) !== normaliseApproverId(ctx.request.actor.userId) && a.userId.trim().length === 0,
  ).length;

  return result(
    'APPROVAL_ROLE_AUTHORISED',
    'APPROVAL',
    passed,
    approvalNeeded
      ? unauthorisedIds.length === 0
        ? `All ${candidateIds.length} non-self approval(s) carry approval authority for ` +
            `category '${ctx.categoryId ?? 'unresolved'}'.`
        : `Approver(s) [${unauthorisedIds.join(', ')}] hold no role authorised to approve ` +
            `category '${ctx.categoryId ?? 'unresolved'}'; their approvals are excluded.`
      : `Action requires no approval; approver authority not assessed.`,
    {
      approvalRequirement: ctx.requirement,
      requiredDistinctApprovers: ctx.requiredApprovers,
      category: ctx.categoryId ?? null,
      categoryApprovalRoles: uniqueSorted([...ctx.approvalRoles]),
      approverRolesSupplied: ctx.request.approver_roles !== undefined,
      suppliedApproverIds: candidateIds,
      authorisedApproverIds: authorisedIds,
      unauthorisedApproverIds: unauthorisedIds,
      blankIdApprovalCount,
    },
    `approval.role_not_authorised: approver(s) [${unauthorisedIds.join(', ')}] hold none of the ` +
      `roles authorised to approve category '${ctx.categoryId ?? 'unresolved'}' ` +
      `([${[...ctx.approvalRoles].join(', ')}]) under policy ${ctx.policy.version}; their ` +
      `approvals are excluded from the approver count.`,
  );
};

const checkApprovalDistinctSufficient: CheckFn = (ctx) => {
  const eligible = eligibleApproverIds(ctx);
  // WP-14/M2: two-person control additionally requires ROLE DIVERSITY — the
  // eligible approvers must, between them, cover at least `requiredApprovers`
  // distinct authorising roles, so two members of the same function cannot
  // collude to satisfy a §58.2 two-person control. Single-approval categories
  // and no-approval categories are unaffected (this only makes TWO_PERSON
  // stricter, never looser — CERT-O deny-by-default is preserved).
  const distinctAuthorisingRoles = uniqueSorted(eligible.flatMap((id) => [...authorisingRolesFor(ctx, id)]));
  // Diversity is enforced ONLY when the category opts in (keeps CERT-O intact
  // for every baseline category, which counts distinct identities only).
  const roleDiverse = !ctx.requireRoleDiversity || distinctAuthorisingRoles.length >= ctx.requiredApprovers;
  const passed = eligible.length >= ctx.requiredApprovers && roleDiverse;
  return result(
    'APPROVAL_DISTINCT_SUFFICIENT',
    'APPROVAL',
    passed,
    ctx.requiredApprovers === 0
      ? `Action requires no approval.`
      : `Action requires ${ctx.requiredApprovers} distinct approver(s) other than the actor; ` +
          `${eligible.length} supplied${ctx.requirement === 'TWO_PERSON' ? `, covering ${distinctAuthorisingRoles.length} authorising role(s)` : ''}.`,
    {
      approvalRequirement: ctx.requirement,
      requiredDistinctApprovers: ctx.requiredApprovers,
      suppliedApprovalCount: ctx.approvals.length,
      suppliedApproverIds: uniqueSorted(ctx.approvals.map((a) => normaliseApproverId(a.userId))),
      eligibleApproverIds: eligible,
      distinctEligibleApprovers: eligible.length,
      distinctAuthorisingRoles,
      roleDiverse,
      actorUserId: ctx.request.actor.userId,
    },
    ctx.requirement === 'TWO_PERSON'
      ? `approval.insufficient_distinct_approvers: two-person control requires ` +
          `${ctx.requiredApprovers} distinct approvers other than the actor holding ` +
          `${ctx.requiredApprovers} distinct authorising roles; ${eligible.length} eligible ` +
          `approval(s) [${eligible.join(', ')}] covering ${distinctAuthorisingRoles.length} role(s).`
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
  checkApprovalRoleAuthorised,
  checkApprovalDistinctSufficient,
];

/* -------------------------------------------------------------------------- */
/* Evaluator                                                                  */
/* -------------------------------------------------------------------------- */

const NO_APPROVER_ROLES: ApproverRoles = Object.freeze({});

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
    // An unresolved category authorises nobody: no approval roles at all.
    approvalRoles: category?.approval_roles ?? [],
    requireRoleDiversity: category?.require_role_diversity === true,
    approverRoles: request.approver_roles ?? NO_APPROVER_ROLES,
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
