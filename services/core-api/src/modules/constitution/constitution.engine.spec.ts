/**
 * SENTINEL — ported CERT-O evaluator suite.
 *
 * This is `docs/execution/certification/artifacts/cert-o/constitution.test.ts`, ported with its
 * semantics intact. Every `describe`, every `it` and every assertion is unchanged. Three
 * fixture-level adaptations were unavoidable once APPROVAL_ROLE_AUTHORISED joined the check
 * sequence, and none of them weakens an assertion:
 *
 *  1. `makeRequest` now also supplies `approver_roles`, derived from each approval's claimed
 *     role. That is exactly what a caller does in production — resolve the approver's roles
 *     from Identity and hand them to the engine. Without it every approval would be
 *     unauthorised (the engine fails closed on unresolved roles) and the CERT-O approval
 *     scenarios would be testing the wrong thing.
 *  2. `REASON_CODE_BY_CHECK` gains the new check's reason code; the map is typed
 *     `Record<CheckId, string>`, so it would not compile otherwise.
 *  3. Imports point at the ported module rather than the certification artifact.
 *
 * The baseline policy's approval-authority lists were chosen so that every approver role used
 * below is genuinely authorised for the category it approves — the ported expectations were
 * not relaxed to accommodate the new check.
 */

import { describe, expect, it } from 'vitest';

import {
  CHECK_SEQUENCE,
  CLASSIFICATION_LEVELS,
  evaluate,
  type Actor,
  type Approval,
  type CheckId,
  type Classification,
  type ConstitutionDecision,
  type ConstitutionRequest,
  type Policy,
  type Target,
  type TraceEntry,
} from './constitution.engine';
import { SENTINEL_BASELINE_POLICY } from './constitution.policy';

/* -------------------------------------------------------------------------- */
/* Fixtures                                                                   */
/* -------------------------------------------------------------------------- */

const ORG = 'org-sentinel-1';
const OTHER_ORG = 'org-sentinel-2';

function makeActor(overrides: Partial<Actor> = {}): Actor {
  return {
    userId: 'u-actor',
    roles: ['analyst'],
    organisationId: ORG,
    clearance: 3,
    deviceTrust: 'TRUSTED',
    ...overrides,
  };
}

/** Builds a self-consistent target (declared level == canonical level) unless overridden. */
function makeTarget(classification: Classification, overrides: Partial<Target> = {}): Target {
  return {
    organisationId: ORG,
    classification,
    classificationLevel: CLASSIFICATION_LEVELS[classification] ?? 5,
    ...overrides,
  };
}

function makeApproval(userId: string, role = 'security.officer'): Approval {
  return { userId, role, at: '2026-08-14T10:00:00.000Z' };
}

/**
 * Stands in for the caller resolving approver roles from Identity (WP-03). In these fixtures
 * the resolved role is the one the approval claims; the dedicated approver-role suite covers
 * the cases where the two differ.
 */
function resolvedRolesFrom(approvals: readonly Approval[]): Record<string, string[]> {
  const resolved: Record<string, string[]> = {};
  for (const approval of approvals) {
    const existing = resolved[approval.userId] ?? [];
    resolved[approval.userId] = existing.includes(approval.role)
      ? existing
      : [...existing, approval.role];
  }
  return resolved;
}

function makeRequest(
  action: string,
  actor: Actor,
  target: Target,
  approvals?: readonly Approval[],
): ConstitutionRequest {
  return approvals === undefined
    ? { action, actor, target }
    : { action, actor, target, approvals, approver_roles: resolvedRolesFrom(approvals) };
}

/**
 * A deliberately misconfigured policy: a role has been granted a prohibited action.
 * Used to prove that prohibition outranks role grants and approvals.
 */
const MISCONFIGURED_POLICY: Policy = {
  ...SENTINEL_BASELINE_POLICY,
  version: 'sentinel-constitution-1.1.0-misconfigured',
  roles: {
    ...SENTINEL_BASELINE_POLICY.roles,
    'constitution.steward': [
      ...(SENTINEL_BASELINE_POLICY.roles['constitution.steward'] ?? []),
      'constitution.evaluator.bypass',
    ],
  },
};

/* -------------------------------------------------------------------------- */
/* Assertion helpers                                                          */
/* -------------------------------------------------------------------------- */

function failedChecks(decision: ConstitutionDecision): CheckId[] {
  return decision.trace.filter((e) => e.outcome === 'FAIL').map((e) => e.check);
}

function traceEntry(decision: ConstitutionDecision, check: CheckId): TraceEntry {
  const found = decision.trace.find((e) => e.check === check);
  if (found === undefined) throw new Error(`trace is missing check ${check}`);
  return found;
}

function hasReasonCode(decision: ConstitutionDecision, code: string): boolean {
  return decision.reasons.some((r) => r.startsWith(`${code}:`));
}

/** The reason code each check emits when it fails — used by the trace-completeness tests. */
const REASON_CODE_BY_CHECK: Readonly<Record<CheckId, string>> = {
  ACTION_NOT_PROHIBITED: 'action.prohibited',
  ACTION_KNOWN: 'action.unknown',
  ACTION_CATEGORY_KNOWN: 'policy.category_unresolved',
  ROLE_PERMITS_ACTION: 'role.not_permitted',
  ORGANISATION_MATCH: 'organisation.mismatch',
  CLASSIFICATION_CONSISTENT: 'classification.inconsistent',
  CLEARANCE_SUFFICIENT: 'clearance.insufficient',
  DEVICE_TRUST_ACCEPTABLE: 'device.trust_insufficient',
  PURPOSE_PRESENT: 'purpose.missing',
  APPROVAL_SELF_EXCLUSION: 'approval.self_approval_not_permitted',
  APPROVAL_ROLE_AUTHORISED: 'approval.role_not_authorised',
  APPROVAL_DISTINCT_SUFFICIENT: 'approval.insufficient_distinct_approvers',
};

/* -------------------------------------------------------------------------- */
/* Registration and prohibition                                               */
/* -------------------------------------------------------------------------- */

describe('deny by default: unregistered actions', () => {
  it('denies an action that is not registered in the policy', () => {
    const decision = evaluate(
      makeRequest('incident.teleport', makeActor(), makeTarget('PUBLIC')),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    expect(hasReasonCode(decision, 'action.unknown')).toBe(true);
    expect(failedChecks(decision)).toContain('ACTION_KNOWN');
  });

  it('denies an unregistered action even when approvals are supplied (never REQUIRE_*)', () => {
    const decision = evaluate(
      makeRequest('incident.teleport', makeActor(), makeTarget('PUBLIC'), [
        makeApproval('u-approver-1'),
        makeApproval('u-approver-2'),
      ]),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    expect(failedChecks(decision)).toEqual(
      expect.arrayContaining(['ACTION_KNOWN', 'ACTION_CATEGORY_KNOWN', 'ROLE_PERMITS_ACTION']),
    );
  });
});

describe('prohibited actions', () => {
  it('denies a prohibited action even with two valid, distinct approvals and full clearance', () => {
    const actor = makeActor({
      userId: 'u-steward',
      roles: ['constitution.steward'],
      clearance: 5,
      purpose: 'Emergency maintenance authorised by the board',
    });
    const decision = evaluate(
      makeRequest('constitution.evaluator.bypass', actor, makeTarget('SECRETS'), [
        makeApproval('u-approver-1', 'constitution.steward'),
        makeApproval('u-approver-2', 'security.officer'),
      ]),
      MISCONFIGURED_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    // Everything else passed: prohibition alone is what stopped it.
    expect(failedChecks(decision)).toEqual(['ACTION_NOT_PROHIBITED']);
    expect(hasReasonCode(decision, 'action.prohibited')).toBe(true);
    expect(traceEntry(decision, 'APPROVAL_DISTINCT_SUFFICIENT').values['distinctEligibleApprovers'])
      .toBe(2);
  });

  it('denies a prohibited action that no role grants, reporting both bars', () => {
    const decision = evaluate(
      makeRequest(
        'audit.ledger.delete',
        makeActor({ roles: ['platform.admin'], clearance: 5, purpose: 'cleanup' }),
        makeTarget('EVIDENCE'),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    expect(hasReasonCode(decision, 'action.prohibited')).toBe(true);
    expect(hasReasonCode(decision, 'role.not_permitted')).toBe(true);
    // Prohibition is reported first: it is the most fundamental bar.
    expect(decision.reasons[1]).toMatch(/^action\.prohibited:/);
  });
});

/* -------------------------------------------------------------------------- */
/* Tenancy                                                                    */
/* -------------------------------------------------------------------------- */

describe('organisation boundary', () => {
  it('denies a cross-organisation action', () => {
    const decision = evaluate(
      makeRequest(
        'incident.view',
        makeActor(),
        makeTarget('INTERNAL', { organisationId: OTHER_ORG }),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    expect(failedChecks(decision)).toEqual(['ORGANISATION_MATCH']);
    expect(hasReasonCode(decision, 'organisation.mismatch')).toBe(true);

    const entry = traceEntry(decision, 'ORGANISATION_MATCH');
    expect(entry.values['actorOrganisationId']).toBe(ORG);
    expect(entry.values['targetOrganisationId']).toBe(OTHER_ORG);
  });
});

/* -------------------------------------------------------------------------- */
/* Clearance boundary                                                         */
/* -------------------------------------------------------------------------- */

describe('clearance boundary', () => {
  it('allows when clearance equals the target classification level', () => {
    const decision = evaluate(
      makeRequest(
        'incident.annotate',
        makeActor({ clearance: 2, purpose: 'Reviewing incident 42' }),
        makeTarget('SENSITIVE'),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('ALLOW');
    expect(failedChecks(decision)).toEqual([]);
  });

  it('denies when clearance is one level below the target classification level', () => {
    const decision = evaluate(
      makeRequest(
        'incident.annotate',
        makeActor({ clearance: 1, purpose: 'Reviewing incident 42' }),
        makeTarget('SENSITIVE'),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    expect(failedChecks(decision)).toEqual(['CLEARANCE_SUFFICIENT']);

    const entry = traceEntry(decision, 'CLEARANCE_SUFFICIENT');
    expect(entry.values['actorClearance']).toBe(1);
    expect(entry.values['effectiveClassificationLevel']).toBe(2);
  });

  it('allows at the top of the range (clearance 5 against SECRETS)', () => {
    const decision = evaluate(
      makeRequest(
        'incident.view',
        makeActor({ clearance: 5, purpose: 'Key custody audit' }),
        makeTarget('SECRETS'),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('ALLOW');
  });
});

/* -------------------------------------------------------------------------- */
/* Device trust                                                               */
/* -------------------------------------------------------------------------- */

describe('device trust', () => {
  it('denies a COMPROMISED device even for a PUBLIC target', () => {
    const decision = evaluate(
      makeRequest('incident.view', makeActor({ deviceTrust: 'COMPROMISED' }), makeTarget('PUBLIC')),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    expect(failedChecks(decision)).toEqual(['DEVICE_TRUST_ACCEPTABLE']);
    expect(hasReasonCode(decision, 'device.trust_insufficient')).toBe(true);
  });

  it('denies a QUARANTINED device even for a PUBLIC target', () => {
    const decision = evaluate(
      makeRequest('incident.view', makeActor({ deviceTrust: 'QUARANTINED' }), makeTarget('PUBLIC')),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    expect(failedChecks(decision)).toEqual(['DEVICE_TRUST_ACCEPTABLE']);
  });

  it('allows a SUSPICIOUS device against an INTERNAL target', () => {
    const decision = evaluate(
      makeRequest('incident.view', makeActor({ deviceTrust: 'SUSPICIOUS' }), makeTarget('INTERNAL')),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('ALLOW');
  });

  it('denies a SUSPICIOUS device against a SENSITIVE target', () => {
    const decision = evaluate(
      makeRequest(
        'incident.annotate',
        makeActor({ deviceTrust: 'SUSPICIOUS', purpose: 'Reviewing incident 42' }),
        makeTarget('SENSITIVE'),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    expect(failedChecks(decision)).toEqual(['DEVICE_TRUST_ACCEPTABLE']);
    expect(traceEntry(decision, 'DEVICE_TRUST_ACCEPTABLE').values['deviceTrust']).toBe('SUSPICIOUS');
  });

  it('allows a DEGRADED device against a RESTRICTED target', () => {
    const decision = evaluate(
      makeRequest(
        'incident.view',
        makeActor({ deviceTrust: 'DEGRADED', clearance: 3, purpose: 'Scheduled review' }),
        makeTarget('RESTRICTED'),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('ALLOW');
  });
});

/* -------------------------------------------------------------------------- */
/* Purpose                                                                    */
/* -------------------------------------------------------------------------- */

describe('purpose limitation', () => {
  it('denies a SENSITIVE target when no purpose is stated', () => {
    const decision = evaluate(
      makeRequest('incident.annotate', makeActor(), makeTarget('SENSITIVE')),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    expect(failedChecks(decision)).toEqual(['PURPOSE_PRESENT']);
    expect(hasReasonCode(decision, 'purpose.missing')).toBe(true);
  });

  it('treats a whitespace-only purpose as missing', () => {
    const decision = evaluate(
      makeRequest(
        'incident.view',
        makeActor({ clearance: 4, purpose: '   \t  ' }),
        makeTarget('EVIDENCE'),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    expect(failedChecks(decision)).toEqual(['PURPOSE_PRESENT']);
    expect(traceEntry(decision, 'PURPOSE_PRESENT').values['purposeProvided']).toBe(false);
  });

  it('does not require a purpose below SENSITIVE', () => {
    const decision = evaluate(
      makeRequest('incident.view', makeActor(), makeTarget('INTERNAL')),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('ALLOW');
    expect(traceEntry(decision, 'PURPOSE_PRESENT').values['purposeRequired']).toBe(false);
  });
});

/* -------------------------------------------------------------------------- */
/* Role grants                                                                */
/* -------------------------------------------------------------------------- */

describe('role allow lists', () => {
  it('denies when no held role grants the action, and records unknown roles', () => {
    const decision = evaluate(
      makeRequest(
        'incident.annotate',
        makeActor({ roles: ['viewer', 'ghost.role'] }),
        makeTarget('INTERNAL'),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    expect(failedChecks(decision)).toEqual(['ROLE_PERMITS_ACTION']);

    const entry = traceEntry(decision, 'ROLE_PERMITS_ACTION');
    expect(entry.values['permittingRoles']).toEqual([]);
    expect(entry.values['unknownRoles']).toEqual(['ghost.role']);
  });
});

/* -------------------------------------------------------------------------- */
/* Approvals — single and two-person control (§58.2)                          */
/* -------------------------------------------------------------------------- */

describe('single approval control', () => {
  it('returns REQUIRE_APPROVAL when every hard check passes but no approval is supplied', () => {
    const decision = evaluate(
      makeRequest(
        'report.export.summary',
        makeActor({ purpose: 'Quarterly regulator submission' }),
        makeTarget('SENSITIVE'),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('REQUIRE_APPROVAL');
    expect(failedChecks(decision)).toEqual(['APPROVAL_DISTINCT_SUFFICIENT']);
  });

  it('returns ALLOW once a distinct approver has approved', () => {
    const decision = evaluate(
      makeRequest(
        'report.export.summary',
        makeActor({ purpose: 'Quarterly regulator submission' }),
        makeTarget('SENSITIVE'),
        [makeApproval('u-approver-1', 'platform.admin')],
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('ALLOW');
    expect(failedChecks(decision)).toEqual([]);
    expect(hasReasonCode(decision, 'approval.satisfied')).toBe(true);
  });

  it('rejects an actor approving their own action', () => {
    const actor = makeActor({ purpose: 'Quarterly regulator submission' });
    const decision = evaluate(
      makeRequest('report.export.summary', actor, makeTarget('SENSITIVE'), [
        makeApproval(actor.userId, 'analyst'),
      ]),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).not.toBe('ALLOW');
    expect(decision.decision).toBe('REQUIRE_APPROVAL');
    expect(hasReasonCode(decision, 'approval.self_approval_not_permitted')).toBe(true);
    expect(hasReasonCode(decision, 'approval.insufficient_distinct_approvers')).toBe(true);
    expect(traceEntry(decision, 'APPROVAL_DISTINCT_SUFFICIENT').values['distinctEligibleApprovers'])
      .toBe(0);
  });

  it('ignores approvals for actions that require none', () => {
    const actor = makeActor();
    const decision = evaluate(
      makeRequest('incident.view', actor, makeTarget('INTERNAL'), [
        makeApproval(actor.userId, 'analyst'),
      ]),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('ALLOW');
    expect(traceEntry(decision, 'APPROVAL_SELF_EXCLUSION').outcome).toBe('PASS');
  });
});

describe('two-person control (§58.2)', () => {
  const twoPersonActor = (): Actor =>
    makeActor({
      userId: 'u-officer',
      roles: ['security.officer'],
      clearance: 4,
      purpose: 'Warrant 2026-118 execution',
    });

  it('returns REQUIRE_TWO_PERSON when no approvals are supplied', () => {
    const decision = evaluate(
      makeRequest('tracking.exceptional.enable', twoPersonActor(), makeTarget('RESTRICTED')),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('REQUIRE_TWO_PERSON');
    expect(failedChecks(decision)).toEqual(['APPROVAL_DISTINCT_SUFFICIENT']);
  });

  it('returns REQUIRE_TWO_PERSON with only one approval', () => {
    const decision = evaluate(
      makeRequest('tracking.exceptional.enable', twoPersonActor(), makeTarget('RESTRICTED'), [
        makeApproval('u-approver-1'),
      ]),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('REQUIRE_TWO_PERSON');
    expect(traceEntry(decision, 'APPROVAL_DISTINCT_SUFFICIENT').values['distinctEligibleApprovers'])
      .toBe(1);
  });

  it('rejects the same person supplying both approvals', () => {
    const decision = evaluate(
      makeRequest('security.protection.disable', twoPersonActor(), makeTarget('RESTRICTED'), [
        makeApproval('u-approver-1'),
        makeApproval('u-approver-1'),
      ]),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('REQUIRE_TWO_PERSON');
    const entry = traceEntry(decision, 'APPROVAL_DISTINCT_SUFFICIENT');
    expect(entry.values['suppliedApprovalCount']).toBe(2);
    expect(entry.values['distinctEligibleApprovers']).toBe(1);
    expect(entry.values['requiredDistinctApprovers']).toBe(2);
  });

  it('rejects the actor counting as one of the two approvers', () => {
    const actor = twoPersonActor();
    const decision = evaluate(
      makeRequest('reality.controlled.activate.high', actor, makeTarget('RESTRICTED'), [
        makeApproval(actor.userId, 'security.officer'),
        makeApproval('u-approver-1'),
      ]),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('REQUIRE_TWO_PERSON');
    expect(hasReasonCode(decision, 'approval.self_approval_not_permitted')).toBe(true);
    expect(traceEntry(decision, 'APPROVAL_DISTINCT_SUFFICIENT').values['eligibleApproverIds'])
      .toEqual(['u-approver-1']);
  });

  it('allows once two distinct approvers, neither the actor, have approved', () => {
    const decision = evaluate(
      makeRequest('tracking.exceptional.enable', twoPersonActor(), makeTarget('RESTRICTED'), [
        makeApproval('u-approver-1'),
        makeApproval('u-approver-2'),
      ]),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('ALLOW');
    expect(failedChecks(decision)).toEqual([]);
    expect(hasReasonCode(decision, 'approval.satisfied')).toBe(true);
  });

  it('covers every §58.2 category with a two-person requirement', () => {
    const twoPersonActions = [
      'tracking.exceptional.enable',
      'reality.controlled.activate.high',
      'security.protection.disable',
      'evidence.biometric.export.restricted',
      'evidence.retention.modify.legalhold',
      'constitution.rules.alter.core',
    ];

    for (const action of twoPersonActions) {
      const categoryId = SENTINEL_BASELINE_POLICY.actions[action];
      expect(categoryId).toBeDefined();
      const category =
        categoryId === undefined ? undefined : SENTINEL_BASELINE_POLICY.categories[categoryId];
      expect(category?.approval).toBe('TWO_PERSON');
    }
  });
});

/* -------------------------------------------------------------------------- */
/* Classification integrity                                                   */
/* -------------------------------------------------------------------------- */

describe('classification integrity', () => {
  it('denies when the classification label and level disagree, evaluating at the stricter level', () => {
    const decision = evaluate(
      makeRequest(
        'incident.view',
        makeActor({ clearance: 5, purpose: 'Key custody audit' }),
        makeTarget('SECRETS', { classificationLevel: 0 }),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    expect(failedChecks(decision)).toEqual(['CLASSIFICATION_CONSISTENT']);
    expect(hasReasonCode(decision, 'classification.inconsistent')).toBe(true);
    // The under-declared level must not be the one used downstream.
    expect(traceEntry(decision, 'CLEARANCE_SUFFICIENT').values['effectiveClassificationLevel'])
      .toBe(5);
  });

  it('does not let an under-declared level bypass the SUSPICIOUS device rule', () => {
    const decision = evaluate(
      makeRequest(
        'incident.view',
        makeActor({ clearance: 5, deviceTrust: 'SUSPICIOUS', purpose: 'Key custody audit' }),
        makeTarget('SECRETS', { classificationLevel: 0 }),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    expect(failedChecks(decision)).toEqual(
      expect.arrayContaining(['CLASSIFICATION_CONSISTENT', 'DEVICE_TRUST_ACCEPTABLE']),
    );
  });
});

/* -------------------------------------------------------------------------- */
/* Decision Ledger: trace completeness and auditability                       */
/* -------------------------------------------------------------------------- */

describe('decision ledger trace', () => {
  interface LedgerCase {
    readonly expected: string;
    readonly request: ConstitutionRequest;
    readonly policy: Policy;
  }

  const ledgerCases: readonly LedgerCase[] = [
    {
      expected: 'ALLOW',
      request: makeRequest('incident.view', makeActor(), makeTarget('INTERNAL')),
      policy: SENTINEL_BASELINE_POLICY,
    },
    {
      expected: 'DENY',
      request: makeRequest(
        'incident.teleport',
        makeActor({ deviceTrust: 'COMPROMISED' }),
        makeTarget('SECRETS'),
      ),
      policy: SENTINEL_BASELINE_POLICY,
    },
    {
      expected: 'REQUIRE_TWO_PERSON',
      request: makeRequest(
        'tracking.exceptional.enable',
        makeActor({ roles: ['security.officer'], clearance: 4, purpose: 'Warrant 2026-118' }),
        makeTarget('RESTRICTED'),
      ),
      policy: SENTINEL_BASELINE_POLICY,
    },
  ];

  for (const ledgerCase of ledgerCases) {
    it(`records every check, in order, for a ${ledgerCase.expected} decision`, () => {
      const decision = evaluate(ledgerCase.request, ledgerCase.policy);

      expect(decision.decision).toBe(ledgerCase.expected);
      expect(decision.trace).toHaveLength(CHECK_SEQUENCE.length);
      expect(decision.trace.map((e) => e.check)).toEqual([...CHECK_SEQUENCE]);

      decision.trace.forEach((entry, index) => {
        expect(entry.seq).toBe(index + 1);
        expect(['PASS', 'FAIL']).toContain(entry.outcome);
        expect(['HARD', 'APPROVAL']).toContain(entry.severity);
        expect(entry.summary.length).toBeGreaterThan(0);
        expect(Object.keys(entry.values).length).toBeGreaterThan(0);
      });
    });
  }

  it('emits a reason for every failed check, so the outcome is explainable without re-running', () => {
    const decision = evaluate(
      makeRequest(
        'incident.annotate',
        makeActor({
          roles: ['viewer'],
          organisationId: OTHER_ORG,
          clearance: 0,
          deviceTrust: 'COMPROMISED',
        }),
        makeTarget('EVIDENCE'),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    const failed = failedChecks(decision);
    expect(failed).toEqual(
      expect.arrayContaining([
        'ROLE_PERMITS_ACTION',
        'ORGANISATION_MATCH',
        'CLEARANCE_SUFFICIENT',
        'DEVICE_TRUST_ACCEPTABLE',
        'PURPOSE_PRESENT',
      ]),
    );
    for (const check of failed) {
      expect(hasReasonCode(decision, REASON_CODE_BY_CHECK[check])).toBe(true);
    }
    // One decision-level reason plus one per failed check.
    expect(decision.reasons).toHaveLength(failed.length + 1);
  });

  it('records the compared values, not just the outcome', () => {
    const decision = evaluate(
      makeRequest(
        'incident.annotate',
        makeActor({ clearance: 1, purpose: 'Reviewing incident 42' }),
        makeTarget('SENSITIVE'),
      ),
      SENTINEL_BASELINE_POLICY,
    );

    const clearance = traceEntry(decision, 'CLEARANCE_SUFFICIENT');
    expect(clearance.outcome).toBe('FAIL');
    expect(clearance.values).toMatchObject({
      actorClearance: 1,
      declaredClassificationLevel: 2,
      effectiveClassificationLevel: 2,
      classification: 'SENSITIVE',
      sufficient: false,
    });
  });

  it('echoes the policy version and always gives at least one reason', () => {
    const allowed = evaluate(
      makeRequest('incident.view', makeActor(), makeTarget('PUBLIC')),
      SENTINEL_BASELINE_POLICY,
    );
    const denied = evaluate(
      makeRequest('incident.view', makeActor(), makeTarget('PUBLIC', { organisationId: OTHER_ORG })),
      SENTINEL_BASELINE_POLICY,
    );

    for (const decision of [allowed, denied]) {
      expect(decision.policyVersion).toBe(SENTINEL_BASELINE_POLICY.version);
      expect(decision.reasons.length).toBeGreaterThan(0);
    }
    expect(allowed.decision).toBe('ALLOW');
    expect(denied.decision).toBe('DENY');
  });
});

/* -------------------------------------------------------------------------- */
/* Purity                                                                     */
/* -------------------------------------------------------------------------- */

describe('purity and immutability', () => {
  it('does not mutate the request and is deterministic', () => {
    const request = makeRequest(
      'report.export.summary',
      makeActor({ purpose: 'Quarterly regulator submission' }),
      makeTarget('SENSITIVE'),
      [makeApproval('u-approver-1')],
    );
    const snapshot = JSON.stringify(request);

    const first = evaluate(request, SENTINEL_BASELINE_POLICY);
    const second = evaluate(request, SENTINEL_BASELINE_POLICY);

    expect(JSON.stringify(request)).toBe(snapshot);
    expect(first).toEqual(second);
    expect(first.decision).toBe('ALLOW');
  });

  it('returns a frozen decision', () => {
    const decision = evaluate(
      makeRequest('incident.view', makeActor(), makeTarget('PUBLIC')),
      SENTINEL_BASELINE_POLICY,
    );

    expect(Object.isFrozen(decision)).toBe(true);
    expect(Object.isFrozen(decision.trace)).toBe(true);
  });
});
