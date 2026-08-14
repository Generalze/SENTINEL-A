/**
 * SENTINEL — APPROVAL_ROLE_AUTHORISED coverage (WP-06 mandatory addition 1).
 *
 * §62.1: authority is an attribute of the approver, resolved from Identity — not a claim the
 * approval makes about itself. These tests pin that down: an approval only counts when the
 * roles the *caller resolved* for that user intersect the category's approval authority.
 */

import { describe, expect, it } from 'vitest';

import {
  CHECK_SEQUENCE,
  CLASSIFICATION_LEVELS,
  evaluate,
  type Actor,
  type Approval,
  type ApproverRoles,
  type CheckId,
  type Classification,
  type ConstitutionDecision,
  type ConstitutionRequest,
  type Target,
  type TraceEntry,
} from './constitution.engine';
import { SENTINEL_BASELINE_POLICY } from './constitution.policy';

const ORG = 'org-sentinel-1';

/** Two-person action; `exceptional_tracking_powers` authorises officers/directors/commanders. */
const TWO_PERSON_ACTION = 'tracking.exceptional.enable';
/** Single-approval action; `sensitive_data_export` additionally authorises platform.admin. */
const ONE_PERSON_ACTION = 'report.export.summary';

function officer(overrides: Partial<Actor> = {}): Actor {
  return {
    userId: 'u-officer',
    roles: ['security.officer'],
    organisationId: ORG,
    clearance: 4,
    deviceTrust: 'TRUSTED',
    purpose: 'Warrant 2026-118 execution',
    ...overrides,
  };
}

function target(classification: Classification = 'RESTRICTED'): Target {
  return {
    organisationId: ORG,
    classification,
    classificationLevel: CLASSIFICATION_LEVELS[classification] ?? 5,
  };
}

function approval(userId: string, claimedRole = 'security.officer'): Approval {
  return { userId, role: claimedRole, at: '2026-08-14T10:00:00.000Z' };
}

function request(
  action: string,
  actor: Actor,
  approvals: readonly Approval[],
  approver_roles: ApproverRoles,
): ConstitutionRequest {
  return { action, actor, target: target(), approvals, approver_roles };
}

function traceEntry(decision: ConstitutionDecision, check: CheckId): TraceEntry {
  const found = decision.trace.find((e) => e.check === check);
  if (found === undefined) throw new Error(`trace is missing check ${check}`);
  return found;
}

function failedChecks(decision: ConstitutionDecision): CheckId[] {
  return decision.trace.filter((e) => e.outcome === 'FAIL').map((e) => e.check);
}

function hasReasonCode(decision: ConstitutionDecision, code: string): boolean {
  return decision.reasons.some((r) => r.startsWith(`${code}:`));
}

describe('APPROVAL_ROLE_AUTHORISED: the check is always present', () => {
  it('sits between the self-exclusion and the count, and runs on every evaluation', () => {
    expect(CHECK_SEQUENCE.indexOf('APPROVAL_ROLE_AUTHORISED')).toBe(
      CHECK_SEQUENCE.indexOf('APPROVAL_SELF_EXCLUSION') + 1,
    );
    expect(CHECK_SEQUENCE.indexOf('APPROVAL_DISTINCT_SUFFICIENT')).toBe(
      CHECK_SEQUENCE.indexOf('APPROVAL_ROLE_AUTHORISED') + 1,
    );

    // Even an action that needs no approval at all emits the entry.
    const decision = evaluate(
      {
        action: 'incident.view',
        actor: officer({ roles: ['viewer'] }),
        target: target('INTERNAL'),
      },
      SENTINEL_BASELINE_POLICY,
    );

    const entry = traceEntry(decision, 'APPROVAL_ROLE_AUTHORISED');
    expect(entry.outcome).toBe('PASS');
    expect(entry.severity).toBe('APPROVAL');
    expect(entry.values['requiredDistinctApprovers']).toBe(0);
  });
});

describe('APPROVAL_ROLE_AUTHORISED: two-person control', () => {
  it("excludes an unauthorised approver's approval from the two-person count", () => {
    const decision = evaluate(
      request(
        TWO_PERSON_ACTION,
        officer(),
        [approval('u-authorised'), approval('u-unauthorised')],
        {
          'u-authorised': ['security.officer'],
          // A real, resolved role — but one with no approval authority for this category.
          'u-unauthorised': ['viewer'],
        },
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('REQUIRE_TWO_PERSON');
    expect(failedChecks(decision)).toEqual([
      'APPROVAL_ROLE_AUTHORISED',
      'APPROVAL_DISTINCT_SUFFICIENT',
    ]);

    const authorised = traceEntry(decision, 'APPROVAL_ROLE_AUTHORISED');
    expect(authorised.values['authorisedApproverIds']).toEqual(['u-authorised']);
    expect(authorised.values['unauthorisedApproverIds']).toEqual(['u-unauthorised']);

    // The unauthorised approval is not merely reported — it does not count.
    const count = traceEntry(decision, 'APPROVAL_DISTINCT_SUFFICIENT');
    expect(count.values['suppliedApprovalCount']).toBe(2);
    expect(count.values['distinctEligibleApprovers']).toBe(1);
    expect(count.values['eligibleApproverIds']).toEqual(['u-authorised']);
    expect(hasReasonCode(decision, 'approval.role_not_authorised')).toBe(true);
  });

  it('allows once both approvers are role-authorised, via different authorised roles', () => {
    const decision = evaluate(
      request(TWO_PERSON_ACTION, officer(), [approval('u-1'), approval('u-2')], {
        'u-1': ['security.officer'],
        'u-2': ['site.commander'],
      }),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('ALLOW');
    expect(failedChecks(decision)).toEqual([]);
    expect(traceEntry(decision, 'APPROVAL_ROLE_AUTHORISED').values['authorisedApproverIds'])
      .toEqual(['u-1', 'u-2']);
  });

  it('counts an approver who holds several roles, only one of which carries authority', () => {
    const decision = evaluate(
      request(TWO_PERSON_ACTION, officer(), [approval('u-1'), approval('u-2')], {
        'u-1': ['security.officer'],
        'u-2': ['viewer', 'analyst', 'org.security.director'],
      }),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('ALLOW');
  });

  it('holds the action even when enough authorised approvers exist alongside an unauthorised one', () => {
    // Symmetric with CERT-O's treatment of a self-approval: a tainted approval set is reported
    // and held, not quietly filtered down to the subset that happens to work.
    const decision = evaluate(
      request(
        TWO_PERSON_ACTION,
        officer(),
        [approval('u-1'), approval('u-2'), approval('u-3')],
        {
          'u-1': ['security.officer'],
          'u-2': ['org.security.director'],
          'u-3': ['viewer'],
        },
      ),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('REQUIRE_TWO_PERSON');
    expect(failedChecks(decision)).toEqual(['APPROVAL_ROLE_AUTHORISED']);
    expect(traceEntry(decision, 'APPROVAL_DISTINCT_SUFFICIENT').outcome).toBe('PASS');
  });
});

describe('APPROVAL_ROLE_AUTHORISED: the claimed role is not evidence', () => {
  it('ignores the role stated on the approval and uses the resolved roles', () => {
    const decision = evaluate(
      request(TWO_PERSON_ACTION, officer(), [approval('u-1'), approval('u-2')], {
        // Both approvals claim security.officer; identity says otherwise for u-2.
        'u-1': ['security.officer'],
        'u-2': ['viewer'],
      }),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('REQUIRE_TWO_PERSON');
    expect(traceEntry(decision, 'APPROVAL_ROLE_AUTHORISED').values['unauthorisedApproverIds'])
      .toEqual(['u-2']);
  });

  it('counts nothing when the caller resolved no roles at all (fails closed)', () => {
    const decision = evaluate(
      {
        action: TWO_PERSON_ACTION,
        actor: officer(),
        target: target(),
        approvals: [approval('u-1'), approval('u-2')],
      },
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('REQUIRE_TWO_PERSON');
    const entry = traceEntry(decision, 'APPROVAL_ROLE_AUTHORISED');
    expect(entry.outcome).toBe('FAIL');
    expect(entry.values['approverRolesSupplied']).toBe(false);
    expect(entry.values['authorisedApproverIds']).toEqual([]);
    expect(traceEntry(decision, 'APPROVAL_DISTINCT_SUFFICIENT').values['distinctEligibleApprovers'])
      .toBe(0);
  });

  it('does not authorise an approver whose resolved roles are missing from the map', () => {
    const decision = evaluate(
      request(TWO_PERSON_ACTION, officer(), [approval('u-1'), approval('u-2')], {
        'u-1': ['security.officer'],
        // u-2 has no entry at all.
      }),
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('REQUIRE_TWO_PERSON');
    expect(traceEntry(decision, 'APPROVAL_ROLE_AUTHORISED').values['unauthorisedApproverIds'])
      .toEqual(['u-2']);
  });
});

describe('APPROVAL_ROLE_AUTHORISED: single-approval categories', () => {
  it('returns REQUIRE_APPROVAL when the only approver is not role-authorised', () => {
    const decision = evaluate(
      {
        action: ONE_PERSON_ACTION,
        actor: officer({ roles: ['analyst'], clearance: 2 }),
        target: target('SENSITIVE'),
        approvals: [approval('u-1', 'platform.admin')],
        approver_roles: { 'u-1': ['analyst'] },
      },
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('REQUIRE_APPROVAL');
    expect(failedChecks(decision)).toEqual([
      'APPROVAL_ROLE_AUTHORISED',
      'APPROVAL_DISTINCT_SUFFICIENT',
    ]);
  });

  it('allows when the single approver is role-authorised', () => {
    const decision = evaluate(
      {
        action: ONE_PERSON_ACTION,
        actor: officer({ roles: ['analyst'], clearance: 2 }),
        target: target('SENSITIVE'),
        approvals: [approval('u-1', 'platform.admin')],
        approver_roles: { 'u-1': ['platform.admin'] },
      },
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('ALLOW');
  });
});

describe('APPROVAL_ROLE_AUTHORISED: unresolved categories authorise nobody', () => {
  it('authorises no approver when the action does not resolve to a category', () => {
    const decision = evaluate(
      {
        action: 'incident.teleport',
        actor: officer(),
        target: target(),
        approvals: [approval('u-1')],
        approver_roles: { 'u-1': ['security.officer', 'org.security.director'] },
      },
      SENTINEL_BASELINE_POLICY,
    );

    expect(decision.decision).toBe('DENY');
    const entry = traceEntry(decision, 'APPROVAL_ROLE_AUTHORISED');
    expect(entry.outcome).toBe('FAIL');
    expect(entry.values['category']).toBeNull();
    expect(entry.values['categoryApprovalRoles']).toEqual([]);
  });
});

describe('baseline policy approval authority', () => {
  it('gives every approval-requiring category a non-empty, registered authority list', () => {
    for (const [id, category] of Object.entries(SENTINEL_BASELINE_POLICY.categories)) {
      if (category.approval === 'NONE') continue;
      expect(category.approval_roles.length, `${id} has no approval_roles`).toBeGreaterThan(0);
      for (const role of category.approval_roles) {
        expect(
          Object.prototype.hasOwnProperty.call(SENTINEL_BASELINE_POLICY.roles, role),
          `${id} names unregistered approval role ${role}`,
        ).toBe(true);
      }
    }
  });
});
