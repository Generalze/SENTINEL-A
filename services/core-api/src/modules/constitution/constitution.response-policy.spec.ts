import { describe, expect, it } from 'vitest';
import { evaluate, type Approval, type ConstitutionRequest } from './constitution.engine';
import { SENTINEL_BASELINE_POLICY } from './constitution.policy';

const baseRequest: ConstitutionRequest = {
  action: 'response.dispatch.standard',
  actor: {
    userId: 'system:incident-response',
    roles: ['system.response'],
    organisationId: 'org-a',
    clearance: 5,
    purpose: 'incident-response-dispatch',
    deviceTrust: 'TRUSTED',
  },
  target: {
    organisationId: 'org-a',
    siteId: 'site-a',
    classification: 'SENSITIVE',
    classificationLevel: 2,
  },
};

function approval(userId: string): Approval {
  return { userId, role: 'site.commander', at: '2026-08-16T12:00:00.000Z' };
}

describe('baseline response-dispatch policy', () => {
  it('allows a standard dispatch by the server-only response actor', () => {
    const decision = evaluate(baseRequest, SENTINEL_BASELINE_POLICY);
    expect(decision.decision).toBe('ALLOW');
    expect(decision.trace.every((entry) => entry.outcome !== 'FAIL')).toBe(true);
  });

  it('requires two distinct site commanders for silent dispatch', () => {
    const silent = { ...baseRequest, action: 'response.dispatch.silent' };
    expect(evaluate(silent, SENTINEL_BASELINE_POLICY).decision).toBe('REQUIRE_TWO_PERSON');

    const one = approval('commander-1');
    expect(
      evaluate(
        { ...silent, approvals: [one], approver_roles: { 'commander-1': ['site.commander'] } },
        SENTINEL_BASELINE_POLICY,
      ).decision,
    ).toBe('REQUIRE_TWO_PERSON');

    const two = approval('commander-2');
    expect(
      evaluate(
        {
          ...silent,
          approvals: [one, two],
          approver_roles: {
            'commander-1': ['site.commander'],
            'commander-2': ['site.commander'],
          },
        },
        SENTINEL_BASELINE_POLICY,
      ).decision,
    ).toBe('ALLOW');
  });

  it('rejects a classification label/level mismatch', () => {
    const decision = evaluate(
      { ...baseRequest, target: { ...baseRequest.target, classificationLevel: 3 } },
      SENTINEL_BASELINE_POLICY,
    );
    expect(decision.decision).toBe('DENY');
    expect(decision.trace).toContainEqual(expect.objectContaining({ check: 'CLASSIFICATION_CONSISTENT', outcome: 'FAIL' }));
  });
});
