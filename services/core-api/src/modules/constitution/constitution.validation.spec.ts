/**
 * SENTINEL — policy load-time validation (WP-06 mandatory addition 2).
 *
 * One test per rule, plus the shape gate and the "boot fails" assertion that
 * `assertValidPolicy` throws rather than returning a degraded policy.
 */

import { describe, expect, it } from 'vitest';

import type { Policy } from './constitution.engine';
import { PolicyShapeError, SENTINEL_BASELINE_POLICY, parsePolicy, policyBody } from './constitution.policy';
import {
  PolicyValidationError,
  assertValidPolicy,
  validatePolicy,
  type PolicyValidationCode,
} from './constitution.validation';

/** A deep, mutable copy of the baseline — the baseline itself is frozen. */
function baselineCopy(): Policy {
  return JSON.parse(JSON.stringify(SENTINEL_BASELINE_POLICY)) as Policy;
}

function codes(policy: Policy): PolicyValidationCode[] {
  return validatePolicy(policy).map((issue) => issue.code);
}

describe('validatePolicy: the certified baseline', () => {
  it('accepts the baseline policy with no issues', () => {
    expect(validatePolicy(SENTINEL_BASELINE_POLICY)).toEqual([]);
    expect(assertValidPolicy(SENTINEL_BASELINE_POLICY)).toBe(SENTINEL_BASELINE_POLICY);
  });
});

describe('validatePolicy: rule 1 — dangling category references', () => {
  it('rejects an action mapped to a category the policy does not define', () => {
    const policy = baselineCopy();
    (policy.actions as Record<string, string>)['incident.view'] = 'category_that_does_not_exist';

    expect(codes(policy)).toContain('policy.category_dangling');
    expect(validatePolicy(policy)[0]?.message).toContain('incident.view');
  });
});

describe('validatePolicy: rule 2 — role grants of unregistered actions', () => {
  it('rejects a role granting an action that is not registered', () => {
    const policy = baselineCopy();
    (policy.roles as Record<string, string[]>)['analyst'] = ['incident.view', 'incident.teleport'];

    expect(codes(policy)).toContain('policy.action_unregistered');
    expect(validatePolicy(policy).some((i) => i.message.includes('incident.teleport'))).toBe(true);
  });
});

describe('validatePolicy: rule 3 — prohibited actions in role grants', () => {
  it('rejects a prohibited action appearing in any role grant', () => {
    const policy = baselineCopy();
    (policy.roles as Record<string, string[]>)['constitution.steward'] = [
      'incident.view',
      'constitution.rules.alter.core',
      'constitution.evaluator.bypass',
    ];

    expect(codes(policy)).toContain('policy.prohibited_action_granted');
  });

  it('rejects it even though the evaluator would have denied the action anyway', () => {
    // The evaluator is safe (ACTION_NOT_PROHIBITED outranks role grants) — this rule exists so
    // a policy that *looks* like it authorises a prohibition never reaches production at all.
    const policy = baselineCopy();
    (policy.roles as Record<string, string[]>)['viewer'] = ['incident.view', 'audit.ledger.delete'];

    expect(codes(policy)).toEqual(['policy.prohibited_action_granted']);
  });
});

describe('validatePolicy: rule 4 — approval authority on approval-requiring categories', () => {
  it('rejects an empty approval_roles on a TWO_PERSON category', () => {
    const policy = baselineCopy();
    policy.categories['exceptional_tracking_powers'] = {
      approval: 'TWO_PERSON',
      description: '§58.2 Use of exceptional tracking powers.',
      approval_roles: [],
    };

    expect(codes(policy)).toContain('policy.approval_roles_empty');
  });

  it('rejects an empty approval_roles on a ONE category', () => {
    const policy = baselineCopy();
    policy.categories['sensitive_data_export'] = {
      approval: 'ONE',
      description: 'Export of sensitive data outside the platform.',
      approval_roles: [],
    };

    expect(codes(policy)).toContain('policy.approval_roles_empty');
  });

  it('accepts an empty approval_roles on a NONE category', () => {
    // routine_read/routine_write already declare `[]` in the baseline.
    expect(SENTINEL_BASELINE_POLICY.categories['routine_read']?.approval_roles).toEqual([]);
    expect(validatePolicy(SENTINEL_BASELINE_POLICY)).toEqual([]);
  });
});

describe('validatePolicy: rule 5 — approval authority must name registered roles', () => {
  it('rejects a category naming an approval role the policy does not define', () => {
    const policy = baselineCopy();
    policy.categories['exceptional_tracking_powers'] = {
      approval: 'TWO_PERSON',
      description: '§58.2 Use of exceptional tracking powers.',
      approval_roles: ['role.that.does.not.exist'],
    };

    expect(codes(policy)).toContain('policy.approval_role_unregistered');
  });
});

describe('validatePolicy: reporting', () => {
  it('reports every issue rather than stopping at the first', () => {
    const policy = baselineCopy();
    (policy.actions as Record<string, string>)['incident.view'] = 'nope';
    (policy.roles as Record<string, string[]>)['viewer'] = ['audit.ledger.delete', 'no.such.action'];
    policy.categories['alter_core_constitution_rules'] = {
      approval: 'TWO_PERSON',
      description: '§58.2 Alteration of core Constitution rules.',
      approval_roles: [],
    };

    expect(new Set(codes(policy))).toEqual(
      new Set([
        'policy.category_dangling',
        'policy.action_unregistered',
        'policy.prohibited_action_granted',
        'policy.approval_roles_empty',
      ]),
    );
  });
});

describe('assertValidPolicy: the boot gate', () => {
  it('throws PolicyValidationError, carrying every issue', () => {
    const policy = baselineCopy();
    policy.categories['exceptional_tracking_powers'] = {
      approval: 'TWO_PERSON',
      description: '§58.2 Use of exceptional tracking powers.',
      approval_roles: [],
    };

    expect(() => assertValidPolicy(policy)).toThrow(PolicyValidationError);
    try {
      assertValidPolicy(policy);
      expect.unreachable('assertValidPolicy must throw');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(PolicyValidationError);
      const validationError = error as PolicyValidationError;
      expect(validationError.policyVersion).toBe(policy.version);
      expect(validationError.issues.length).toBeGreaterThan(0);
      expect(validationError.message).toContain('policy.approval_roles_empty');
    }
  });
});

describe('parsePolicy: the shape gate', () => {
  it('round-trips the baseline through its stored body', () => {
    const parsed = parsePolicy(policyBody(SENTINEL_BASELINE_POLICY));
    expect(parsed).toEqual(SENTINEL_BASELINE_POLICY);
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.categories)).toBe(true);
  });

  it('rejects a body whose category is missing approval_roles', () => {
    const body = policyBody(SENTINEL_BASELINE_POLICY);
    const categories = body['categories'] as Record<string, Record<string, unknown>>;
    delete categories['routine_read']?.['approval_roles'];

    expect(() => parsePolicy(body)).toThrow(PolicyShapeError);
  });

  it('rejects a body with an unknown approval requirement', () => {
    const body = policyBody(SENTINEL_BASELINE_POLICY);
    const categories = body['categories'] as Record<string, Record<string, unknown>>;
    const routineRead = categories['routine_read'];
    if (routineRead !== undefined) routineRead['approval'] = 'MAYBE';

    expect(() => parsePolicy(body)).toThrow(PolicyShapeError);
  });

  it('rejects a body that is not an object at all', () => {
    expect(() => parsePolicy('not a policy')).toThrow(PolicyShapeError);
    expect(() => parsePolicy(null)).toThrow(PolicyShapeError);
  });

  it('names the offending path in the error', () => {
    const body = policyBody(SENTINEL_BASELINE_POLICY);
    delete body['version'];

    try {
      parsePolicy(body);
      expect.unreachable('parsePolicy must throw');
    } catch (error: unknown) {
      expect(error).toBeInstanceOf(PolicyShapeError);
      expect((error as PolicyShapeError).issues.join(' ')).toContain('version');
    }
  });
});
