import { describe, expect, it } from 'vitest';
import { assignmentAllowsExecution, assignmentAllowsScheduling } from './patrol.eligibility';

/**
 * WP-19/C9-05: the two assignment-eligibility gates, stated as a truth table so
 * a future edit that widens either set is a visible diff here.
 */
describe('patrol incident-assignment eligibility (C9-05)', () => {
  it('scheduling accepts any still-actionable assignment', () => {
    expect(assignmentAllowsScheduling('REQUESTED')).toBe(true);
    expect(assignmentAllowsScheduling('ACCEPTED')).toBe(true);
    expect(assignmentAllowsScheduling('IN_PROGRESS')).toBe(true);
  });

  it('scheduling refuses every terminal assignment — ended involvement confers nothing', () => {
    for (const status of ['DECLINED', 'COMPLETED', 'CANCELLED', 'EXPIRED']) {
      expect(assignmentAllowsScheduling(status)).toBe(false);
    }
  });

  it('execution additionally requires the operative to have taken the duty on', () => {
    expect(assignmentAllowsExecution('ACCEPTED')).toBe(true);
    expect(assignmentAllowsExecution('IN_PROGRESS')).toBe(true);
    // Intended is not accepted: a REQUESTED assignment cannot start or verify.
    expect(assignmentAllowsExecution('REQUESTED')).toBe(false);
    for (const status of ['DECLINED', 'COMPLETED', 'CANCELLED', 'EXPIRED']) {
      expect(assignmentAllowsExecution(status)).toBe(false);
    }
  });

  it('an unknown status fails closed on both gates', () => {
    expect(assignmentAllowsScheduling('SOMETHING_NEW')).toBe(false);
    expect(assignmentAllowsExecution('SOMETHING_NEW')).toBe(false);
  });
});
