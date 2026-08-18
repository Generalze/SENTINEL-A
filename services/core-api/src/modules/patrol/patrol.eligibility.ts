/**
 * WP-19/C9-05: incident-assignment eligibility for incident-linked patrols.
 *
 * Pure functions over already-loaded status strings, following the WP-18
 * eligibility precedent: the rules are stated once, testable without a
 * database, and never spread across query predicates.
 */

/**
 * SCHEDULING an incident-linked patrol requires the operative to hold a Field
 * assignment for that exact organisation + site + incident that can still be
 * acted on. Terminal assignments (DECLINED, COMPLETED, CANCELLED, EXPIRED)
 * confer nothing: an operative whose involvement ended must not be scheduled
 * back onto the incident through patrol.
 */
export const SCHEDULING_ASSIGNMENT_STATUSES: readonly string[] = ['REQUESTED', 'ACCEPTED', 'IN_PROGRESS'];

/**
 * STARTING or VERIFYING additionally requires the assignment to be ACCEPTED or
 * IN_PROGRESS (C9-05). A merely-REQUESTED assignment proves the incident chain
 * intended the operative, not that the operative took the duty on.
 */
export const ACTIVE_ASSIGNMENT_STATUSES: readonly string[] = ['ACCEPTED', 'IN_PROGRESS'];

export function assignmentAllowsScheduling(status: string): boolean {
  return SCHEDULING_ASSIGNMENT_STATUSES.includes(status);
}

export function assignmentAllowsExecution(status: string): boolean {
  return ACTIVE_ASSIGNMENT_STATUSES.includes(status);
}
