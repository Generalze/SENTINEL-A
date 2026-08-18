import { roleHasAction } from '../identity/roles';
import { ACTION_MESSAGE_READ } from './field-messaging.constants';

/**
 * WP-18/C8-03: who may be *named* on an incident message, and who may send one.
 *
 * Same-tenant membership is deliberately NOT sufficient. Named membership is
 * the FINAL narrowing step of the section 62.1 chain
 * (organisation -> site -> incident -> assignment/purpose -> named recipient);
 * it cannot also be the mechanism by which a sender makes an otherwise
 * ineligible user authorised. Without this, any authorised sender could turn
 * any employee in the tenant into a recipient of need-to-know incident content.
 *
 * These are pure functions over already-loaded rows so the rules are testable
 * without a database and are stated in one place rather than spread across
 * query predicates.
 */

/** A Field assignment is operational while it can still be acted on. */
export const OPERATIONAL_ASSIGNMENT_STATUSES: readonly string[] = ['REQUESTED', 'ACCEPTED', 'IN_PROGRESS'];

/**
 * Terminal statuses deliberately do NOT confer eligibility: DECLINED,
 * COMPLETED, CANCELLED, EXPIRED. An operative whose involvement has ended must
 * not keep receiving incident traffic.
 */
export function isOperationalAssignment(status: string): boolean {
  return OPERATIONAL_ASSIGNMENT_STATUSES.includes(status);
}

export interface RoleAssignmentRow {
  role: string;
  siteId: string | null;
}

/** True when the role assignment applies at `siteId` — site-scoped to it, or organisation-wide. */
function appliesAtSite(assignment: RoleAssignmentRow, siteId: string): boolean {
  return assignment.siteId === null || assignment.siteId === siteId;
}

/** Roles whose scope alone qualifies them, without an incident assignment. */
const COMMAND_ROLES: readonly string[] = ['site.commander', 'dispatcher'];

export interface EligibilityInput {
  /** The user's role assignments, already loaded and already tenant-filtered. */
  roles: readonly RoleAssignmentRow[];
  /** The incident's site, derived server-side. */
  siteId: string;
  /** True when the user holds an operational Field assignment for this exact organisation + site + incident. */
  hasOperationalAssignment: boolean;
}

/**
 * Eligibility to be NAMED on a message for this incident.
 *
 * Note what this is not: being eligible to be named does not make somebody a
 * recipient of any particular message. Actual membership still decides who may
 * read a sent message — an eligible-but-unnamed operative still gets 404.
 */
export function isEligibleRecipient(input: EligibilityInput): boolean {
  const qualifying = input.roles.filter((assignment) => appliesAtSite(assignment, input.siteId) && roleHasAction(assignment.role, ACTION_MESSAGE_READ));
  if (qualifying.length === 0) return false;

  // A command role's scope is sufficient on its own.
  if (qualifying.some((assignment) => COMMAND_ROLES.includes(assignment.role))) return true;

  // Everyone else (today: field.operative) additionally needs an operational
  // assignment tying them to THIS incident.
  return input.hasOperationalAssignment;
}

/**
 * Eligibility to SEND into this incident. Same shape, evaluated against the
 * send action: a site-scoped operative must not be able to inject messages into
 * every incident at their site merely because the incident exists there.
 */
export function isEligibleSender(input: EligibilityInput, sendAction: string): boolean {
  const qualifying = input.roles.filter((assignment) => appliesAtSite(assignment, input.siteId) && roleHasAction(assignment.role, sendAction));
  if (qualifying.length === 0) return false;
  if (qualifying.some((assignment) => COMMAND_ROLES.includes(assignment.role))) return true;
  return input.hasOperationalAssignment;
}
