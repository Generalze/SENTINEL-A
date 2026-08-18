/**
 * §62 role registry — the source of truth for which action strings each
 * Milestone-1 role is allowed to perform. Versioned in code (not the DB)
 * so a change to what a role can do is a reviewable code diff.
 *
 * Action vocabulary (architecture §62.1 subjects; "incident.ack" is
 * deliberately not a thing — field acknowledgement is `field.acknowledge`):
 *
 * | Action             | Meaning                                          |
 * |--------------------|---------------------------------------------------|
 * | incident.view      | Read an incident's state/timeline                |
 * | incident.close     | Close/resolve an incident                         |
 * | field.acknowledge  | Acknowledge a field task/dispatch                 |
 * | field.assignment.manage | Create/cancel Field assignments              |
 * | field.assignment.act | Accept/start/complete own Field assignments       |
 * | field.state.write  | Submit audited Field operative state              |
 * | field.state.read   | Read audited Field operative state                |
 * | event.ingest       | Submit normalised events                          |
 * | evidence.read      | Read preserved evidence                           |
 * | ledger.read        | Read Decision Ledger entries                      |
 * | org.admin          | Create/administer organisations                   |
 * | site.admin         | Create/administer sites and zones                 |
 * | user.admin         | Create/administer users and role assignments      |
 * | presence.view      | Read Field operative presence/location            |
 * | field.message.send | Send an incident-scoped Field message              |
 * | field.message.read | Read a Field message you sent or were addressed in |
 * | field.message.acknowledge | Acknowledge a Field message addressed to you |
 * | incident.field-message.oversight.read | Read incident Field messages as command oversight |
 *
 * §62 role -> action table (source of truth for RBAC; site/clearance/
 * purpose are attribute-based constraints layered on top by AccessGuard,
 * not part of this table):
 *
 * | Role                | Actions                                                          |
 * |---------------------|-------------------------------------------------------------------|
 * | site.commander      | incident.view, incident.close, field.acknowledge, evidence.read  |
 * | operator            | incident.view, presence.view, event.ingest                       |
 * | dispatcher          | incident.view, presence.view                                     |
 * | field.operative     | field.acknowledge, incident.view                                 |
 * | investigator        | evidence.read, ledger.read, incident.view                        |
 * | evidence.custodian  | evidence.read                                                    |
 * | admin               | org.admin, site.admin, user.admin, incident.view                 |
 */
export const ACTIONS = [
  'incident.view',
  'incident.close',
  'incident.silent.approve',
  'field.acknowledge',
  'field.assignment.manage',
  'field.assignment.act',
  'field.state.write',
  'field.state.read',
  'field.message.send',
  'field.message.read',
  'field.message.acknowledge',
  // WP-18: command oversight of incident Field messages. Deliberately its
  // OWN action and NOT implied by incident.view — six roles hold
  // incident.view, so binding message content to it would disclose messages
  // to all six at once. Granted to site.commander only.
  'incident.field-message.oversight.read',
  'event.ingest',
  'event.read',
  'evidence.ingest',
  'evidence.read',
  'evidence.verify',
  'ledger.read',
  'ledger.verify',
  'hypothesis.read',
  'presence.view',
  'constitution.policy.read',
  'org.admin',
  'site.admin',
  'user.admin',
] as const;

export type Action = (typeof ACTIONS)[number];

export const ROLES = [
  'site.commander',
  'operator',
  'dispatcher',
  'field.operative',
  'investigator',
  'evidence.custodian',
  'admin',
] as const;

export type Role = (typeof ROLES)[number];

export const ROLE_ACTIONS: Readonly<Record<Role, readonly Action[]>> = {
  'site.commander': ['incident.view', 'incident.close', 'incident.silent.approve', 'field.acknowledge', 'field.assignment.manage', 'field.state.read', 'evidence.read', 'event.read', 'hypothesis.read', 'field.message.send', 'field.message.read', 'field.message.acknowledge', 'incident.field-message.oversight.read'],
  operator: ['incident.view', 'presence.view', 'field.state.read', 'event.ingest', 'event.read', 'hypothesis.read'],
  dispatcher: ['incident.view', 'presence.view', 'field.assignment.manage', 'field.state.read', 'event.read', 'hypothesis.read', 'field.message.send', 'field.message.read', 'field.message.acknowledge'],
  'field.operative': ['field.acknowledge', 'field.assignment.act', 'field.state.write', 'incident.view', 'field.message.send', 'field.message.read', 'field.message.acknowledge'],
  investigator: ['evidence.read', 'evidence.verify', 'ledger.read', 'ledger.verify', 'incident.view', 'event.read', 'hypothesis.read'],
  'evidence.custodian': ['evidence.read', 'evidence.ingest', 'evidence.verify'],
  admin: ['org.admin', 'site.admin', 'user.admin', 'incident.view', 'constitution.policy.read', 'ledger.verify'],
};

function isKnownRole(role: string): role is Role {
  return Object.prototype.hasOwnProperty.call(ROLE_ACTIONS, role);
}

/**
 * True when `role` (an arbitrary string, e.g. from the DB) grants `action`
 * per the §62 table above. `action` is a plain string (not the `Action`
 * union) so the one canonical guard can enforce any module's action string;
 * an unknown role or unknown action simply fails closed (returns false).
 */
export function roleHasAction(role: string, action: string): boolean {
  return isKnownRole(role) && (ROLE_ACTIONS[role] as readonly string[]).includes(action);
}
