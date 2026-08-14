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
 * | event.ingest       | Submit normalised events                          |
 * | evidence.read      | Read preserved evidence                           |
 * | ledger.read        | Read Decision Ledger entries                      |
 * | org.admin          | Create/administer organisations                   |
 * | site.admin         | Create/administer sites and zones                 |
 * | user.admin         | Create/administer users and role assignments      |
 * | presence.view      | Read Field operative presence/location            |
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
  'field.acknowledge',
  'event.ingest',
  'evidence.read',
  'ledger.read',
  'org.admin',
  'site.admin',
  'user.admin',
  'presence.view',
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
  'site.commander': ['incident.view', 'incident.close', 'field.acknowledge', 'evidence.read'],
  operator: ['incident.view', 'presence.view', 'event.ingest'],
  dispatcher: ['incident.view', 'presence.view'],
  'field.operative': ['field.acknowledge', 'incident.view'],
  investigator: ['evidence.read', 'ledger.read', 'incident.view'],
  'evidence.custodian': ['evidence.read'],
  admin: ['org.admin', 'site.admin', 'user.admin', 'incident.view'],
};

function isKnownRole(role: string): role is Role {
  return Object.prototype.hasOwnProperty.call(ROLE_ACTIONS, role);
}

/** True when `role` (an arbitrary string, e.g. from the DB) grants `action` per the §62 table above. */
export function roleHasAction(role: string, action: Action): boolean {
  return isKnownRole(role) && ROLE_ACTIONS[role].includes(action);
}
