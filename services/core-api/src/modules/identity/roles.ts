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
 * | patrol.route.read  | Read patrol routes and their versioned checkpoints  |
 * | patrol.route.manage | Create patrol routes / publish new route versions  |
 * | patrol.run.read    | Read patrol runs (operatives: own runs only)        |
 * | patrol.run.manage  | Schedule/cancel patrol runs; command abandonment    |
 * | patrol.run.act     | Start/abandon own assigned patrol run               |
 * | patrol.checkpoint.verify | Verify a checkpoint on own assigned run       |
 * | whisper.signal.read | Read Whisper signal versions and lifecycle state    |
 * | whisper.signal.manage | Create/edit a DRAFT signal version; advance lifecycle |
 * | whisper.signal.approve | Approve activation of a tested signal version     |
 * | whisper.device-action.invoke | Submit an OWN device-action recognition     |
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
  // WP-19/C9-09: patrol capability is its own explicit vocabulary. None of it
  // is implied by incident.view or the Field assignment actions. The C9-05
  // matrix: site.commander reads and manages routes and runs; dispatcher may
  // schedule runs but NOT redefine patrol standards (that is the point of
  // ruling timing policy onto the route version); field.operative may only
  // act on and read their own run. COMPLETE is system-owned — no role holds
  // an action for it because no endpoint exists.
  'patrol.route.read',
  'patrol.route.manage',
  'patrol.run.read',
  'patrol.run.manage',
  'patrol.run.act',
  'patrol.checkpoint.verify',
  // WP-21B/B11-02: a MECHANICAL transcription of PROPOSED_WHISPER_ROLE_ACTIONS
  // in the frozen contract (packages/contracts/src/whisper.ts, W21-12), which
  // stated the matrix as data precisely so this change would be a reviewable
  // copy rather than a fresh judgement call.
  //
  // Four SEPARATE capabilities, because reading a signal roster, editing a
  // configuration, approving an activation and firing the thing are four
  // different powers.
  //
  // NO EXISTING ACTION IMPLIES ANY OF THEM. Not incident.view (six roles hold
  // it), not incident.silent.approve, not field.acknowledge, and not admin's
  // org/site/user.admin — platform administration is not authority over a
  // silent duress channel. The WP-18 reasoning for
  // incident.field-message.oversight.read applies with more force here: an
  // authority that can raise a silent dispatch must be granted deliberately,
  // never inherited as a side effect of holding something else.
  'whisper.signal.read',
  'whisper.signal.manage',
  'whisper.signal.approve',
  'whisper.device-action.invoke',
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
  // WP-21B: site.commander holds manage AND approve because W21-12's
  // separation is between distinct PEOPLE, not distinct roles — enforced by
  // whisperActivationApproverIsDistinct, which refuses a creator approving
  // their own version. Splitting the two across roles would have been a
  // different (and unmandated) org design.
  'site.commander': ['incident.view', 'incident.close', 'incident.silent.approve', 'field.acknowledge', 'field.assignment.manage', 'field.state.read', 'evidence.read', 'event.read', 'hypothesis.read', 'field.message.send', 'field.message.read', 'field.message.acknowledge', 'incident.field-message.oversight.read', 'patrol.route.read', 'patrol.route.manage', 'patrol.run.read', 'patrol.run.manage', 'whisper.signal.read', 'whisper.signal.manage', 'whisper.signal.approve'],
  operator: ['incident.view', 'presence.view', 'field.state.read', 'event.ingest', 'event.read', 'hypothesis.read'],
  dispatcher: ['incident.view', 'presence.view', 'field.assignment.manage', 'field.state.read', 'event.read', 'hypothesis.read', 'field.message.send', 'field.message.read', 'field.message.acknowledge', 'patrol.route.read', 'patrol.run.read', 'patrol.run.manage'],
  // WP-21B: whisper.device-action.invoke is OWN-ONLY and is not a grant to
  // fire anything. Every runtime entitlement check in
  // evaluateWhisperRuntimeEligibility still applies on top of it (W21-04): the
  // actor must be named on the exact active version AND hold current authority
  // at that moment, on a TRUSTED device, within scope and freshness.
  'field.operative': ['field.acknowledge', 'field.assignment.act', 'field.state.write', 'incident.view', 'field.message.send', 'field.message.read', 'field.message.acknowledge', 'patrol.run.read', 'patrol.run.act', 'patrol.checkpoint.verify', 'whisper.device-action.invoke'],
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
