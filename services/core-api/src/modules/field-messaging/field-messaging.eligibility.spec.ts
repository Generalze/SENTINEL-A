import { describe, expect, it } from 'vitest';
import { isEligibleRecipient, isEligibleSender, isOperationalAssignment, OPERATIONAL_ASSIGNMENT_STATUSES } from './field-messaging.eligibility';
import { ACTION_MESSAGE_SEND } from './field-messaging.constants';

const SITE = 'site-a1';

function input(roles: Array<{ role: string; siteId: string | null }>, hasOperationalAssignment = false) {
  return { roles, siteId: SITE, hasOperationalAssignment };
}

describe('WP-18/C8-03 recipient eligibility', () => {
  it('rejects same-tenant membership on its own — a user with no qualifying role cannot be named', () => {
    expect(isEligibleRecipient(input([]))).toBe(false);
    // operator holds incident.view but no field.message.read.
    expect(isEligibleRecipient(input([{ role: 'operator', siteId: SITE }]))).toBe(false);
    expect(isEligibleRecipient(input([{ role: 'investigator', siteId: null }]))).toBe(false);
    expect(isEligibleRecipient(input([{ role: 'admin', siteId: null }]))).toBe(false);
  });

  it('accepts a command role on scope alone, site-scoped or organisation-wide', () => {
    expect(isEligibleRecipient(input([{ role: 'site.commander', siteId: SITE }]))).toBe(true);
    expect(isEligibleRecipient(input([{ role: 'site.commander', siteId: null }]))).toBe(true);
    expect(isEligibleRecipient(input([{ role: 'dispatcher', siteId: SITE }]))).toBe(true);
    expect(isEligibleRecipient(input([{ role: 'dispatcher', siteId: null }]))).toBe(true);
  });

  it('requires a field operative to hold an operational assignment for THIS incident', () => {
    const unassigned = input([{ role: 'field.operative', siteId: SITE }], false);
    const assigned = input([{ role: 'field.operative', siteId: SITE }], true);
    expect(isEligibleRecipient(unassigned)).toBe(false);
    expect(isEligibleRecipient(assigned)).toBe(true);
  });

  it('rejects a role that does not apply at the incident site', () => {
    expect(isEligibleRecipient({ roles: [{ role: 'site.commander', siteId: 'site-a2' }], siteId: SITE, hasOperationalAssignment: false })).toBe(false);
    expect(isEligibleRecipient({ roles: [{ role: 'field.operative', siteId: 'site-a2' }], siteId: SITE, hasOperationalAssignment: true })).toBe(false);
  });

  it('treats only pre-terminal assignment statuses as operational', () => {
    expect([...OPERATIONAL_ASSIGNMENT_STATUSES]).toEqual(['REQUESTED', 'ACCEPTED', 'IN_PROGRESS']);
    for (const live of ['REQUESTED', 'ACCEPTED', 'IN_PROGRESS']) expect(isOperationalAssignment(live)).toBe(true);
    // An operative whose involvement ended must not keep receiving traffic.
    for (const terminal of ['DECLINED', 'COMPLETED', 'CANCELLED', 'EXPIRED']) expect(isOperationalAssignment(terminal)).toBe(false);
  });

  it('an unknown role fails closed', () => {
    expect(isEligibleRecipient(input([{ role: 'not.a.real.role', siteId: null }], true))).toBe(false);
  });
});

describe('WP-18/C8-03 sender eligibility', () => {
  it('lets a command role send on scope alone', () => {
    expect(isEligibleSender(input([{ role: 'site.commander', siteId: SITE }]), ACTION_MESSAGE_SEND)).toBe(true);
    expect(isEligibleSender(input([{ role: 'dispatcher', siteId: null }]), ACTION_MESSAGE_SEND)).toBe(true);
  });

  it('requires a field operative to be assigned to the incident before they may send into it', () => {
    // The merge-blocking case: a site-scoped operative must not be able to
    // inject into every incident at their site merely because it exists there.
    expect(isEligibleSender(input([{ role: 'field.operative', siteId: SITE }], false), ACTION_MESSAGE_SEND)).toBe(false);
    expect(isEligibleSender(input([{ role: 'field.operative', siteId: SITE }], true), ACTION_MESSAGE_SEND)).toBe(true);
  });

  it('rejects a role without the send action however well scoped', () => {
    expect(isEligibleSender(input([{ role: 'operator', siteId: null }], true), ACTION_MESSAGE_SEND)).toBe(false);
    expect(isEligibleSender(input([{ role: 'investigator', siteId: SITE }], true), ACTION_MESSAGE_SEND)).toBe(false);
  });
});
