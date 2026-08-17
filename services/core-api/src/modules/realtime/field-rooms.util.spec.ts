import { describe, expect, it } from 'vitest';
import { fieldRoomsFor } from './field-rooms.util';
import { fieldOrgWideRoom, fieldSiteRoom } from './realtime.constants';
import type { RealtimePrincipal, RealtimeRoleAssignment } from './realtime.types';

function principal(roles: RealtimeRoleAssignment[], organisationId = 'org-1'): RealtimePrincipal {
  return { user_id: 'user-1', organisation_id: organisationId, roles };
}

describe('fieldRoomsFor (WP-17/D1)', () => {
  it('puts a site-scoped operative in exactly their own site room', () => {
    const rooms = fieldRoomsFor(principal([{ role: 'field.operative', site_id: 'site-a' }]));
    expect(rooms).toEqual([fieldSiteRoom('org-1', 'site-a')]);
  });

  it('puts an organisation-wide authority in the org-wide Field room and no site rooms', () => {
    const rooms = fieldRoomsFor(principal([{ role: 'dispatcher', site_id: null }]));
    expect(rooms).toEqual([fieldOrgWideRoom('org-1')]);
  });

  it('prefers the org-wide room when a principal holds both org-wide and site-scoped grants, so no event is delivered twice', () => {
    const rooms = fieldRoomsFor(
      principal([
        { role: 'dispatcher', site_id: null },
        { role: 'site.commander', site_id: 'site-a' },
      ]),
    );
    expect(rooms).toEqual([fieldOrgWideRoom('org-1')]);
  });

  it('joins one room per granted site, de-duplicated across roles', () => {
    const rooms = fieldRoomsFor(
      principal([
        { role: 'field.operative', site_id: 'site-a' },
        { role: 'site.commander', site_id: 'site-a' },
        { role: 'dispatcher', site_id: 'site-b' },
      ]),
    );
    expect(rooms).toEqual([fieldSiteRoom('org-1', 'site-a'), fieldSiteRoom('org-1', 'site-b')]);
  });

  it('gives no Field room to a principal whose roles grant no Field visibility action', () => {
    expect(fieldRoomsFor(principal([{ role: 'evidence.custodian', site_id: 'site-a' }]))).toEqual([]);
    expect(fieldRoomsFor(principal([{ role: 'investigator', site_id: null }]))).toEqual([]);
  });

  it('gives no Field room to a principal with no roles at all, and fails closed on an unknown role', () => {
    expect(fieldRoomsFor(principal([]))).toEqual([]);
    expect(fieldRoomsFor(principal([{ role: 'not.a.real.role', site_id: null }]))).toEqual([]);
  });

  it('only ever derives rooms under the principal own organisation', () => {
    const rooms = fieldRoomsFor(principal([{ role: 'field.operative', site_id: 'site-a' }], 'org-2'));
    expect(rooms).toEqual([fieldSiteRoom('org-2', 'site-a')]);
    expect(rooms[0]).toContain('org-2');
    expect(rooms[0]).not.toContain('org-1');
  });
});
