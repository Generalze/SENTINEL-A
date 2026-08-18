import { roleHasAction } from '../identity/roles';
import { fieldOrgWideRoom, fieldSiteRoom } from './realtime.constants';
import type { RealtimePrincipal } from './realtime.types';

/**
 * WP-17/D1: which section 62 actions make Field traffic visible to a principal.
 *
 * Holding any one of these is what puts a socket in a Field room at all — a
 * principal whose roles grant none of them (an evidence custodian, say) is in
 * no Field room and therefore receives no Field event, rather than receiving
 * one and being expected to ignore it.
 */
export const FIELD_VISIBILITY_ACTIONS: readonly string[] = ['field.assignment.manage', 'field.assignment.act', 'field.state.read'];

/**
 * The Field rooms a socket may join, derived entirely from the principal's own
 * role assignments — never from anything the client sends.
 *
 * Mirrors identity's `intersectSiteScope`: an organisation-wide granting
 * assignment (`site_id === null`) means the whole tenant is in scope, so the
 * socket joins the single org-wide Field room and no site rooms. Otherwise it
 * joins one room per granted site. The two branches are mutually exclusive, so
 * a Field event emitted to both the org-wide room and one site room has a
 * single eligible fanout path to any given socket — it cannot be delivered
 * twice by room membership. This is a fanout property, not a transport
 * delivery guarantee (see `realtime.constants.ts`); REST remains
 * authoritative.
 *
 * This module imports identity's role table directly rather than re-deriving
 * it: WP-12's lane rule that kept `realtime` free of `modules/identity` was a
 * concurrency measure for that wave, and duplicating the section 62 table
 * would let realtime's view of "who may see Field traffic" drift away from the
 * guard's.
 *
 * Known limitation (recorded in docs/execution/security/WAVE-7-FINDINGS.md):
 * this runs once, at handshake time. A role assignment revoked while a socket
 * is connected does not move that socket out of its Field rooms until it
 * reconnects — the same property the organisation room already has. Immediate
 * revocation is a session-invalidation concern for the production IdP work.
 */
export function fieldRoomsFor(principal: RealtimePrincipal): string[] {
  const granting = principal.roles.filter((assignment) => FIELD_VISIBILITY_ACTIONS.some((action) => roleHasAction(assignment.role, action)));
  if (granting.length === 0) {
    return [];
  }
  if (granting.some((assignment) => assignment.site_id === null)) {
    return [fieldOrgWideRoom(principal.organisation_id)];
  }
  const siteIds = [...new Set(granting.map((assignment) => assignment.site_id).filter((siteId): siteId is string => siteId !== null))];
  return siteIds.map((siteId) => fieldSiteRoom(principal.organisation_id, siteId));
}
