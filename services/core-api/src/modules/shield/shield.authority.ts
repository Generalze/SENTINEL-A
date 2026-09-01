import type { Principal } from '../../common/security/principal';
import { intersectSiteScope } from '../identity/list-pagination';
import type { ShieldRefusal } from './shield.types';

/**
 * WP-24/D24-02 — the authority check every Shield service performs, in ONE place.
 *
 * It is the `field-offline` executor's discipline exactly: authority comes
 * from `Principal.hasAction`, which is derived from the §62 role table in
 * `identity/roles.ts` and from nothing else. No service in this module has a
 * role name in it, no service compares against `admin`, and no service can
 * assert an authority the seeded roles do not grant — because `buildPrincipal`
 * builds `hasAction` from the table itself.
 *
 * THREE FACTS ARE CHECKED, AND THEY ARE INDEPENDENT (§62.1)
 * --------------------------------------------------------
 *  1. the caller's organisation IS the organisation being acted on;
 *  2. some role assignment grants the action (RBAC, the §62 table);
 *  3. the site being acted on lies inside the scope those GRANTING
 *     assignments cover (ABAC, layered on top exactly as it is for every
 *     other action in the platform).
 *
 * Fact 3 is computed from `intersectSiteScope`, so a site-scoped
 * `site.commander` cannot reach a device at a site they do not hold. An
 * org-wide assignment (`site_id: null`) is unrestricted, which is the same
 * semantics every other module gives it.
 *
 * WHAT IS DELIBERATELY NOT HERE
 * -----------------------------
 * There is no "the intended user may act on their own device" branch, and
 * there never will be: D24-02 rules that a Field operative's participation is
 * not device-management authority, and being the intended or current user of a
 * device grants nothing in the matrix. There is also no `admin` fallback —
 * platform administration is not authority over hardware trust.
 *
 * An INTERNAL MACHINE LOOKUP is not modelled here at all. When WP-25's gateway
 * resolves a registry record to authenticate an incoming device, that is a
 * service call, not a `device.registry.read` performed by a person, and
 * `DeviceRegistryService` exposes it as a separate method that takes no
 * principal rather than as a human read with a synthetic one.
 */

/** `null` means authorised. Anything else is the refusal to return verbatim. */
export function checkDeviceAuthority(
  principal: Principal,
  action: string,
  organisationId: string,
  siteId: string | null,
): ShieldRefusal | null {
  // Tenant first. A cross-organisation call is refused before its roles are
  // even consulted, so a role held in tenant A can never be weighed against a
  // resource in tenant B.
  if (principal.organisation_id !== organisationId) return 'NOT_AUTHORISED';
  if (!principal.hasAction(action)) return 'NOT_AUTHORISED';
  if (siteId === null) return null;

  const scope = intersectSiteScope(principal, action);
  if (scope.orgWide) return null;
  return scope.siteIds.includes(siteId) ? null : 'SITE_NOT_IN_SCOPE';
}

/**
 * The sites a reader's `action` grants cover, or `null` for org-wide.
 *
 * `null` and `[]` are deliberately different answers: org-wide means "do not
 * narrow", while an empty list means "this principal holds the action at no
 * site" and must return nothing rather than everything. Collapsing the two is
 * the classic way a scoped read becomes a tenant-wide one.
 */
export function readableSiteIds(principal: Principal, action: string): string[] | null {
  const scope = intersectSiteScope(principal, action);
  return scope.orgWide ? null : scope.siteIds;
}
