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
 * ---------------------------------------------------------------------------
 * C16-06 — A DEVICE IS NOT A SITE-SHAPED OBJECT, AND `some()` WAS THE BUG
 * ---------------------------------------------------------------------------
 *
 * A device can be associated with SEVERAL sites. The original checks treated
 * that list the way one treats a single-site resource, with two consequences:
 *
 *   READ LEAKED. A reader holding site A could read a device associated with
 *   A and B, and was then handed the device's ENTIRE active site list —
 *   including B. Holding one site became a way to enumerate the others a
 *   device is deployed at.
 *
 *   MUTATION OVER-REACHED. Key rotation, trust change, revocation and
 *   disposition are GLOBAL PHYSICAL-DEVICE mutations: there is one credential,
 *   one trust value and one device row, and rotating the key at site A rotates
 *   it at site B too. Requiring authority over ANY ONE associated site let a
 *   commander scoped to A silently change the credential a commander at B
 *   depends on. Authority over part of a thing is not authority over the thing.
 *
 * And the zero-site case was worse than either: `siteIds.length === 0` returned
 * "authorised" outright, so a device with no active association could be
 * rotated or revoked by anyone holding the action ANYWHERE in the tenant. An
 * unscoped object is not a public object; it is one only organisation-wide
 * authority can reach.
 *
 * THE THREE ANSWERS THIS FILE NOW GIVES
 * -------------------------------------
 *   `checkDeviceAuthority`             one named site, unchanged (D24-02).
 *   `projectReadableDeviceSites`       what a READER may be told.
 *   `checkGlobalDeviceMutationAuthority`  whether a COMMANDER may change the
 *                                      whole physical device.
 *
 * GENUINE ORGANISATION-WIDE AUTHORITY means `intersectSiteScope(...).orgWide` —
 * a role assignment with a NULL site id. It is deliberately NOT "the caller
 * holds this action at some site", which is the conflation that produced both
 * defects above.
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

/**
 * C16-06 — GENUINE ORGANISATION-WIDE AUTHORITY.
 *
 * A role assignment whose `site_id` is NULL for this action. Not "holds the
 * action somewhere", which is what every site-scoped commander also satisfies.
 */
export function hasOrganisationWideDeviceAuthority(principal: Principal, action: string, organisationId: string): boolean {
  if (principal.organisation_id !== organisationId) return false;
  if (!principal.hasAction(action)) return false;
  return intersectSiteScope(principal, action).orgWide;
}

/**
 * C16-06 — WHAT A SITE-SCOPED READER MAY BE TOLD ABOUT A DEVICE'S SITES.
 *
 * Returns the projected site list, or `null` when the reader may not see the
 * device at all — which the caller reports as the SAME refusal an invented
 * device id gets, because "you may not see that device" and "there is no such
 * device" must be indistinguishable from outside.
 *
 * Only genuine organisation-wide authority receives the full list. A reader
 * holding sites A and C, looking at a device associated with A, B and C, is
 * told "A and C": true, complete with respect to what they are entitled to,
 * and silent about B. A reader holding none of the device's sites is told
 * nothing at all.
 *
 * A device with NO active site association is visible only to organisation-wide
 * authority: there is no site through which a scoped reader could have earned
 * a view of it.
 */
export function projectReadableDeviceSites(
  principal: Principal,
  action: string,
  organisationId: string,
  deviceSiteIds: readonly string[],
): string[] | null {
  if (checkDeviceAuthority(principal, action, organisationId, null) !== null) return null;
  if (hasOrganisationWideDeviceAuthority(principal, action, organisationId)) return [...deviceSiteIds];

  const scope = intersectSiteScope(principal, action);
  const visible = deviceSiteIds.filter((siteId) => scope.siteIds.includes(siteId));
  return visible.length === 0 ? null : visible;
}

/**
 * C16-06 — AUTHORITY TO PERFORM A GLOBAL PHYSICAL-DEVICE MUTATION.
 *
 * Key rotation, trust change, revocation and disposition each change ONE row
 * that every site the device serves depends on. So the requirement is not "a
 * site I hold is among them" but the whole thing:
 *
 *   * genuine organisation-wide authority for the action; OR
 *   * authority covering EVERY active associated site, and there must be at
 *     least one — a device associated with nothing is reachable only
 *     organisation-wide.
 *
 * The refusal is always `DEVICE_NOT_FOUND`, matching the isolation rule the
 * read side follows: an unauthorised commander must not learn that the device
 * exists, nor that it is deployed at a site they cannot see.
 */
export function checkGlobalDeviceMutationAuthority(
  principal: Principal,
  action: string,
  organisationId: string,
  deviceSiteIds: readonly string[],
): 'DEVICE_NOT_FOUND' | null {
  if (checkDeviceAuthority(principal, action, organisationId, null) !== null) return 'DEVICE_NOT_FOUND';
  if (hasOrganisationWideDeviceAuthority(principal, action, organisationId)) return null;

  // A site-scoped commander and a device bound to no site: there is no site
  // through which the authority could reach it.
  if (deviceSiteIds.length === 0) return 'DEVICE_NOT_FOUND';

  const scope = intersectSiteScope(principal, action);
  const coversEverySite = deviceSiteIds.every((siteId) => scope.siteIds.includes(siteId));
  return coversEverySite ? null : 'DEVICE_NOT_FOUND';
}
