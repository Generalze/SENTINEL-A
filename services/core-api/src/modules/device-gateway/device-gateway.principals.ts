import type { DeviceActorAuthorityFacts, DeviceTrust } from '@sentinel/contracts';
import { buildPrincipal, type Principal } from '../../common/security/principal';
import { intersectSiteScope, type SiteScope } from '../identity/list-pagination';
import type { ActorAuthorityRow, DeviceGatewayRepository, GatewayTx } from './device-gateway.repository';
import type { DeviceGatewayPrincipalFacts } from './device-gateway.types';

/**
 * WP-25 — THE HUMAN HALF OF THE INVARIANT, REBUILT FROM SERVER STATE.
 *
 *     USER AUTHORITY + DEVICE IDENTITY + CURRENT DEVICE TRUST
 *       + SITE / CONTEXT AUTHORITY   must remain INDEPENDENT facts.
 *
 * The device half arrives as a signed possession proof. The HUMAN half has to
 * come from somewhere too, and this file is that somewhere. It matters that it
 * is a separate file with a separate argument, because the single easiest way
 * to break §62.1 is to let a device credential produce the user answer as a
 * side effect of authenticating the hardware.
 *
 * WHAT THE CONTEXT'S `actor_user_id` IS, AND IS NOT
 * -------------------------------------------------
 * It is a BINDING, NEVER A GRANT (C14-02) — the same words
 * `device-gateway.prisma` puts beside the column. Naming an actor gives that
 * actor nothing. What this file does with the name is go and ASK, right now,
 * from the user row and the role assignments:
 *
 *     does this person still exist in this tenant?
 *     do they still hold the capability THIS operation requires?
 *     does their CURRENT site entitlement still cover the site being acted at?
 *
 * All three are re-read on every request and inside the final effect
 * transaction, so a suspension, a role change or a site move lands on the NEXT
 * request rather than at the end of the context's life (D25-04).
 *
 * WHY A `Principal` IS BUILT HERE
 * -------------------------------
 * The domain services take the ONE canonical `Principal` and derive their own
 * site scope from it with `intersectSiteScope`, exactly as the HTTP routes do.
 * Building the same principal from the same two tables — via the same
 * `buildPrincipal`, whose `hasAction` is derived from the §62 role table — is
 * what makes the device path and the human path the same authorisation model
 * rather than two. No caller can assert an authority the seeded roles do not
 * grant, because nothing here constructs `hasAction` by hand.
 *
 * THIS IS NOT A SESSION. The principal is assembled from persisted rows for the
 * duration of one request; it is never issued, never returned, never cached and
 * never carries a credential of any kind.
 */

export interface ResolvedActorAuthority {
  /** The canonical principal the domain services are called with. */
  readonly principal: Principal;
  /** The CURRENT facts the frozen evaluator judges, for the required action. */
  readonly facts: DeviceActorAuthorityFacts;
  /** The site scope the domain service will filter on, derived exactly as a route derives it. */
  readonly siteScope: SiteScope;
}

/**
 * Resolves the current authority of `actorUserId` for `requiredAction`.
 *
 * `null` means the actor does not exist in this tenant. That is deliberately
 * the same answer a caller gets for a nonexistent user and for another
 * tenant's real user (D25-13), and the caller collapses it into the single
 * external refusal.
 */
export async function resolveActorAuthority(
  repository: DeviceGatewayRepository,
  input: { organisationId: string; actorUserId: string; requiredAction: string },
  tx?: GatewayTx,
): Promise<ResolvedActorAuthority | null> {
  const row = await repository.findActorAuthority(input.organisationId, input.actorUserId, tx);
  if (row === null) return null;
  return buildResolvedAuthority(repository, input.organisationId, row, input.requiredAction, tx);
}

async function buildResolvedAuthority(
  repository: DeviceGatewayRepository,
  organisationId: string,
  row: ActorAuthorityRow,
  requiredAction: string,
  tx?: GatewayTx,
): Promise<ResolvedActorAuthority> {
  const principal = buildPrincipal({
    user: { id: row.userId, clearance: row.clearance },
    organisation_id: row.organisationId,
    roles: row.roles.map((assignment) => ({ role: assignment.role, site_id: assignment.siteId })),
  });
  const siteScope = intersectSiteScope(principal, requiredAction);

  // An ORGANISATION-WIDE assignment is expanded into the concrete roster
  // rather than into "whatever site was asked for". The frozen evaluator's
  // check is `authorised_site_ids.includes(proof.site_id)`; feeding it the
  // requested site because the assignment happens to be org-wide would make
  // that check answer itself.
  const authorisedSiteIds = siteScope.orgWide ? await repository.listOrganisationSiteIds(organisationId, tx) : siteScope.siteIds;

  return {
    principal,
    siteScope,
    facts: {
      user_id: row.userId,
      authorised_site_ids: authorisedSiteIds,
      holds_required_capability: principal.hasAction(requiredAction),
    },
  };
}

/**
 * The actor as the ESTABLISHMENT ceremony needs to see them: which sites do
 * they currently hold ANY gateway-operable capability at?
 *
 * This is deliberately a different question from the per-operation one. A
 * context is issued for a SITE, not for an operation, so requiring one NAMED
 * action at issuance would be either the loosest of the three — letting a
 * dispatcher establish a context and then discover they cannot record state —
 * or the strictest, refusing an establishment to somebody who can legitimately
 * acknowledge messages. Issuing the context settles nothing either way: every
 * operation re-asks for its OWN action, through `resolveActorAuthority`, inside
 * the final effect transaction. Widening here therefore widens nothing.
 *
 * `null` for an actor who does not exist in this tenant — the same answer a
 * nonexistent user and another tenant's real user both get (D25-13).
 */
export interface ResolvedGatewayActor {
  readonly principal: Principal;
  /** The union of the sites where any gateway-operable capability is currently held. */
  readonly gatewaySiteIds: readonly string[];
}

export async function resolveGatewayActor(
  repository: DeviceGatewayRepository,
  input: { organisationId: string; actorUserId: string; actions: readonly string[] },
  tx?: GatewayTx,
): Promise<ResolvedGatewayActor | null> {
  const row = await repository.findActorAuthority(input.organisationId, input.actorUserId, tx);
  if (row === null) return null;
  const principal = buildPrincipal({
    user: { id: row.userId, clearance: row.clearance },
    organisation_id: row.organisationId,
    roles: row.roles.map((assignment) => ({ role: assignment.role, site_id: assignment.siteId })),
  });
  const scopes = input.actions.map((action) => intersectSiteScope(principal, action));
  const orgWide = scopes.some((scope) => scope.orgWide);
  const gatewaySiteIds = orgWide
    ? await repository.listOrganisationSiteIds(input.organisationId, tx)
    : [...new Set(scopes.flatMap((scope) => scope.siteIds))].sort();
  return { principal, gatewaySiteIds };
}

/**
 * WP-25/C17-01 — THE ONE PLACE THE FIVE FACTS ARE ASSEMBLED.
 *
 * It exists so that `sessionAuthenticated` has EXACTLY ONE source in this
 * module — the authenticated request principal, handed in by the caller — and
 * so that the two halves of each composite fact are written out where they can
 * be read side by side rather than collapsed at the call site:
 *
 *     deviceAuthenticated  = possession PROVEN  AND  credential INTACT
 *     siteAuthorityGranted = the HUMAN works this site  AND
 *                            the DEVICE is deployed at it
 *
 * There is deliberately no default and no optional parameter. Every one of
 * these has to be supplied by a caller that actually established it, because
 * the failure this whole batch corrects was a half of an invariant acquiring a
 * value nobody had to justify.
 */
export function composeDeviceGatewayPrincipalFacts(input: {
  /** THIS REQUEST carried the authenticated human principal. Never inferred. */
  readonly sessionAuthenticated: boolean;
  /** The live user/role re-read: the person exists AND holds the required capability. */
  readonly actorCurrentlyAuthorised: boolean;
  /** The P-256 verification over the canonical statement said yes. */
  readonly possessionVerified: boolean;
  /** Neither the device row nor the key row has withdrawn the credential. */
  readonly credentialIntact: boolean;
  /** Shield's CURRENT effective standing. Never the context's snapshot. */
  readonly deviceCurrentlyTrusted: DeviceTrust;
  /** The human currently works the site being acted at. */
  readonly humanSiteAuthorityGranted: boolean;
  /** The device is currently deployed at the site being acted at. */
  readonly deviceSiteAuthorityGranted: boolean;
}): DeviceGatewayPrincipalFacts {
  return {
    sessionAuthenticated: input.sessionAuthenticated,
    actorCurrentlyAuthorised: input.actorCurrentlyAuthorised,
    deviceAuthenticated: input.possessionVerified && input.credentialIntact,
    deviceCurrentlyTrusted: input.deviceCurrentlyTrusted,
    siteAuthorityGranted: input.humanSiteAuthorityGranted && input.deviceSiteAuthorityGranted,
  };
}

/**
 * C17-01: the human half, established by the TYPE rather than by a literal.
 *
 * `Principal` here is required and non-nullable. It is produced by
 * `requirePrincipal` behind the global session guard, so a caller that has one
 * has, by construction, presented an authenticated session on THIS request.
 *
 * The point of routing the fact through a function is that there is then
 * exactly one expression in the module that can yield `sessionAuthenticated:
 * true`, and it cannot be reached without a principal. The revision this
 * corrects derived the same half from "a matching user row was found in the
 * database", which proves CURRENT AUTHORISATION and says nothing about who
 * sent the request — the two facts this architecture exists to keep apart.
 *
 * It deliberately reads the principal rather than ignoring it: an
 * organisation-less or user-less principal is not a session this gateway will
 * accept, and saying so here keeps the check next to its justification.
 */
export function sessionAuthenticatedBy(principal: Principal): boolean {
  return principal.organisation_id.length > 0 && principal.user.id.length > 0;
}
