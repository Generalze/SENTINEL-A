import { UnauthorizedException } from '@nestjs/common';
import type { RequestWithTraceId } from '../http-types';
import { roleHasAction, type Action } from '../../modules/identity/roles';

/**
 * ============================================================================
 * THE canonical Principal (WP-14 — fixes H1/H2/L1).
 *
 * Before WP-14 every HTTP module (events, evidence, ledger, fusion, realtime,
 * constitution) declared its OWN local `principal` shape and its OWN
 * `@RequiresAction` decorator with a DIFFERENT metadata key, none of which the
 * globally-wired identity guards read — so the guards were inert on those
 * routes and the principal shapes were mutually incompatible. This is the ONE
 * Principal type every module now shares. It lives in `common/security`
 * (owned by no feature module) and is populated by the global DevAuthGuard and
 * read by the global AccessGuard.
 * ============================================================================
 */

/** One §62 role assignment for a user, optionally scoped to a single site. */
export interface PrincipalRoleAssignment {
  role: string;
  site_id: string | null;
}

/**
 * The authenticated caller, attached to `request.principal` by the global
 * DevAuthGuard and consumed by the global AccessGuard and every controller.
 */
export interface Principal {
  /** The minimal user facts the access layer needs. */
  user: { id: string; clearance: number };
  organisation_id: string;
  roles: PrincipalRoleAssignment[];
  /** True when any of the caller's role assignments grants `action` (§62 table). */
  hasAction(action: string): boolean;
}

/**
 * Node's `http` request narrowed with the fields Express adds at runtime and
 * the principal the global auth chain attaches. Typed against the built-in
 * `http` types (not `express.Request`) so the service needs no
 * `@types/express` devDependency — matches `common/http-types.ts`.
 */
export interface RequestWithPrincipal extends RequestWithTraceId {
  params?: Record<string, string>;
  query?: Record<string, string | string[] | undefined>;
  body?: unknown;
  /** Set by the global DevAuthGuard once the caller is authenticated. */
  principal?: Principal;
}

export interface BuildPrincipalInput {
  user: { id: string; clearance: number };
  organisation_id: string;
  roles: PrincipalRoleAssignment[];
}

/**
 * Builds a canonical Principal whose `hasAction` is derived from the §62 role
 * table (the single source of truth in `identity/roles.ts`) — so no caller can
 * assert an authority its roles do not grant.
 */
export function buildPrincipal(input: BuildPrincipalInput): Principal {
  const roles = input.roles;
  return {
    user: { id: input.user.id, clearance: input.user.clearance },
    organisation_id: input.organisation_id,
    roles,
    hasAction(action: string): boolean {
      return roles.some((assignment) => roleHasAction(assignment.role, action as Action));
    },
  };
}

/**
 * Narrows `request.principal` from optional to required. Safe to call in any
 * handler behind a route decorated with `@RequiresAction`, since the global
 * AccessGuard denies the request before the handler runs when no principal is
 * present. The throw here is defence in depth only.
 */
export function requirePrincipal(request: RequestWithPrincipal): Principal {
  if (!request.principal) {
    throw new UnauthorizedException('No authenticated principal on request');
  }
  return request.principal;
}
