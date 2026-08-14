import { UnauthorizedException } from '@nestjs/common';
import type { User } from '@prisma/client';
import type { RequestWithPrincipal } from './http-types';

/** One §62 role assignment for a user, optionally scoped to a single site. */
export interface PrincipalRoleAssignment {
  role: string;
  site_id: string | null;
}

/**
 * The authenticated caller, attached to `request.principal` by
 * DevAuthGuard and consumed by AccessGuard and every identity controller.
 */
export interface Principal {
  user: User;
  roles: PrincipalRoleAssignment[];
  organisation_id: string;
}

/**
 * Narrows `request.principal` from optional to required. Safe to call in
 * any handler behind a route decorated with `@RequiresAction`, since
 * AccessGuard denies the request before the handler runs when no
 * principal is present. The throw here is defence in depth only.
 */
export function requirePrincipal(request: RequestWithPrincipal): Principal {
  if (!request.principal) {
    throw new UnauthorizedException('No authenticated principal on request');
  }
  return request.principal;
}
