/**
 * SENTINEL — admin gate for the Constitution read API.
 *
 * TODO-WIRED(lead, after WP-03): replace the duck-typed principal lookup below with the real
 * Identity guard/decorator once the identity module lands. This file deliberately imports
 * NOTHING from `src/modules/identity` — WP-03 is being built concurrently and WP-06 must not
 * take a build-time dependency on it. The contract assumed here is only that some upstream
 * authentication layer attaches a principal to the request object; the moment it does, this
 * guard works unchanged, and until it does, the endpoint fails closed with 401.
 *
 * Deliberately strict (§62.1, deny by default): no principal is 401, a principal without an
 * administrative role is 403. There is no "open in development" branch — a policy-metadata
 * endpoint that silently opens itself is exactly the kind of quiet authority erosion the
 * Constitution exists to prevent.
 */

import {
  ForbiddenException,
  Injectable,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';

export interface ConstitutionPrincipal {
  readonly userId: string;
  readonly roles: readonly string[];
}

/** Roles permitted to read active-policy metadata (§62 administrative authority). */
export const CONSTITUTION_POLICY_READER_ROLES: readonly string[] = [
  'platform.admin',
  'org.security.director',
  'constitution.steward',
];

/** Request properties an authentication layer conventionally attaches a principal to. */
const PRINCIPAL_PROPERTIES: readonly string[] = ['principal', 'user'];

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null ? (value as Record<string, unknown>) : null;
}

function firstNonEmptyString(...values: unknown[]): string | null {
  for (const value of values) {
    if (typeof value === 'string' && value.trim().length > 0) return value;
  }
  return null;
}

function readRoles(candidate: Record<string, unknown>): readonly string[] {
  const roles = candidate['roles'];
  if (!Array.isArray(roles)) return [];
  return roles.filter((role): role is string => typeof role === 'string');
}

/**
 * Pulls a principal off the request without knowing what produced it. Returns null when there
 * is nothing usable — the caller decides what that means (here: 401).
 */
export function extractPrincipal(request: unknown): ConstitutionPrincipal | null {
  const record = asRecord(request);
  if (record === null) return null;

  for (const property of PRINCIPAL_PROPERTIES) {
    const candidate = asRecord(record[property]);
    if (candidate === null) continue;
    const userId = firstNonEmptyString(
      candidate['userId'],
      candidate['user_id'],
      candidate['id'],
      candidate['sub'],
    );
    if (userId === null) continue;
    return { userId, roles: readRoles(candidate) };
  }
  return null;
}

@Injectable()
export class ConstitutionAdminGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const principal = extractPrincipal(context.switchToHttp().getRequest());

    if (principal === null) {
      throw new UnauthorizedException(
        'An authenticated principal is required to read Constitution policy metadata.',
      );
    }

    const authorised = principal.roles.some((role) =>
      CONSTITUTION_POLICY_READER_ROLES.includes(role),
    );
    if (!authorised) {
      throw new ForbiddenException(
        'Reading Constitution policy metadata requires an administrative role.',
      );
    }

    return true;
  }
}
