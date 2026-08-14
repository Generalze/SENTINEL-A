import { CanActivate, ExecutionContext, ForbiddenException, Inject, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PURPOSE_REQUIRED_FROM } from './classification';
import type { RequestWithPrincipal } from './http-types';
import { IS_PUBLIC_KEY, REQUIRES_ACTION_KEY, type RequiredActionMetadata } from './requires-action.decorator';
import { roleHasAction } from './roles';

const PURPOSE_HEADER = 'x-purpose';
const ORGANISATION_PARAM_KEYS = ['organisationId', 'organisation_id'];
const SITE_PARAM_KEYS = ['siteId', 'site_id'];

type FailedConjunct =
  | 'principal_missing'
  | 'role_permits_action'
  | 'organisation_matches'
  | 'site_scope_matches'
  | 'clearance'
  | 'purpose_required';

/** First string value found for any of `keys` across params, then query, then body — request sources §62.1 checks may need a resource id from. */
function findRequestValue(request: RequestWithPrincipal, keys: readonly string[]): string | undefined {
  const sources: Array<Record<string, unknown> | undefined> = [
    request.params,
    request.query,
    request.body as Record<string, unknown> | undefined,
  ];
  for (const source of sources) {
    if (!source || typeof source !== 'object') continue;
    for (const key of keys) {
      const value = source[key];
      if (typeof value === 'string' && value.length > 0) return value;
    }
  }
  return undefined;
}

/**
 * Implements the §62.1 ALLOW-WHEN rule for Milestone 1:
 *
 *   ALLOW action WHEN
 *     role permits action
 *     AND organisation matches
 *     AND site scope matches (when the granting role assignment is site-scoped and the request carries a site)
 *     AND clearance >= object classification
 *     AND purpose is valid (x-purpose header present, for SENSITIVE+ routes)
 *
 * Device trust and Constitution-required-approval are explicitly out of
 * scope for WP-03 (device trust arrives with Shield; Constitution is a
 * separate module) and are NOT evaluated here.
 *
 * Every DENY is logged with the actor, the action and the specific failed
 * conjunct. Per directive: a cross-organisation match failure returns 404
 * (never reveal that the resource/org exists); every other failure
 * returns 403. Routes with no `@RequiresAction` are not restricted by
 * this guard — pair it with the decorator on every route that needs it.
 */
@Injectable()
export class AccessGuard implements CanActivate {
  private readonly logger = new Logger(AccessGuard.name);

  constructor(@Inject(Reflector) private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    // A @Public route is unauthenticated by design (DevAuthGuard attaches no
    // principal); it is never action-gated.
    const isPublic = this.reflector.getAllAndOverride<boolean | undefined>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

    const required = this.reflector.getAllAndOverride<RequiredActionMetadata | undefined>(REQUIRES_ACTION_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!required) {
      return true;
    }

    const request = context.switchToHttp().getRequest<RequestWithPrincipal>();
    const principal = request.principal;
    const actor = principal?.user.id ?? 'anonymous';

    const deny = (conjunct: FailedConjunct, notFound = false): never => {
      this.logger.warn(
        `access denied: actor=${actor} action=${required.action} failed_conjunct=${conjunct}`,
      );
      if (notFound) throw new NotFoundException();
      throw new ForbiddenException(`Not permitted: ${required.action}`);
    };

    if (!principal) {
      return deny('principal_missing');
    }

    // 1. role permits action
    const grantingAssignments = principal.roles.filter((assignment) => roleHasAction(assignment.role, required.action));
    if (grantingAssignments.length === 0) {
      return deny('role_permits_action');
    }

    // 2. organisation matches — the one conjunct whose failure hides
    // existence (404) instead of revealing "forbidden" (403). Most M1
    // routes never carry an explicit organisation id (it's always implied
    // by the principal), so this is a defensive check against any route
    // that does. The primary enforcement of tenant isolation is every
    // service query being filtered by principal.organisation_id.
    const requestedOrgId = findRequestValue(request, ORGANISATION_PARAM_KEYS);
    if (requestedOrgId !== undefined && requestedOrgId !== principal.organisation_id) {
      return deny('organisation_matches', true);
    }

    // 3. site scope matches — only enforced when the request names a site
    // AND none of the granting assignments are organisation-wide (an
    // org-wide, i.e. null-scoped, assignment always satisfies this).
    const requestedSiteId = findRequestValue(request, SITE_PARAM_KEYS);
    if (requestedSiteId !== undefined) {
      const satisfiesSiteScope = grantingAssignments.some(
        (assignment) => assignment.site_id === null || assignment.site_id === requestedSiteId,
      );
      if (!satisfiesSiteScope) {
        return deny('site_scope_matches');
      }
    }

    // 4. clearance >= object classification
    if (principal.user.clearance < required.classification) {
      return deny('clearance');
    }

    // 5. purpose is valid (required for SENSITIVE+ routes)
    if (required.classification >= PURPOSE_REQUIRED_FROM) {
      const purposeHeader = request.headers[PURPOSE_HEADER];
      const purpose = Array.isArray(purposeHeader) ? purposeHeader[0] : purposeHeader;
      if (!purpose || purpose.trim().length === 0) {
        return deny('purpose_required');
      }
    }

    return true;
  }
}
