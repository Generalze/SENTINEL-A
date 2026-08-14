import { ForbiddenException, Injectable, Logger, SetMetadata, UnauthorizedException, type CanActivate, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { RequestWithPrincipal } from './principal.types';

const REQUIRES_ACTION_KEY = 'sentinel:requires-action';

/**
 * Marks a route handler as requiring the given action on the caller's
 * principal. Mirrors the shape of the `@RequiresAction(...)` decorator
 * described for the identity module's real access guard (WP-03, arch
 * §62.1), so that swapping `PrincipalActionGuard` for the real guard at
 * integration is a drop-in replacement — this module's controllers would
 * not need to change.
 */
export const RequiresAction = (action: string): MethodDecorator & ClassDecorator => SetMetadata(REQUIRES_ACTION_KEY, action);

/**
 * TODO-WIRED-IN-WAVE-4
 * ---------------------
 * Stand-in for the identity module's real access guard, which is being
 * built concurrently elsewhere in this tree and is not yet wired into
 * app.module.ts. We must not import from `src/modules/identity`, so this
 * guard reads `request.principal` defensively (it may simply be absent
 * today) rather than assuming any particular auth pipeline populated it.
 *
 * Behaviour:
 *  - principal present  -> require `principal.hasAction(action)` to be
 *    true (fails closed if `hasAction` isn't even a function). Org-match
 *    against the request body is enforced separately in the controller,
 *    once the body has been schema-validated.
 *  - principal absent, DEV_AUTH_ENABLED === 'true' -> allow through. This
 *    is the local/dev/test fallback for this wave, where nothing upstream
 *    populates `request.principal` yet. Downstream code MUST treat an
 *    absent principal as "org-match not enforced" and log that it did so
 *    — see events.controller.ts.
 *  - principal absent, DEV_AUTH_ENABLED !== 'true' -> 401. Fails closed by
 *    default so this never silently becomes an open endpoint outside dev.
 *
 * The lead replaces this guard wholesale once the identity module's guard
 * lands; nothing else in this module should need to change.
 */
@Injectable()
export class PrincipalActionGuard implements CanActivate {
  private readonly logger = new Logger(PrincipalActionGuard.name);

  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const action = this.reflector.getAllAndOverride<string | undefined>(REQUIRES_ACTION_KEY, [context.getHandler(), context.getClass()]);
    const request = context.switchToHttp().getRequest<RequestWithPrincipal>();
    const principal = request.principal;

    if (!principal) {
      if (process.env.DEV_AUTH_ENABLED !== 'true') {
        this.logger.warn(`denied [action=${action ?? 'unknown'}]: no principal on request and DEV_AUTH_ENABLED is not "true"`);
        throw new UnauthorizedException('Authentication required');
      }
      this.logger.warn(`allowing [action=${action ?? 'unknown'}] with no principal: DEV_AUTH_ENABLED dev bypass (TODO-WIRED-IN-WAVE-4)`);
      return true;
    }

    if (action && (typeof principal.hasAction !== 'function' || !principal.hasAction(action))) {
      this.logger.warn(`denied [action=${action}]: principal (org=${principal.organisation_id}) lacks this action`);
      throw new ForbiddenException(`Missing required action: ${action}`);
    }

    return true;
  }
}
