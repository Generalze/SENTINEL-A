import {
  ForbiddenException,
  Injectable,
  Logger,
  SetMetadata,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { RequestWithLedgerPrincipal } from './ledger.principal.types';

const REQUIRES_ACTION_KEY = 'sentinel:ledger:requires-action';

/**
 * Marks a route handler as requiring the given action on the caller's principal. Mirrors
 * events/principal-action.guard.ts's `@RequiresAction(...)` shape exactly, so swapping this
 * guard for the identity module's real access guard at integration is a drop-in replacement.
 */
export const RequiresLedgerAction = (action: string): MethodDecorator & ClassDecorator =>
  SetMetadata(REQUIRES_ACTION_KEY, action);

/**
 * TODO-WIRED-IN-WAVE-4
 * ---------------------
 * Stand-in for the identity module's real access guard — mirrors
 * events/principal-action.guard.ts's `PrincipalActionGuard` pattern exactly (same behaviour,
 * same defensive read of `request.principal`, same dev bypass), duplicated locally rather than
 * imported so this module stays self-contained within its exclusive lane. We must not import
 * from `src/modules/identity`, so this guard reads `request.principal` defensively (it may
 * simply be absent) rather than assuming any particular auth pipeline populated it.
 *
 * Behaviour:
 *  - principal present  -> require `principal.hasAction(action)` to be true (fails closed if
 *    `hasAction` isn't even a function). Org-match against tenant-scoped data is enforced by
 *    the controller always using the principal's own organisation_id — see ledger.controller.ts.
 *  - principal absent, DEV_AUTH_ENABLED === 'true' -> allow through. Local/dev/test fallback
 *    for this wave, where nothing upstream populates `request.principal` yet. Downstream code
 *    MUST treat an absent principal as "org-match not enforced" and log that it did so.
 *  - principal absent, DEV_AUTH_ENABLED !== 'true' -> 401. Fails closed by default so this
 *    never silently becomes an open endpoint outside dev.
 *
 * Every denial (401 or 403) is logged via `Logger`, which the app wires to pino
 * (`app.useLogger(app.get(Logger))` in main.ts) — satisfies "unauthorized read denied and
 * logged" without this guard needing its own pino dependency.
 *
 * The lead replaces this guard wholesale once the identity module's guard is integrated into
 * this route set; nothing else in this module should need to change.
 */
@Injectable()
export class LedgerPrincipalActionGuard implements CanActivate {
  private readonly logger = new Logger(LedgerPrincipalActionGuard.name);

  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const action = this.reflector.getAllAndOverride<string | undefined>(REQUIRES_ACTION_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    const request = context.switchToHttp().getRequest<RequestWithLedgerPrincipal>();
    const principal = request.principal;

    if (!principal) {
      if (process.env.DEV_AUTH_ENABLED !== 'true') {
        this.logger.warn(`ledger access denied [action=${action ?? 'unknown'}]: no principal on request and DEV_AUTH_ENABLED is not "true"`);
        throw new UnauthorizedException('Authentication required');
      }
      this.logger.warn(`ledger access allowed [action=${action ?? 'unknown'}] with no principal: DEV_AUTH_ENABLED dev bypass (TODO-WIRED-IN-WAVE-4)`);
      return true;
    }

    if (action && (typeof principal.hasAction !== 'function' || !principal.hasAction(action))) {
      this.logger.warn(`ledger access denied [action=${action}]: principal (org=${principal.organisation_id}) lacks this action`);
      throw new ForbiddenException(`Missing required action: ${action}`);
    }

    return true;
  }
}
