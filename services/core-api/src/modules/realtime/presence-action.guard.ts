import { ForbiddenException, Inject, Injectable, Logger, SetMetadata, UnauthorizedException, type CanActivate, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AppConfigService } from '../../config/config.service';
import type { RequestWithPresencePrincipal } from './realtime-http-principal.types';

const REQUIRES_ACTION_KEY = 'sentinel:realtime:requires-action';

/** Marks `GET /api/v1/presence` as requiring `presence.view` on the caller's principal. */
export const RequiresRealtimeAction = (action: string): MethodDecorator & ClassDecorator => SetMetadata(REQUIRES_ACTION_KEY, action);

/**
 * TODO-WIRED-IN-WAVE-4
 * ---------------------
 * Stand-in for the identity module's real access guard, same pattern as
 * `events/principal-action.guard.ts` (see that file's doc comment for the
 * full rationale) — duplicated locally rather than imported/shared, per
 * this module's exclusive-lane coordination rule. Behaviour:
 *
 *  - principal present  -> require `principal.hasAction('presence.view')`.
 *  - principal absent, DEV_AUTH_ENABLED === true -> allow through (dev
 *    bypass); the controller then requires an explicit `organisation_id`
 *    query param since there is no principal org to scope the list to.
 *  - principal absent, DEV_AUTH_ENABLED !== true -> 401.
 *
 * The lead replaces this guard wholesale once the identity module's guard
 * is wired into app.module.ts; nothing else in this module should need to
 * change.
 */
@Injectable()
export class PresenceActionGuard implements CanActivate {
  private readonly logger = new Logger(PresenceActionGuard.name);

  constructor(
    @Inject(Reflector) private readonly reflector: Reflector,
    @Inject(AppConfigService) private readonly appConfig: AppConfigService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const action = this.reflector.getAllAndOverride<string | undefined>(REQUIRES_ACTION_KEY, [context.getHandler(), context.getClass()]);
    const request = context.switchToHttp().getRequest<RequestWithPresencePrincipal>();
    const principal = request.principal;

    if (!principal) {
      if (this.appConfig.values.DEV_AUTH_ENABLED !== true) {
        this.logger.warn(`denied [action=${action ?? 'unknown'}]: no principal on request and DEV_AUTH_ENABLED is not true`);
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
