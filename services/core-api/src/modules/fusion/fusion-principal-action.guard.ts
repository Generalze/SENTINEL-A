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
import type { RequestWithPrincipal } from './fusion-principal.types';

const REQUIRES_ACTION_KEY = 'sentinel:requires-action';

/**
 * Marks a route handler as requiring the given action on the caller's
 * principal. Mirrors the shape of the `@RequiresAction(...)` decorator the
 * identity module's real access guard is specified to use (arch §62.1), so
 * swapping this guard for the real one is a drop-in replacement and this
 * module's controller does not change.
 */
export const RequiresAction = (action: string): MethodDecorator & ClassDecorator => SetMetadata(REQUIRES_ACTION_KEY, action);

/**
 * TODO-WIRED-IN-WAVE-4
 * ---------------------
 * Stand-in for the identity module's real access guard, which is being built
 * concurrently in this tree and is not yet wired into app.module.ts. This
 * module must not import from `src/modules/identity`, so the guard is
 * duplicated locally — deliberately, and deliberately kept tiny — and reads
 * `request.principal` defensively rather than assuming any particular auth
 * pipeline populated it.
 *
 * Behaviour:
 *  - principal present -> require `principal.hasAction(action)` to be true.
 *    Fails closed if `hasAction` is not even a function, so a partially
 *    wired principal cannot accidentally authorise anything.
 *  - principal absent, DEV_AUTH_ENABLED === 'true' -> allow through. Local/
 *    dev/test fallback for this wave, where nothing upstream populates
 *    `request.principal` yet. The controller MUST then treat the tenant as
 *    un-inferred and demand an explicit `organisation_id` — see
 *    fusion.controller.ts; listing hypotheses across every organisation is
 *    never acceptable, even in dev.
 *  - principal absent, DEV_AUTH_ENABLED !== 'true' -> 401. Fails closed by
 *    default so this can never silently become an open endpoint outside dev.
 *
 * The lead replaces this guard wholesale (together with the events module's
 * identical stand-in) once the identity guard lands.
 */
@Injectable()
export class FusionPrincipalActionGuard implements CanActivate {
  private readonly logger = new Logger(FusionPrincipalActionGuard.name);

  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const action = this.reflector.getAllAndOverride<string | undefined>(REQUIRES_ACTION_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    const request = context.switchToHttp().getRequest<RequestWithPrincipal>();
    const principal = request.principal;

    if (!principal) {
      if (process.env.DEV_AUTH_ENABLED !== 'true') {
        this.logger.warn(
          `denied [action=${action ?? 'unknown'}]: no principal on request and DEV_AUTH_ENABLED is not "true"`,
        );
        throw new UnauthorizedException('Authentication required');
      }
      this.logger.warn(
        `allowing [action=${action ?? 'unknown'}] with no principal: DEV_AUTH_ENABLED dev bypass (TODO-WIRED-IN-WAVE-4)`,
      );
      return true;
    }

    if (action && (typeof principal.hasAction !== 'function' || !principal.hasAction(action))) {
      this.logger.warn(`denied [action=${action}]: principal (org=${principal.organisation_id}) lacks this action`);
      throw new ForbiddenException(`Missing required action: ${action}`);
    }

    return true;
  }
}
