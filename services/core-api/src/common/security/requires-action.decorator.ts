import { SetMetadata } from '@nestjs/common';
import { CLASSIFICATION_LEVELS, type ClassificationLevel } from '../../modules/identity/classification';

/**
 * ============================================================================
 * THE canonical route-authorisation decorators (WP-14 — fixes H1/H2).
 *
 * ONE metadata key, read by the globally-wired AccessGuard. Every module's
 * previous per-module `@RequiresAction` (each with its own private metadata
 * key such as `sentinel:requires-action`, `sentinel:evidence:requires-action`,
 * `sentinel:ledger:requires-action`, ...) is deleted in favour of this.
 * ============================================================================
 */

/** Reflector key for the action a route requires. Read by AccessGuard. */
export const REQUIRES_ACTION_KEY = 'identity:requires-action';

/** Reflector key marking a route exempt from authentication. Read by DevAuthGuard/AccessGuard. */
export const IS_PUBLIC_KEY = 'identity:public';

export interface RequiresActionOptions {
  /** Object classification for this route (§47). Defaults to PUBLIC (no clearance/purpose requirement). */
  classification?: ClassificationLevel;
}

export interface RequiredActionMetadata {
  /** §62.1 action string; validated against the role table at runtime by AccessGuard. */
  action: string;
  classification: ClassificationLevel;
}

/**
 * Declares the §62.1 action a route requires. Read by the global AccessGuard
 * via Reflector, e.g.:
 *
 *   @RequiresAction('evidence.read', { classification: CLASSIFICATION_LEVELS.SENSITIVE })
 *
 * AccessGuard treats an undecorated, non-@Public route as unrestricted (it is
 * not a default-deny gate by itself) — every route that needs protecting MUST
 * carry this decorator.
 */
export function RequiresAction(action: string, options: RequiresActionOptions = {}): MethodDecorator & ClassDecorator {
  const metadata: RequiredActionMetadata = {
    action,
    classification: options.classification ?? CLASSIFICATION_LEVELS.PUBLIC,
  };
  return SetMetadata(REQUIRES_ACTION_KEY, metadata);
}

/**
 * Marks a route as PUBLIC: no authentication is performed and no principal is
 * attached. The global DevAuthGuard honours this so liveness/readiness probes
 * work even when `DEV_AUTH_ENABLED=false` (WP-14 — fixes the health 401). A
 * @Public route must never also carry @RequiresAction.
 */
export function Public(): MethodDecorator & ClassDecorator {
  return SetMetadata(IS_PUBLIC_KEY, true);
}
