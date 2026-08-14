import { SetMetadata } from '@nestjs/common';
import { CLASSIFICATION_LEVELS, type ClassificationLevel } from './classification';
import type { Action } from './roles';

export const REQUIRES_ACTION_KEY = 'identity:requires-action';

export interface RequiresActionOptions {
  /** Object classification for this route (§47). Defaults to PUBLIC (no clearance/purpose requirement). */
  classification?: ClassificationLevel;
}

export interface RequiredActionMetadata {
  action: Action;
  classification: ClassificationLevel;
}

/**
 * Declares the §62.1 action a route requires. Read by AccessGuard via
 * Reflector, e.g.:
 *
 *   @RequiresAction('evidence.read', { classification: CLASSIFICATION_LEVELS.SENSITIVE })
 *
 * AccessGuard treats an undecorated route as unrestricted (it is not a
 * default-deny gate by itself) — every identity route MUST carry this
 * decorator to be protected.
 */
export function RequiresAction(action: Action, options: RequiresActionOptions = {}): MethodDecorator & ClassDecorator {
  const metadata: RequiredActionMetadata = {
    action,
    classification: options.classification ?? CLASSIFICATION_LEVELS.PUBLIC,
  };
  return SetMetadata(REQUIRES_ACTION_KEY, metadata);
}
