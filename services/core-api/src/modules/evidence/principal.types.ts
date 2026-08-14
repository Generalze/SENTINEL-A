import type { RequestWithTraceId } from '../../common/http-types';

/**
 * TODO-WIRED-IN-WAVE-4: this is a local, minimal shape for the principal
 * the identity module (WP-03) is expected to attach to `request.principal`
 * once its guard is wired into app.module.ts by the lead. Mirrors
 * `modules/events/principal.types.ts` exactly: we deliberately do NOT
 * import anything from `src/modules/identity` (WP-09's coordination rules
 * — both modules are being worked concurrently in this tree), so this
 * interface only declares the fields this module actually reads, and is
 * read defensively (optional `hasAction`, optional `user_id`) so it
 * degrades gracefully if the real shape differs slightly once integrated.
 */
export interface EvidencePrincipal {
  organisation_id: string;
  /** Identity module's User.id, when known. Used to attribute a 'user' custody actor; falls back to an anonymous marker when absent. */
  user_id?: string;
  hasAction?: (action: string) => boolean;
}

export interface RequestWithPrincipal extends RequestWithTraceId {
  principal?: EvidencePrincipal;
}
