import type { RequestWithTraceId } from '../../common/http-types';

/**
 * TODO-WIRED-IN-WAVE-4: local, minimal shape for the principal an upstream
 * auth layer (identity's real access guard, once wired into
 * app.module.ts by the lead) is expected to attach to `request.principal`
 * for HTTP requests. Mirrors `events/principal.types.ts`'s
 * `EventsPrincipal` — same pattern, kept local to this module rather than
 * imported, per this module's exclusive-lane coordination rule and to
 * avoid a build-time dependency on `src/modules/identity` (WP-03,
 * concurrent work in this tree).
 */
export interface PresenceHttpPrincipal {
  organisation_id: string;
  hasAction?: (action: string) => boolean;
}

export interface RequestWithPresencePrincipal extends RequestWithTraceId {
  principal?: PresenceHttpPrincipal;
}
