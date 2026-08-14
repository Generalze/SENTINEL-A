import type { RequestWithTraceId } from '../../common/http-types';

/**
 * TODO-WIRED-IN-WAVE-4
 * ---------------------
 * Minimal local shape for the principal that the identity module (WP-03) is
 * expected to attach to `request.principal` once the lead wires its guard
 * into app.module.ts.
 *
 * This module deliberately does NOT import anything from
 * `src/modules/identity` — that module is being built concurrently in this
 * same tree and is not yet registered — so the interface declares only the
 * two fields the fusion routes actually read, and is read defensively
 * (`hasAction` optional) so it degrades safely if the real shape differs
 * slightly at integration. It intentionally mirrors the equivalent local
 * declaration in the events module rather than importing it: the two modules
 * are separate lanes, and both stubs are deleted together when the real
 * principal type lands.
 */
export interface FusionPrincipal {
  organisation_id: string;
  hasAction?: (action: string) => boolean;
}

export interface RequestWithPrincipal extends RequestWithTraceId {
  principal?: FusionPrincipal;
}
