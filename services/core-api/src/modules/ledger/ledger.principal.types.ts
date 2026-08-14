import type { RequestWithTraceId } from '../../common/http-types';

/**
 * TODO-WIRED-IN-WAVE-4: this is a local, minimal shape for the principal the identity module
 * (WP-03) is expected to attach to `request.principal`. Mirrors
 * events/principal.types.ts exactly. We deliberately do NOT import anything from
 * `src/modules/identity` (developed on its own timeline in this same tree) — this interface
 * only declares the fields this module actually reads, and is read defensively (optional
 * `hasAction`) so it degrades gracefully if the real shape differs slightly once integrated.
 */
export interface LedgerPrincipal {
  organisation_id: string;
  hasAction?: (action: string) => boolean;
}

export interface RequestWithLedgerPrincipal extends RequestWithTraceId {
  principal?: LedgerPrincipal;
}
