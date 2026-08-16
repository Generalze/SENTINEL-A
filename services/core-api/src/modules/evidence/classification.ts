/**
 * Local, minimal duplicate of the §47 data-classification level names.
 *
 * Canonical source: `src/modules/identity/classification.ts` (WP-03,
 * exclusive identity-module lane). WP-09's coordination rules say this
 * module must not import anything from `src/modules/identity` — both
 * modules are worked concurrently in this tree, and importing across
 * lanes would create a merge/build coupling neither lane controls. So
 * only the small piece this module actually needs (the level *names*,
 * used to tag an Evidence row and to build the ingest DTO's zod enum) is
 * mirrored here, not the full table or the numeric clearance-comparison
 * semantics (this module does not evaluate clearance at all in WP-09 —
 * see principal-action.guard.ts's doc comment).
 *
 * Milestone-1 boundary: once identity/classification.ts is safe for other
 * modules to import (e.g. hoisted to a shared package, or the lead wires
 * cross-module imports after both lanes land), delete this file and
 * import the canonical one instead.
 */
export const EVIDENCE_CLASSIFICATION_LEVELS = ['PUBLIC', 'INTERNAL', 'SENSITIVE', 'RESTRICTED', 'EVIDENCE', 'SECRETS'] as const;

export type EvidenceClassificationLevel = (typeof EVIDENCE_CLASSIFICATION_LEVELS)[number];
