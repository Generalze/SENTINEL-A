/** Per-organisation prefix separator inside an evidence object key: `{organisation_id}/{evidence_id}`. */
export const OBJECT_KEY_SEPARATOR = '/';

/**
 * Actions this module's routes require on the caller's principal
 * (TODO-WIRED-IN-WAVE-4, same convention as events.constants.ts — the
 * identity module's real AccessGuard already lists 'evidence.read' as a
 * known §62 action; this module cannot import that constant directly per
 * WP-09's coordination rules, so the string is duplicated here).
 */
export const ACTION_EVIDENCE_INGEST = 'evidence.ingest';
export const ACTION_EVIDENCE_READ = 'evidence.read';
export const ACTION_EVIDENCE_VERIFY = 'evidence.verify';

/** System actor id recorded on custody events the service writes without a human actor. */
export const SYSTEM_ACTOR_ID = 'system:evidence-vault';

export const PURPOSE_HEADER = 'x-purpose';

export const DEFAULT_LIST_LIMIT = 50;
export const MAX_LIST_LIMIT = 200;
