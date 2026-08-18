/**
 * WP-19/C9-09 actions. Patrol capability is deliberately its own vocabulary:
 * none of it is implied by `incident.view` or by the Field assignment actions,
 * and COMPLETE has no action at all because completion is system-owned — it
 * happens inside the transaction that resolves the final checkpoint, never on
 * a request.
 */
export const ACTION_PATROL_ROUTE_READ = 'patrol.route.read';
export const ACTION_PATROL_ROUTE_MANAGE = 'patrol.route.manage';
export const ACTION_PATROL_RUN_READ = 'patrol.run.read';
export const ACTION_PATROL_RUN_MANAGE = 'patrol.run.manage';
export const ACTION_PATROL_RUN_ACT = 'patrol.run.act';
export const ACTION_PATROL_CHECKPOINT_VERIFY = 'patrol.checkpoint.verify';

/**
 * Audit kinds written to FieldAuditLog (patrol is a Field capability and its
 * audit trail rides the same site-scoped, append-only table).
 */
export const AUDIT_PATROL_ROUTE_CREATED = 'PATROL_ROUTE_CREATED';
export const AUDIT_PATROL_ROUTE_VERSION_PUBLISHED = 'PATROL_ROUTE_VERSION_PUBLISHED';
export const AUDIT_PATROL_RUN_SCHEDULED = 'PATROL_RUN_SCHEDULED';
export const AUDIT_PATROL_RUN_STARTED = 'PATROL_RUN_STARTED';
export const AUDIT_PATROL_RUN_CANCELLED = 'PATROL_RUN_CANCELLED';
export const AUDIT_PATROL_RUN_ABANDONED = 'PATROL_RUN_ABANDONED';
export const AUDIT_PATROL_RUN_COMPLETED = 'PATROL_RUN_COMPLETED';
export const AUDIT_PATROL_CHECKPOINT_VERIFIED = 'PATROL_CHECKPOINT_VERIFIED';
export const AUDIT_PATROL_CHECKPOINT_MISSED = 'PATROL_CHECKPOINT_MISSED';

/**
 * Timeline kinds appended to an incident's own timeline when the run is
 * incident-linked. Identifiers and states only — never location payloads or
 * verification context.
 */
export const TIMELINE_PATROL_RUN_SCHEDULED = 'PATROL_RUN_SCHEDULED';
export const TIMELINE_PATROL_RUN_STARTED = 'PATROL_RUN_STARTED';
export const TIMELINE_PATROL_RUN_CANCELLED = 'PATROL_RUN_CANCELLED';
export const TIMELINE_PATROL_RUN_ABANDONED = 'PATROL_RUN_ABANDONED';
export const TIMELINE_PATROL_RUN_COMPLETED = 'PATROL_RUN_COMPLETED';
export const TIMELINE_PATROL_CHECKPOINT_VERIFIED = 'PATROL_CHECKPOINT_VERIFIED';
export const TIMELINE_PATROL_CHECKPOINT_MISSED = 'PATROL_CHECKPOINT_MISSED';

/**
 * WP-19 realtime rides the WP-17 Field path unchanged: a FieldOutbox row on
 * `sentinel.field.updated.{org}.{site}`, delivered to the Field site room.
 * The payload is this kind plus identifiers — run id, organisation, site —
 * and nothing else. Checkpoint states, windows, and verification detail are
 * read over REST, where own-run need-to-know is enforced (directive s.12).
 */
export const OUTBOX_KIND_PATROL_RUN_UPDATED = 'PATROL_RUN_UPDATED';

/** Run lifecycle actions recorded in the actor-scoped replay guard. */
export const RUN_ACTION_START = 'start';
export const RUN_ACTION_CANCEL = 'cancel';
export const RUN_ACTION_ABANDON = 'abandon';
