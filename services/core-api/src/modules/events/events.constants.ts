/** JetStream stream name for accepted events (deliverable #4). */
export const STREAM_NAME = 'SENTINEL_EVENTS';

/** Wildcard subject the stream captures; individual publishes use a concrete subject. */
export const SUBJECT_WILDCARD = 'sentinel.events.>';

/** File-storage retention window for the stream: 7 days. */
export const STREAM_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/** How long a single JetStream publish attempt is allowed to take. */
export const PUBLISH_TIMEOUT_MS = 2000;

/** Retry-sweep tick interval (§76: unpublished events must eventually be delivered). */
export const SWEEP_INTERVAL_MS = 10_000;

/** An unpublished row is only eligible for the sweep once it's this old. */
export const UNPUBLISHED_RETRY_AFTER_MS = 15_000;

/** How many overdue rows a single sweep tick will attempt to republish. */
export const SWEEP_BATCH_SIZE = 100;

/** Idempotency key time-bucket window (architecture §64.1). */
export const IDEMPOTENCY_WINDOW_MS = 5000;

export const DEFAULT_LIST_LIMIT = 50;
export const MAX_LIST_LIMIT = 200;

/** Actions enforced by the global AccessGuard on this module's routes. */
export const ACTION_EVENT_INGEST = 'event.ingest';
export const ACTION_EVENT_READ = 'event.read';
