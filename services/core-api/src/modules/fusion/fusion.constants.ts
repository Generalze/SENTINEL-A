/**
 * Fusion v1 constants (WP-05). Everything version-stamped onto a hypothesis
 * or emitted on the wire is declared here so a reviewer can see the whole
 * externally-visible surface of the module in one file.
 */

/**
 * Version of the declarative event -> signal rule table (core/eventRules.ts).
 * Recorded in §65.3 `rule_or_model_versions` on every hypothesis and every
 * transition. Bump whenever a rule is added, removed or its mapping changes,
 * so a replayed history always shows which table produced each decision.
 */
export const FUSION_RULES_VERSION = 'fusion-rules-1.0.0';

/**
 * Version of the certified threat-state core (core/threatState.ts, ported
 * from CERT-S). Recorded alongside FUSION_RULES_VERSION because a hypothesis
 * is only reproducible if you know BOTH which rules mapped the events and
 * which state machine consumed them.
 *
 * Fusion v1 is transparent rules only (§65.1) — no model version will ever
 * appear in this list until a learned component is introduced and separately
 * approved.
 */
export const FUSION_CORE_VERSION = 'fusion-threat-state-1.0.0';

/** The exact value written to §65.3 `rule_or_model_versions`, in this order. */
export const FUSION_RULE_VERSIONS: readonly string[] = [FUSION_RULES_VERSION, FUSION_CORE_VERSION];

/**
 * §65.3 `type`. Fusion v1 maintains one general hypothesis per correlation
 * window rather than competing typed hypotheses (typed/alternative
 * hypotheses are explicitly a later milestone), so this is a constant.
 */
export const HYPOTHESIS_TYPE = 'situation.correlated.v1';

// ---------------------------------------------------------------------------
// Correlation
// ---------------------------------------------------------------------------

/** Tumbling-window size for the correlation key (directive deliverable #1). */
export const CORRELATION_WINDOW_MS = 15 * 60 * 1000;

/** Substituted for a missing `zone_id` in the correlation key. */
export const SITE_WIDE_ZONE = 'site-wide';

// ---------------------------------------------------------------------------
// Messaging
// ---------------------------------------------------------------------------

/** Stream WP-04 owns and fusion consumes. Fusion never creates or alters it. */
export const EVENTS_STREAM_NAME = 'SENTINEL_EVENTS';

/** Subject filter for the fusion consumer — every event, every tenant. */
export const EVENTS_SUBJECT_FILTER = 'sentinel.events.>';

/**
 * Durable JetStream consumer name (directive deliverable #4). Durable so a
 * restart resumes from the last acknowledged message instead of replaying or
 * silently skipping the backlog.
 */
export const FUSION_DURABLE_NAME = 'fusion-v1';

/** JetStream stream fusion publishes its own output to. */
export const FUSION_STREAM_NAME = 'SENTINEL_FUSION';

/** Subjects captured by FUSION_STREAM_NAME. */
export const FUSION_SUBJECT_WILDCARD = 'sentinel.fusion.>';

/** Retention window for fusion output: 7 days, matching SENTINEL_EVENTS. */
export const FUSION_STREAM_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

export const PUBLISH_TIMEOUT_MS = 2000;

/** Per-message redelivery wait for un-acked fusion work. */
export const CONSUMER_ACK_WAIT_MS = 30_000;

/** Max redelivery attempts before a message is left to the stream's limits. */
export const CONSUMER_MAX_DELIVER = 5;

export function hypothesisSubject(organisationId: string): string {
  return `sentinel.fusion.hypothesis.${organisationId}`;
}

export function incidentCandidateSubject(organisationId: string): string {
  return `sentinel.fusion.incident-candidate.${organisationId}`;
}

// ---------------------------------------------------------------------------
// Incident-candidate latch
// ---------------------------------------------------------------------------

/**
 * Threat state at which a hypothesis becomes an incident candidate
 * (directive deliverable #5). §11.2 STATE 2 — SUSPICIOUS is the first state
 * whose documented system behaviour is "create alert", so it is the
 * threshold at which Response is handed something to act on.
 */
export const INCIDENT_CANDIDATE_STATE_THRESHOLD = 2;

// ---------------------------------------------------------------------------
// Persistence / concurrency
// ---------------------------------------------------------------------------

/**
 * How many times a single event application is retried when it loses an
 * optimistic-concurrency race (another delivery updated the same hypothesis
 * row first) or a create race on the correlation key.
 */
export const APPLY_MAX_ATTEMPTS = 4;

/** Prisma unique-constraint violation code. */
export const UNIQUE_CONSTRAINT_VIOLATION = 'P2002';

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

export const DEFAULT_LIST_LIMIT = 50;
export const MAX_LIST_LIMIT = 200;

/** Action this module's read routes require on the caller's principal; the global AccessGuard enforces it. */
export const ACTION_HYPOTHESIS_READ = 'hypothesis.read';
