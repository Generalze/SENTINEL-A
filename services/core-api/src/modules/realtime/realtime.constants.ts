/** Deliverable #1: same HTTP server, dedicated Engine.IO path, default namespace. */
export const WS_PATH = '/ws';

/** Deliverable #1: Vite dev server default. */
export const DEFAULT_WS_CORS_ORIGIN = 'http://localhost:5173';

/**
 * Deliverable #1 (config-driven CORS). Read directly from `process.env`
 * rather than through `AppConfigService`/`env.schema.ts`: per WP-12
 * coordination rules this module's lane is `src/modules/realtime/**` only
 * (env.schema.ts is out of lane while three other agents work concurrently
 * in this tree) — mirroring how `events/principal-action.guard.ts` reads
 * `DEV_AUTH_ENABLED` straight off `process.env` for the same reason.
 * `WS_CORS_ORIGIN` may be a comma-separated list for more than one origin.
 */
export function resolveWsCorsOrigin(): string | string[] {
  const raw = process.env.WS_CORS_ORIGIN;
  if (!raw || raw.trim().length === 0) {
    return DEFAULT_WS_CORS_ORIGIN;
  }
  const origins = raw
    .split(',')
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);
  return origins.length > 0 ? origins : DEFAULT_WS_CORS_ORIGIN;
}

/**
 * Deliverable #3: plain (non-JetStream) subscriptions — this channel is
 * fire-and-forget, clients refetch history via REST. `>` matches the
 * organisation id token and anything published after it, per the
 * coordination note (fusion/incidents publishers are concurrent work and
 * their exact subject arity beyond `{organisation_id}` isn't fixed yet).
 */
export const NATS_SUBJECT_HYPOTHESIS = 'sentinel.fusion.hypothesis.>';
export const NATS_SUBJECT_INCIDENT = 'sentinel.incidents.updated.>';

/** Both subjects above carry `{organisation_id}` as their 4th dot-segment. */
export const SUBJECT_ORG_ID_SEGMENT_INDEX = 3;

export const WS_EVENT_HYPOTHESIS_UPDATED = 'hypothesis.updated';
export const WS_EVENT_INCIDENT_UPDATED = 'incident.updated';
export const WS_EVENT_PRESENCE_CHANGED = 'presence.changed';

/** Deliverable #4: `sentinel:presence:{organisation_id}` hash, field = user_id. */
export const PRESENCE_KEY_PREFIX = 'sentinel:presence:';

/** Action this module's HTTP route requires on the caller's principal (TODO-WIRED-IN-WAVE-4). */
export const ACTION_PRESENCE_VIEW = 'presence.view';

/** The one and only room a socket may ever join — always derived server-side. */
export function orgRoom(organisationId: string): string {
  return `org:${organisationId}`;
}
