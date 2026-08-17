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
export const NATS_SUBJECT_FIELD = 'sentinel.field.updated.>';

/** All update subjects above carry `{organisation_id}` as their 4th dot-segment. */
export const SUBJECT_ORG_ID_SEGMENT_INDEX = 3;

/**
 * WP-17/D2: the Field subject alone is site-scoped —
 * `sentinel.field.updated.{organisation_id}.{site_id}` — so its 5th segment is
 * the site. A Field message without that segment is dropped rather than
 * broadcast organisation-wide (fail closed).
 */
export const SUBJECT_SITE_ID_SEGMENT_INDEX = 4;

export const WS_EVENT_HYPOTHESIS_UPDATED = 'hypothesis.updated';
export const WS_EVENT_INCIDENT_UPDATED = 'incident.updated';
export const WS_EVENT_FIELD_UPDATED = 'field.updated';
export const WS_EVENT_PRESENCE_CHANGED = 'presence.changed';

/** Deliverable #4: `sentinel:presence:{organisation_id}` hash, field = user_id. */
export const PRESENCE_KEY_PREFIX = 'sentinel:presence:';

/** Action enforced by the global AccessGuard on this module's HTTP route. */
export const ACTION_PRESENCE_VIEW = 'presence.view';

/** Organisation-wide room: incident, hypothesis, and presence traffic. Always derived server-side. */
export function orgRoom(organisationId: string): string {
  return `org:${organisationId}`;
}

/**
 * WP-17/D1: Field rooms, also derived server-side only.
 *
 * A socket joins EITHER `fieldOrgWideRoom` (when some Field-granting role
 * assignment is organisation-wide) OR one `fieldSiteRoom` per site-scoped
 * grant — never both. The bridge emits each Field event to the org-wide room
 * and to the one site room, so that split is what makes delivery exactly-once
 * per socket while still reaching organisation-wide authorities for every site.
 */
export function fieldSiteRoom(organisationId: string, siteId: string): string {
  return `org:${organisationId}:field:site:${siteId}`;
}

export function fieldOrgWideRoom(organisationId: string): string {
  return `org:${organisationId}:field:all`;
}
