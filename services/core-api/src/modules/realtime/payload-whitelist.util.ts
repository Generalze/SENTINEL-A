/**
 * Deliverable #3: forwards only whitelisted fields from a raw NATS message
 * to WS clients — never the full internal record. `id` accepts a small set
 * of source-field aliases (fusion's Hypothesis record identifies itself as
 * `hypothesis_id`, not `id`; §12.1's Incident uses `id` directly) so both
 * message shapes normalise to the same client-facing `id` key. Every other
 * key is passed through only if it is one of the explicitly whitelisted
 * names — anything else in the source payload (internal notes, raw
 * evidence refs, model internals, ...) is dropped.
 */
const ID_ALIASES = ['id', 'hypothesis_id', 'incident_id', 'incident_candidate_id'] as const;
/**
 * WP-17/D4: `assignment_id` and `user_id` are gone from this list. WP-16 added
 * them so Field events could ride the organisation room; Field traffic now has
 * its own site-scoped rooms and its own narrower projection
 * (`pickFieldRealtimeFields`), so the organisation-room whitelist goes back to
 * carrying only what incident and hypothesis updates need.
 */
const PASSTHROUGH_KEYS = ['organisation_id', 'site_id', 'state', 'severity', 'status', 'updated_at', 'kind'] as const;

export type WhitelistedRealtimePayload = Readonly<Record<string, unknown>>;

/**
 * `fallbackOrganisationId` (parsed from the NATS subject, which always
 * carries it per the `sentinel.*.{organisation_id}` convention) is used
 * only when the payload itself does not carry an `organisation_id` field —
 * this is expected for e.g. today's Hypothesis contract shape.
 */
export function pickWhitelistedFields(raw: unknown, fallbackOrganisationId?: string): WhitelistedRealtimePayload {
  const record = isPlainRecord(raw) ? raw : {};
  const out: Record<string, unknown> = {};

  for (const alias of ID_ALIASES) {
    const value = record[alias];
    if (typeof value === 'string' || typeof value === 'number') {
      out.id = value;
      break;
    }
  }

  for (const key of PASSTHROUGH_KEYS) {
    if (key in record && record[key] !== undefined) {
      out[key] = record[key];
    }
  }

  if (out.organisation_id === undefined && fallbackOrganisationId) {
    out.organisation_id = fallbackOrganisationId;
  }

  return out;
}

/**
 * WP-17/D4: Field events get their own, narrower projection.
 *
 * A Field event is a signal that something in the socket's scope changed —
 * the client then refetches the authoritative record over REST, where
 * `field.assignment.*` / `field.state.read` are enforced. So the wire carries
 * routing and identity only. In particular the operative's `state`
 * (`COMPROMISED`, `NEED_SUPPORT`, ...) is deliberately NOT forwarded, even
 * though the shared whitelist above would pass a `state` key through.
 *
 * `organisation_id` and `site_id` are taken from the NATS subject the message
 * arrived on — the same values that chose the room — rather than from the
 * payload body, so a client can never be told it is looking at a scope other
 * than the one that was authorised to receive it.
 */
const FIELD_PASSTHROUGH_KEYS = ['kind', 'assignment_id', 'user_id'] as const;

export function pickFieldRealtimeFields(raw: unknown, organisationId: string, siteId: string): WhitelistedRealtimePayload {
  const record = isPlainRecord(raw) ? raw : {};
  const out: Record<string, unknown> = { organisation_id: organisationId, site_id: siteId };

  for (const key of FIELD_PASSTHROUGH_KEYS) {
    const value = record[key];
    if (typeof value === 'string' || typeof value === 'number') {
      out[key] = value;
    }
  }

  return out;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
