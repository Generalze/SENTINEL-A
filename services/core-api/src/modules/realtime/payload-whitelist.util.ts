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
const PASSTHROUGH_KEYS = ['organisation_id', 'site_id', 'state', 'severity', 'status', 'updated_at', 'kind', 'assignment_id', 'user_id'] as const;

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

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
