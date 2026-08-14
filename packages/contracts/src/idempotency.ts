/**
 * Idempotency key derivation (architecture §64.1).
 *
 * Sentinel generates an idempotency key from tenant identity, source
 * identity, event identity and a time window so duplicate raw deliveries
 * can be linked to the original without erasing the fact that multiple
 * deliveries occurred.
 *
 * SECURITY (WP-14 / C1): the organisation id (and site id) LEAD the key.
 * A key built from `source_id`/`source_event_id` alone is attacker-forgeable
 * across tenants — org-B could pick org-A's source/event ids and, if the
 * lookup were global, either suppress org-A's genuine event as a "duplicate"
 * or probe for its existence (a cross-tenant oracle). Leading the key with
 * the organisation id makes a key from one tenant structurally incapable of
 * colliding with another's, and the repository lookup is additionally scoped
 * by `organisationId` (defence in depth: the composite DB unique is
 * `@@unique([organisationId, idempotencyKey])`).
 */
export function deriveIdempotencyKey(
  organisationId: string,
  siteId: string,
  sourceId: string,
  sourceEventId: string,
  occurredAt: string,
  windowMs: number
): string {
  if (windowMs <= 0) {
    throw new TypeError('windowMs must be greater than 0');
  }

  const epochMs = new Date(occurredAt).getTime();
  if (isNaN(epochMs)) {
    throw new TypeError('occurredAt must be a valid date string');
  }

  const bucket = Math.floor(epochMs / windowMs);
  return `${organisationId}:${siteId}:${sourceId}:${sourceEventId}:${bucket}`;
}
