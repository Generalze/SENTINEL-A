/**
 * Idempotency key derivation (architecture §64.1).
 *
 * Sentinel generates an idempotency key from source identity, event
 * identity and a time window so duplicate raw deliveries can be linked to
 * the original without erasing the fact that multiple deliveries occurred.
 */
export function deriveIdempotencyKey(
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
  return `${sourceId}:${sourceEventId}:${bucket}`;
}
