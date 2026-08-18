/**
 * WP-17/F3 — the one definition of what may appear as a single NATS subject
 * token in this service.
 *
 * `organisation_id` and `site_id` are free-text columns (see
 * `prisma/schema/field.prisma`), and Field/incident subjects interpolate them
 * directly: `sentinel.field.updated.{organisation_id}.{site_id}`. NATS treats
 * `.` as the token separator and `*`/`>` as wildcards, so an id carrying any of
 * them changes the subject's arity or turns it into a wildcard — which lets a
 * caller who can name a site steer delivery into another site's room, or widen
 * it. Whitespace is excluded for the same reason (NATS rejects it, and a
 * publish failure is a silent delivery gap).
 *
 * The allowlist is deliberately narrower than "everything NATS tolerates":
 * every id this service actually mints is a UUID or a slug, so a tight
 * character class fails closed on anything unexpected rather than trying to
 * enumerate what is dangerous.
 */
export const MAX_SUBJECT_TOKEN_LENGTH = 256;

const SAFE_SUBJECT_TOKEN = /^[A-Za-z0-9_:-]{1,256}$/;

export function isSafeSubjectToken(value: unknown): value is string {
  return typeof value === 'string' && SAFE_SUBJECT_TOKEN.test(value);
}

/** Human-readable constraint, reused in API validation messages. */
export const SUBJECT_TOKEN_RULE = `must be 1-${MAX_SUBJECT_TOKEN_LENGTH} characters of A-Z a-z 0-9 _ : -`;

/**
 * Asserts before a subject is built. Callers that can degrade gracefully
 * (the outbox publishers) should test with `isSafeSubjectToken` first and skip
 * the row; this throw is the last line of defence for callers that cannot.
 */
export function assertSafeSubjectToken(value: string, label: string): void {
  if (!isSafeSubjectToken(value)) {
    throw new Error(`${label} is not a safe NATS subject token (${SUBJECT_TOKEN_RULE})`);
  }
}
