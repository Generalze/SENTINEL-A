import { z } from 'zod';
import { EdgeIdentityContextSchema, type EdgeIdentityContext } from '@sentinel/contracts';
import { EDGE_SIGNATURE_PROFILE } from '../edge-runtime.constants';

/**
 * WP-29B — EDGE CONFIGURATION, AND THE LINE IT IS NOT ALLOWED TO CROSS.
 *
 * Every key below answers one of exactly four questions:
 *
 *   WHO AM I      — `EDGE_ID`, `EDGE_ORGANISATION_ID`, `EDGE_KEY_ID`,
 *                   `EDGE_KEY_VERSION`
 *   WHAT AM I     — `EDGE_AUTHORISED_SITE_IDS`
 *   BOUND TO
 *   WHERE DO I    — `SENTINEL_CENTRAL_URL`, `PORT`
 *   TALK
 *   WHERE DO I    — `EDGE_QUEUE_PATH`
 *   WRITE
 *
 * plus `LOG_LEVEL`, which is operational noise control and affects nothing.
 *
 * THE KEYS THAT ARE DELIBERATELY ABSENT, AND MUST STAY ABSENT
 * -----------------------------------------------------------
 * Adding any of these is a security-contract change, not a convenience. They
 * are enumerated because a reviewer cannot see an absence, and
 * `env.schema.spec.ts` is the permanent guard that each stays missing:
 *
 *   EDGE_TRUSTED / EDGE_TRUST_STATUS
 *       Central owns `edge_trust` on `EdgeRegistryKeyRecord` and refuses
 *       EDGE_NOT_TRUSTED against ITS copy. A deployment-settable trust flag
 *       would be an Edge declaring itself trustworthy in a file that anyone
 *       with shell access to the closet can edit. It would confer nothing —
 *       and it would make an Edge we had suspended look perfectly healthy to
 *       its own operators.
 *
 *   EDGE_ANCHOR_HOLDOVER_MS / EDGE_TRUSTED_TIME_MAX_AGE_MS
 *       How long Edge may vouch for time it cannot re-verify. Hard-wired in
 *       `edge-runtime.constants.ts` at the frozen lease ceiling. A
 *       per-deployment value is a per-deployment answer to "how stale may our
 *       evidence be", set by whoever last edited the file.
 *
 *   EDGE_STALE_TOLERANT_OPERATION_KINDS / EDGE_WITNESS_ALL_KINDS
 *       Which kinds may commit on an unwitnessed clock is
 *       `DEVICE_OFFLINE_STALE_TOLERANT_OPERATION_KINDS`, a frozen contract
 *       list whose own comment says widening it is a security-contract change.
 *       An env var here would widen it per site, invisibly.
 *
 *   EDGE_SIGNATURE_PROFILE
 *       One approved profile, hard-wired. A deployment cannot negotiate
 *       cryptography.
 *
 *   EDGE_ALLOW_UNTRUSTED_TIME / EDGE_FALLBACK_TO_SYSTEM_CLOCK
 *       The single most dangerous key that could ever appear in this file. It
 *       would convert the correct, visible refusal at
 *       NO_TRUSTWORTHY_TIME_WITNESS into a silent forgery from the host wall
 *       clock, and it would be switched on by the first operator who found the
 *       refusals inconvenient.
 *
 *   EDGE_SIGNING_KEY / EDGE_PRIVATE_KEY
 *       Not because key material is unimportant, but because WP-29B has no
 *       ruling on where the Edge signing key lives (see the FW2-11 report).
 *       Inventing an env var for it here would settle that question by
 *       accident, in the least reviewable place available.
 *
 *   DATABASE_URL
 *       Edge has no database and must not acquire one by configuration.
 */

const csvList = z.preprocess((value) => {
  if (typeof value !== 'string') return value;
  const parts = value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  return parts;
}, z.array(z.string().min(1).max(256)).min(1, 'at least one site id is required'));

export const envSchema = z.object({
  /** WHO AM I. Central refuses EDGE_ORGANISATION_MISMATCH when this is wrong. */
  EDGE_ORGANISATION_ID: z
    .string({ required_error: 'EDGE_ORGANISATION_ID is required' })
    .min(1, 'EDGE_ORGANISATION_ID is required')
    .max(256),
  EDGE_ID: z.string({ required_error: 'EDGE_ID is required' }).min(1, 'EDGE_ID is required').max(256),
  /**
   * The registry IDENTITY of the receipt-signing key. Never the key. A wrong
   * value here produces receipts central refuses as EDGE_KEY_NOT_USABLE, which
   * is loud; a key here would be a secret in an environment file, which is not.
   */
  EDGE_KEY_ID: z.string({ required_error: 'EDGE_KEY_ID is required' }).min(1, 'EDGE_KEY_ID is required').max(256),
  EDGE_KEY_VERSION: z.coerce
    .number({ invalid_type_error: 'EDGE_KEY_VERSION must be a number' })
    .int('EDGE_KEY_VERSION must be an integer')
    .positive('EDGE_KEY_VERSION must be positive'),
  /**
   * WHAT AM I BOUND TO. Comma-separated site ids.
   *
   * ADVISORY AND NARROWING ONLY, exactly as documented on
   * `EdgeIdentityContextSchema`. Central holds the authoritative
   * `authorised_site_ids` and refuses EDGE_SITE_NOT_AUTHORISED against its own
   * copy, so widening this list buys a deployment nothing at all — it can only
   * cause Edge to attempt work central will refuse. It is configuration
   * precisely BECAUSE it cannot grant anything.
   *
   * Required, with no default and no wildcard: an Edge that has not been told
   * which sites it serves must fail to boot rather than serve all of them.
   */
  EDGE_AUTHORISED_SITE_IDS: csvList,
  /** WHERE DO I TALK. Endpoint only; reachability is a readiness question. */
  SENTINEL_CENTRAL_URL: z
    .string({ required_error: 'SENTINEL_CENTRAL_URL is required' })
    .min(1, 'SENTINEL_CENTRAL_URL is required')
    .url('SENTINEL_CENTRAL_URL must be a valid URL'),
  /**
   * WHERE DO I WRITE. The durable offline queue's directory.
   *
   * A path, not a policy: it says where the bytes go, never what may be written
   * there or for how long. There is deliberately no companion retention or
   * max-age key — see the absent-keys list above.
   */
  EDGE_QUEUE_PATH: z
    .string({ required_error: 'EDGE_QUEUE_PATH is required' })
    .min(1, 'EDGE_QUEUE_PATH is required'),
  // -------------------------------------------------------------------------
  // WP-29B/FW2-11 — THE TRUSTED-TIME VERIFICATION KEYRING.
  //
  // PUBLIC TRUST MATERIAL, INLINE, DEFAULT-ABSENT, FAIL-CLOSED — the
  // `ANDROID_ATTESTATION_*` pattern, and inline is correct here for the same
  // reason it is correct there: every byte of it is a PUBLIC key. The private
  // counterpart lives at central and never comes near an Edge.
  //
  // These are not an exception to the doctrine above. They do not tell Edge
  // what it may witness or for how long; they tell it WHOSE SIGNATURE COUNTS,
  // which is a binding, exactly like `EDGE_ID`. And unlike a policy knob they
  // cannot fail open: a wrong key verifies nothing, a missing key verifies
  // nothing, and both leave Edge emitting `edge_trusted_time: null` and central
  // refusing at NO_TRUSTWORTHY_TIME_WITNESS.
  //
  // Both are OPTIONAL together. Absence means this Edge cannot verify a
  // persisted anchor, so it does not persist one — see
  // `EDGE_TRUSTED_TIME_ANCHOR_STORE_BINDING`, where the volatile store stays
  // the default.
  //
  // There is deliberately no key-fetch URL, no keyring-refresh interval and no
  // "trust any signer" key. A keyring Edge downloaded would be unavailable
  // exactly when it is needed — with the WAN down — and one it cached would sit
  // on the same disk as the anchor, where whoever could rewrite the anchor
  // could rewrite the key that verifies it.
  // -------------------------------------------------------------------------
  /**
   * JSON array of 1-2 pinned verification keys:
   *   [{"signer_key_id":"...","public_key":"<base64url SEC1 point>","role":"ACTIVE"}]
   *
   * One ACTIVE, optionally one PREVIOUS. Malformed, empty, duplicated,
   * off-curve or ambiguous material refuses the WHOLE set — never a smaller
   * one. See `modules/trusted-time/edge-trusted-time.keyring.ts`.
   */
  EDGE_TRUSTED_TIME_VERIFICATION_KEYS: z.string().min(1, 'EDGE_TRUSTED_TIME_VERIFICATION_KEYS must not be empty').optional(),
  /** Names the keyring a verification decision was reached against, for audit. */
  EDGE_TRUSTED_TIME_KEYRING_VERSION: z.string().min(1, 'EDGE_TRUSTED_TIME_KEYRING_VERSION must not be empty').optional(),
  PORT: z.coerce
    .number({ invalid_type_error: 'PORT must be a number' })
    .int('PORT must be an integer')
    .positive('PORT must be a positive number')
    .default(3100),
  LOG_LEVEL: z
    .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace'], {
      errorMap: () => ({ message: 'LOG_LEVEL must be one of fatal, error, warn, info, debug, trace' }),
    })
    .default('info'),
});

export type EdgeConfig = z.infer<typeof envSchema>;

/**
 * Local alias rather than the ambient `NodeJS.ProcessEnv`: the repo's shared
 * root ESLint config does not register `NodeJS` as a known global for
 * `no-undef`, and this package must not modify root config.
 */
type EnvRecord = Record<string, string | undefined>;

export class ConfigValidationError extends Error {
  public readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super(`Invalid Edge configuration:\n${issues.map((issue) => ` - ${issue}`).join('\n')}`);
    this.name = 'ConfigValidationError';
    this.issues = issues;
  }
}

export function formatZodIssues(error: z.ZodError): string[] {
  return error.issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.join('.') : '(root)';
    return `${path}: ${issue.message}`;
  });
}

/** Boot must fail fast, and must list every bad variable at once rather than the first. */
export function loadConfig(env: EnvRecord = process.env): EdgeConfig {
  const result = envSchema.safeParse(env);
  if (!result.success) {
    throw new ConfigValidationError(formatZodIssues(result.error));
  }
  return result.data;
}

/**
 * THE CONFIGURATION BECOMES THE FROZEN IDENTITY TYPE, AND NOTHING MORE.
 *
 * This function is the only bridge from the environment into the rest of the
 * runtime, and it is intentionally the narrowest possible one: it builds an
 * `EdgeIdentityContext` — the frozen `.strict()` shape that has no trust field
 * and no key material — and everything downstream takes THAT rather than the
 * raw config.
 *
 * The profile is supplied from the hard-wired constant, not from the
 * environment, so an operator has no expressible way to influence it. The
 * `.parse` is not ceremony: it is where a config that has somehow grown a
 * `trust` or a `private_key` field stops, at boot, loudly.
 */
export function toEdgeIdentityContext(config: EdgeConfig): EdgeIdentityContext {
  return EdgeIdentityContextSchema.parse({
    schema_version: 1,
    organisation_id: config.EDGE_ORGANISATION_ID,
    edge_id: config.EDGE_ID,
    edge_key_id: config.EDGE_KEY_ID,
    edge_key_version: config.EDGE_KEY_VERSION,
    claimed_signature_profile: EDGE_SIGNATURE_PROFILE,
    authorised_site_ids: config.EDGE_AUTHORISED_SITE_IDS,
  });
}
