import { z } from 'zod';

/**
 * Accepts common textual representations of a boolean coming from the
 * environment (e.g. "true"/"false", "1"/"0") and normalises them to a
 * real boolean before zod's boolean check runs.
 */
const booleanFromEnvString = z.preprocess((value) => {
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (normalized === 'true' || normalized === '1') {
      return true;
    }
    if (normalized === 'false' || normalized === '0') {
      return false;
    }
  }
  return value;
}, z.boolean());

export const envSchema = z.object({
  DATABASE_URL: z
    .string({ required_error: 'DATABASE_URL is required' })
    .min(1, 'DATABASE_URL is required')
    .url('DATABASE_URL must be a valid connection URL'),
  NATS_URL: z
    .string({ required_error: 'NATS_URL is required' })
    .min(1, 'NATS_URL is required')
    .url('NATS_URL must be a valid connection URL'),
  REDIS_URL: z
    .string({ required_error: 'REDIS_URL is required' })
    .min(1, 'REDIS_URL is required')
    .url('REDIS_URL must be a valid connection URL'),
  S3_ENDPOINT: z
    .string({ required_error: 'S3_ENDPOINT is required' })
    .min(1, 'S3_ENDPOINT is required')
    .url('S3_ENDPOINT must be a valid URL'),
  S3_ACCESS_KEY: z
    .string({ required_error: 'S3_ACCESS_KEY is required' })
    .min(1, 'S3_ACCESS_KEY is required'),
  S3_SECRET_KEY: z
    .string({ required_error: 'S3_SECRET_KEY is required' })
    .min(1, 'S3_SECRET_KEY is required'),
  S3_BUCKET: z
    .string({ required_error: 'S3_BUCKET is required' })
    .min(1, 'S3_BUCKET is required'),
  S3_REGION: z.string().min(1, 'S3_REGION must not be empty').default('us-east-1'),
  /**
   * WP-09 (evidence module) addition. Dedicated bucket for immutable
   * evidence objects, kept separate from `S3_BUCKET` (general-purpose,
   * used elsewhere) so the evidence vault has its own storage namespace
   * per architecture §72.1/§74.1. Optional with a dev default so this is
   * purely additive — boot behaviour for every other module is unchanged
   * whether or not this variable is set.
   */
  S3_EVIDENCE_BUCKET: z.string().min(1, 'S3_EVIDENCE_BUCKET must not be empty').default('sentinel-evidence'),
  PORT: z.coerce
    .number({ invalid_type_error: 'PORT must be a number' })
    .int('PORT must be an integer')
    .positive('PORT must be a positive number')
    .default(3000),
  LOG_LEVEL: z
    .enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace'], {
      errorMap: () => ({
        message: 'LOG_LEVEL must be one of fatal, error, warn, info, debug, trace',
      }),
    })
    .default('info'),
  DEV_AUTH_ENABLED: booleanFromEnvString.default(false),
  // -------------------------------------------------------------------------
  // WP-26/D26-04B/C18-01 — ANDROID KEY ATTESTATION TRUST MATERIAL.
  //
  // THE ONLY WAY A DEPLOYMENT CAN EVER REACH `VERIFIED`, AND IT IS A
  // DEPLOYMENT ACT.
  //
  // Every key below is OPTIONAL and every one of them defaults to ABSENT, not
  // to a value. That is deliberate and it is the security property: a wrong
  // pinned root is worse than a missing one, because a missing one fails closed
  // (`UNAVAILABLE`, the device enrols DEGRADED and can never be TRUSTED) and a
  // wrong one fails open. There is no shipped default anywhere in this
  // repository for any of them, and the real Google hardware-attestation roots
  // are NOT committed here — a deployment supplies them.
  //
  // A `.default(...)` on any key in this block would be a silent substitution
  // and must never be added. `min(1)` rather than a bare string so that an
  // empty value is a CONFIGURATION ERROR at boot rather than a mystery
  // `UNAVAILABLE` in production.
  //
  // The keys are validated for SHAPE here and for MEANING in
  // `modules/device-enrollment-ingress/android-attestation.configured-trust-material.ts`,
  // which parses every anchor, refuses partial material, and returns
  // "unconfigured" — never a smaller anchor set — when anything is wrong.
  // -------------------------------------------------------------------------
  /**
   * The PINNED trust anchors. One or more certificates, as concatenated PEM
   * blocks or as base64 DER separated by commas or whitespace.
   *
   * A ROOT IS NEVER TRUSTED BECAUSE THE DEVICE SUPPLIED IT. This is where the
   * server's own answer comes from, and the verifier compares against it rather
   * than discovering an anchor in the submitted chain.
   */
  ANDROID_ATTESTATION_TRUST_ANCHORS: z.string().min(1, 'ANDROID_ATTESTATION_TRUST_ANCHORS must not be empty').optional(),
  /** Names the anchor set a verdict was reached against. Recorded on every artifact. */
  ANDROID_ATTESTATION_TRUST_ANCHOR_SET_VERSION: z
    .string()
    .min(1, 'ANDROID_ATTESTATION_TRUST_ANCHOR_SET_VERSION must not be empty')
    .optional(),
  /**
   * Google's certificate status list, verbatim, as JSON:
   * `{"entries": {"<serial>": {"status": "REVOKED", "reason": "KEY_COMPROMISE"}}}`.
   *
   * REQUIRED WHENEVER ANCHORS ARE SUPPLIED. "Not revoked" is a conjunct of
   * VERIFIED, and a deployment that has not looked cannot assert it — anchors
   * with no revocation data is PARTIAL material and stays `UNAVAILABLE`.
   */
  ANDROID_ATTESTATION_REVOCATION_SNAPSHOT: z
    .string()
    .min(1, 'ANDROID_ATTESTATION_REVOCATION_SNAPSHOT must not be empty')
    .optional(),
  ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_VERSION: z
    .string()
    .min(1, 'ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_VERSION must not be empty')
    .optional(),
  /**
   * When the snapshot above was OBTAINED, ISO-8601. Freshness is CHECKED, not
   * assumed: past `ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_MAX_AGE_MS` the
   * material is stale and the verdict is `UNAVAILABLE`, never "assume not
   * revoked". A deployment that pins this to a constant is a deployment that
   * stops being able to say VERIFIED a day later, which is the intended
   * behaviour.
   */
  ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_FETCHED_AT: z
    .string()
    .min(1, 'ANDROID_ATTESTATION_REVOCATION_SNAPSHOT_FETCHED_AT must not be empty')
    .optional(),
  /** The Sentinel Android package the leaf must attest to, e.g. `com.sentinel.field`. */
  ANDROID_ATTESTATION_PACKAGE_NAME: z.string().min(1, 'ANDROID_ATTESTATION_PACKAGE_NAME must not be empty').optional(),
  /**
   * Allowed signing-certificate digests: SHA-256, hex, one or more, separated by
   * commas or whitespace. Any one may match — a release key and an upgrade key
   * are both legitimate identities for one application.
   */
  ANDROID_ATTESTATION_SIGNING_DIGESTS: z
    .string()
    .min(1, 'ANDROID_ATTESTATION_SIGNING_DIGESTS must not be empty')
    .optional(),
  /**
   * C13-01: there is deliberately NO patrol sweep interval key here.
   *
   * MISSED is a server-owned verdict (WP-19 s.3), so the cadence that reaches
   * it must not be something a deployment can set — a configurable interval
   * whose `0` means "stop detecting missed checkpoints" is a production
   * kill-switch over a safety-critical judgement, however well-intentioned the
   * default. The interval is hard-wired in `patrol-missed.sweeper.ts`, and the
   * test-determinism problem that motivated the key is solved instead by a
   * dependency seam (`patrol-sweep.scheduler.ts`) that exists only in test
   * wiring. `modules/patrol/patrol-sweep.scheduler.spec.ts` is the permanent
   * guard that this key stays absent and that the interval stays hard-wired.
   */
});

export type AppConfig = z.infer<typeof envSchema>;

/**
 * Local alias instead of the ambient `NodeJS.ProcessEnv` global type: the
 * repo's shared root ESLint config does not register `NodeJS` as a known
 * global for `no-undef`, and this package must not modify root config.
 */
type EnvRecord = Record<string, string | undefined>;

/**
 * Thrown when environment validation fails. `issues` holds one
 * human-readable line per invalid/missing variable so callers (and
 * tests) can assert on the full list, not just the first failure.
 */
export class ConfigValidationError extends Error {
  public readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super(`Invalid environment configuration:\n${issues.map((issue) => ` - ${issue}`).join('\n')}`);
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

/**
 * Validates `env` against {@link envSchema}. Boot must fail fast, so this
 * throws a {@link ConfigValidationError} listing every missing/invalid
 * variable in one go rather than the first one encountered.
 */
export function loadConfig(env: EnvRecord = process.env): AppConfig {
  const result = envSchema.safeParse(env);
  if (!result.success) {
    throw new ConfigValidationError(formatZodIssues(result.error));
  }
  return result.data;
}
