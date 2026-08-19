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
  /**
   * WP-22/W22-02: the patrol missed-sweep cadence, in milliseconds.
   *
   * The sweep decides MISSED by the clock alone, so it must keep running in
   * production — but a BACKGROUND timer firing on its own schedule made the
   * WP-19 integration suite's correctness depend on lucky timing: a sweep
   * landing between a test's own actions changed counts the test was about to
   * assert. That is a scheduler problem, not a patrol-semantics problem.
   *
   * `0` disables the background cadence entirely, leaving `sweep()` callable
   * explicitly. Tests set it to 0 and drive the sweep themselves, so what they
   * assert is what they caused. The sweep logic itself is untouched.
   */
  PATROL_SWEEP_INTERVAL_MS: z.coerce
    .number()
    .int('PATROL_SWEEP_INTERVAL_MS must be an integer')
    .nonnegative('PATROL_SWEEP_INTERVAL_MS must not be negative')
    .default(5000),
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
