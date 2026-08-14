/**
 * Deliverable #5: resilience for the NATS subscription bridge. Pure,
 * synchronous backoff math (`computeBackoffDelayMs`) plus a small
 * generic retry-loop runner (`withRetryBackoff`) that takes its `sleep`
 * function as a parameter — this is what makes the retry/backoff logic
 * unit-testable without real timers (see `backoff.util.spec.ts` and
 * `realtime-nats-bridge.service.spec.ts`).
 */

export interface BackoffOptions {
  readonly baseMs: number;
  readonly maxMs: number;
  readonly factor: number;
}

export const DEFAULT_BACKOFF_OPTIONS: BackoffOptions = {
  baseMs: 500,
  maxMs: 30_000,
  factor: 2,
};

export type SleepFn = (ms: number) => Promise<void>;

export const defaultSleep: SleepFn = (ms) =>
  new Promise((resolve) => {
    // Referenced via `globalThis` rather than the bare identifier because
    // this repo's shared root ESLint config does not register timer
    // globals for `no-undef` — see events/events-publish-sweep.service.ts
    // for the same pattern.
    globalThis.setTimeout(resolve, ms);
  });

/**
 * Exponential backoff, capped at `options.maxMs`. `attempt` is 1-based and
 * is the number of the attempt that just failed — the returned value is
 * how long to wait before the next one.
 */
export function computeBackoffDelayMs(attempt: number, options: BackoffOptions = DEFAULT_BACKOFF_OPTIONS): number {
  if (attempt < 1) {
    throw new RangeError('attempt must be >= 1');
  }
  const raw = options.baseMs * options.factor ** (attempt - 1);
  return Math.min(raw, options.maxMs);
}

export interface RetryBackoffParams<T> {
  /** Performs one attempt. Rejecting triggers a backoff + retry. */
  readonly attempt: () => Promise<T>;
  /** Checked before the first attempt and after every failure; a `true` stops the loop without retrying. */
  readonly isStopped: () => boolean;
  readonly onAttemptError: (error: unknown, attemptNumber: number, delayMs: number) => void;
  readonly sleep?: SleepFn;
  readonly options?: BackoffOptions;
}

/**
 * Retries `attempt()` with exponential backoff until it succeeds or
 * `isStopped()` becomes true. Never throws — a shutdown mid-backoff
 * resolves `undefined` instead of attempting once more or rejecting.
 */
export async function withRetryBackoff<T>(params: RetryBackoffParams<T>): Promise<T | undefined> {
  const sleep = params.sleep ?? defaultSleep;
  let attemptNumber = 0;
  while (!params.isStopped()) {
    attemptNumber += 1;
    try {
      return await params.attempt();
    } catch (error) {
      if (params.isStopped()) {
        return undefined;
      }
      const delayMs = computeBackoffDelayMs(attemptNumber, params.options);
      params.onAttemptError(error, attemptNumber, delayMs);
      await sleep(delayMs);
    }
  }
  return undefined;
}
