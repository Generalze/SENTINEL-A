import type { DependencyStatus, ReadinessDependencies } from './health.types';

export const PROBE_TIMEOUT_MS = 1500;

class ProbeTimeoutError extends Error {
  constructor(ms: number) {
    super(`Probe timed out after ${ms}ms`);
    this.name = 'ProbeTimeoutError';
  }
}

/**
 * Races `promise` against a timer so a slow/hanging dependency can never
 * make the readiness endpoint hang.
 */
export function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    // Referenced off globalThis (an ES2020 language builtin, unlike
    // setTimeout/clearTimeout themselves) since this package's shared
    // root ESLint config does not list setTimeout/clearTimeout as known
    // globals and must not be modified from here.
    const timer = globalThis.setTimeout(() => reject(new ProbeTimeoutError(ms)), ms);
    if (typeof timer.unref === 'function') {
      timer.unref();
    }
    promise.then(
      (value) => {
        globalThis.clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        globalThis.clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

/**
 * Runs a single dependency probe with a hard deadline. Any rejection
 * (network error, timeout) is honestly reported as 'down' — this never
 * throws.
 */
export async function guardedProbe(
  fn: () => Promise<DependencyStatus>,
  ms: number = PROBE_TIMEOUT_MS,
): Promise<DependencyStatus> {
  try {
    return await withTimeout(fn(), ms);
  } catch {
    return 'down';
  }
}

/**
 * Pure aggregation: overall readiness is 'degraded' if any dependency is
 * down. A 'not_configured' dependency is treated as neutral (it is not
 * part of this deployment) and never forces a degraded state by itself.
 */
export function computeReadinessStatus(dependencies: ReadinessDependencies): 'ok' | 'degraded' {
  const isDown = (value: DependencyStatus): boolean => value === 'down';
  return Object.values(dependencies).some(isDown) ? 'degraded' : 'ok';
}

export function statusToHttpCode(status: 'ok' | 'degraded'): 200 | 503 {
  return status === 'ok' ? 200 : 503;
}
