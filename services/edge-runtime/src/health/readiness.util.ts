import { EDGE_READINESS_PROBE_TIMEOUT_MS } from '../edge-runtime.constants';
import type { DependencyStatus } from './health.types';

class ProbeTimeoutError extends Error {
  constructor(ms: number) {
    super(`Probe timed out after ${ms}ms`);
    this.name = 'ProbeTimeoutError';
  }
}

/**
 * Races `promise` against a timer so a hanging dependency can never make the
 * readiness endpoint hang. An Edge whose readiness stalls is indistinguishable
 * from an Edge that is gone, and the two need very different responses from
 * whoever is looking.
 *
 * Timers are reached through `globalThis` so this file does not depend on the
 * shared root ESLint config's globals list, which it must not modify.
 */
export function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = globalThis.setTimeout(() => reject(new ProbeTimeoutError(ms)), ms);
    if (typeof timer.unref === 'function') timer.unref();
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
 * Runs one probe with a hard deadline. Every rejection — a thrown error, a
 * timeout, a probe that returns something nonsensical — is reported honestly as
 * `down`. THIS NEVER THROWS, and that is the load-bearing property: a readiness
 * endpoint that can 500 gives an operator no information at all about which
 * dependency is unhappy.
 */
export async function guardedProbe(
  fn: () => Promise<DependencyStatus>,
  ms: number = EDGE_READINESS_PROBE_TIMEOUT_MS,
): Promise<DependencyStatus> {
  try {
    return await withTimeout(fn(), ms);
  } catch {
    return 'down';
  }
}

/**
 * Pure aggregation. `not_configured` is neutral — a dependency this deployment
 * does not have must never by itself hold an Edge out of service.
 */
export function computeReadinessStatus(dependencies: Readonly<Record<string, DependencyStatus>>): 'ok' | 'degraded' {
  return Object.values(dependencies).some((value) => value === 'down') ? 'degraded' : 'ok';
}

export function statusToHttpCode(status: 'ok' | 'degraded'): 200 | 503 {
  return status === 'ok' ? 200 : 503;
}
