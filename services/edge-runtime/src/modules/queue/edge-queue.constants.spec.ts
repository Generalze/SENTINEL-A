import { describe, expect, it } from 'vitest';
import { MAX_OFFLINE_DEVICE_SEQUENCE } from '@sentinel/contracts';
import {
  EDGE_QUEUE_DEGRADED_FRACTION,
  EDGE_QUEUE_MAX_MONOTONIC_POSITION,
  EDGE_QUEUE_MAX_UNSETTLED,
  EDGE_QUEUE_RETRY_BASE_DELAY_MS,
  EDGE_QUEUE_RETRY_MAX_DELAY_MS,
  EDGE_QUEUE_SETTLED_RETENTION,
  edgeQueueRetryDelayMs,
} from './edge-queue.constants';

/**
 * The arithmetic, settled here rather than discovered on a bad night.
 *
 * `RetrySchedule` on the Android side makes the same argument: everything about
 * a backoff that can be WRONG — an overflow at attempt 60, a ceiling that is not
 * a ceiling, a delay that goes backwards — is arithmetic, and arithmetic is what
 * a unit test can settle.
 */
describe('edge queue backoff', () => {
  it('does not delay an attempt that has never been made', () => {
    expect(edgeQueueRetryDelayMs(0)).toBe(0);
    expect(edgeQueueRetryDelayMs(-1)).toBe(0);
  });

  it('doubles from the base delay', () => {
    expect(edgeQueueRetryDelayMs(1)).toBe(EDGE_QUEUE_RETRY_BASE_DELAY_MS);
    expect(edgeQueueRetryDelayMs(2)).toBe(EDGE_QUEUE_RETRY_BASE_DELAY_MS * 2);
    expect(edgeQueueRetryDelayMs(3)).toBe(EDGE_QUEUE_RETRY_BASE_DELAY_MS * 4);
  });

  it('never decreases, and never exceeds the ceiling, at any attempt count', () => {
    let previous = 0;
    for (let attempt = 1; attempt <= 200; attempt += 1) {
      const delay = edgeQueueRetryDelayMs(attempt);
      expect(Number.isFinite(delay)).toBe(true);
      expect(delay).toBeGreaterThanOrEqual(previous);
      expect(delay).toBeLessThanOrEqual(EDGE_QUEUE_RETRY_MAX_DELAY_MS);
      previous = delay;
    }
  });

  /**
   * THE CEILING IS ON THE DELAY, NOT ON THE NUMBER OF ATTEMPTS.
   *
   * A cap on attempts would eventually DISCARD an operation an operative
   * actually performed, because a network stayed down longer than somebody
   * guessed. The delay saturates; the operation does not expire. Only central
   * ends a queued operation, and it ends it by answering.
   */
  it('saturates rather than ever answering "stop trying"', () => {
    expect(edgeQueueRetryDelayMs(1_000_000)).toBe(EDGE_QUEUE_RETRY_MAX_DELAY_MS);
  });
});

describe('edge queue bounds', () => {
  it('degrades before it refuses, so saturation is visible while it can still be acted on', () => {
    expect(EDGE_QUEUE_DEGRADED_FRACTION).toBeGreaterThan(0);
    expect(EDGE_QUEUE_DEGRADED_FRACTION).toBeLessThan(1);
    expect(Math.floor(EDGE_QUEUE_MAX_UNSETTLED * EDGE_QUEUE_DEGRADED_FRACTION)).toBeLessThan(EDGE_QUEUE_MAX_UNSETTLED);
  });

  /**
   * The SQL CHECK cannot import, so the ceiling is repeated as a literal. This
   * is what stops the copy drifting: a queue that could record a position the
   * frozen receipt schema then refuses to carry would produce entries Edge
   * cannot witness for, discovered at witness time rather than at enqueue.
   */
  it('shares the frozen receipt ceiling, so no position can be recorded that a receipt cannot carry', () => {
    expect(EDGE_QUEUE_MAX_MONOTONIC_POSITION).toBe(MAX_OFFLINE_DEVICE_SEQUENCE);
  });

  it('bounds both what is unresolved and what is retained, so neither grows without limit', () => {
    expect(EDGE_QUEUE_MAX_UNSETTLED).toBeGreaterThan(0);
    expect(EDGE_QUEUE_SETTLED_RETENTION).toBeGreaterThan(0);
  });
});
