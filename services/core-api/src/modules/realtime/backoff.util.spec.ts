import { describe, expect, it, vi } from 'vitest';
import { computeBackoffDelayMs, withRetryBackoff, type BackoffOptions } from './backoff.util';

describe('computeBackoffDelayMs', () => {
  const options: BackoffOptions = { baseMs: 500, maxMs: 30_000, factor: 2 };

  it('doubles each attempt (exponential) starting from baseMs', () => {
    expect(computeBackoffDelayMs(1, options)).toBe(500);
    expect(computeBackoffDelayMs(2, options)).toBe(1000);
    expect(computeBackoffDelayMs(3, options)).toBe(2000);
    expect(computeBackoffDelayMs(4, options)).toBe(4000);
    expect(computeBackoffDelayMs(5, options)).toBe(8000);
  });

  it('caps at maxMs', () => {
    expect(computeBackoffDelayMs(10, options)).toBe(30_000);
    expect(computeBackoffDelayMs(50, options)).toBe(30_000);
  });

  it('uses DEFAULT_BACKOFF_OPTIONS when none are supplied', () => {
    expect(computeBackoffDelayMs(1)).toBe(500);
  });

  it('rejects a non-positive attempt number', () => {
    expect(() => computeBackoffDelayMs(0)).toThrow(RangeError);
    expect(() => computeBackoffDelayMs(-1)).toThrow(RangeError);
  });
});

describe('withRetryBackoff', () => {
  it('resolves immediately when the first attempt succeeds, without sleeping', async () => {
    const sleep = vi.fn().mockResolvedValue(undefined);
    const attempt = vi.fn().mockResolvedValue('ok');
    const onAttemptError = vi.fn();

    const result = await withRetryBackoff({ attempt, isStopped: () => false, onAttemptError, sleep });

    expect(result).toBe('ok');
    expect(attempt).toHaveBeenCalledTimes(1);
    expect(sleep).not.toHaveBeenCalled();
    expect(onAttemptError).not.toHaveBeenCalled();
  });

  it('retries with exponential backoff delays until an attempt succeeds', async () => {
    const sleep = vi.fn().mockResolvedValue(undefined);
    const attempt = vi
      .fn()
      .mockRejectedValueOnce(new Error('fail-1'))
      .mockRejectedValueOnce(new Error('fail-2'))
      .mockResolvedValueOnce('ok');
    const onAttemptError = vi.fn();

    const result = await withRetryBackoff({
      attempt,
      isStopped: () => false,
      onAttemptError,
      sleep,
      options: { baseMs: 10, maxMs: 1000, factor: 2 },
    });

    expect(result).toBe('ok');
    expect(attempt).toHaveBeenCalledTimes(3);
    expect(sleep).toHaveBeenCalledTimes(2);
    expect(sleep.mock.calls[0]?.[0]).toBe(10);
    expect(sleep.mock.calls[1]?.[0]).toBe(20);
    expect(onAttemptError).toHaveBeenCalledTimes(2);
    expect(onAttemptError.mock.calls[0]?.[1]).toBe(1); // attemptNumber
    expect(onAttemptError.mock.calls[1]?.[1]).toBe(2);
  });

  it('never crashes the caller: a persistently failing attempt just keeps retrying (never rejects)', async () => {
    let calls = 0;
    const sleep = vi.fn().mockResolvedValue(undefined);
    const attempt = vi.fn().mockImplementation(() => {
      calls += 1;
      return Promise.reject(new Error(`fail-${calls}`));
    });
    let stop = false;

    const promise = withRetryBackoff({
      attempt,
      isStopped: () => stop,
      onAttemptError: () => {
        if (calls >= 5) {
          stop = true;
        }
      },
      sleep,
      options: { baseMs: 1, maxMs: 5, factor: 1 },
    });

    await expect(promise).resolves.toBeUndefined();
    expect(calls).toBe(5);
  });

  it('stops without one extra attempt when isStopped flips true during a backoff sleep', async () => {
    let stop = false;
    const attempt = vi.fn().mockRejectedValue(new Error('down'));
    const sleep = vi.fn().mockImplementation(() => {
      stop = true; // simulate onModuleDestroy firing while we're waiting out the backoff
      return Promise.resolve();
    });

    const result = await withRetryBackoff({
      attempt,
      isStopped: () => stop,
      onAttemptError: () => undefined,
      sleep,
      options: { baseMs: 1, maxMs: 5, factor: 1 },
    });

    expect(result).toBeUndefined();
    expect(attempt).toHaveBeenCalledTimes(1);
  });

  it('does not attempt at all when already stopped', async () => {
    const attempt = vi.fn();
    const result = await withRetryBackoff({ attempt, isStopped: () => true, onAttemptError: () => undefined });
    expect(result).toBeUndefined();
    expect(attempt).not.toHaveBeenCalled();
  });
});
