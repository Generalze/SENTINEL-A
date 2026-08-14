import { describe, expect, it } from 'vitest';
import {
  computeReadinessStatus,
  guardedProbe,
  statusToHttpCode,
  withTimeout,
} from './readiness.util';
import type { ReadinessDependencies } from './health.types';

describe('computeReadinessStatus', () => {
  it('is ok when every dependency is up', () => {
    const deps: ReadinessDependencies = { database: 'up', nats: 'up', redis: 'up' };
    expect(computeReadinessStatus(deps)).toBe('ok');
  });

  it('is degraded when any dependency is down', () => {
    const deps: ReadinessDependencies = { database: 'up', nats: 'up', redis: 'down' };
    expect(computeReadinessStatus(deps)).toBe('degraded');
  });

  it('is degraded when all dependencies are down', () => {
    const deps: ReadinessDependencies = { database: 'down', nats: 'down', redis: 'down' };
    expect(computeReadinessStatus(deps)).toBe('degraded');
  });

  it('treats not_configured as neutral, not as a failure', () => {
    const deps: ReadinessDependencies = { database: 'up', nats: 'not_configured', redis: 'up' };
    expect(computeReadinessStatus(deps)).toBe('ok');
  });

  it('is degraded when a real dependency is down even alongside not_configured ones', () => {
    const deps: ReadinessDependencies = { database: 'down', nats: 'not_configured', redis: 'up' };
    expect(computeReadinessStatus(deps)).toBe('degraded');
  });
});

describe('statusToHttpCode', () => {
  it('maps ok to 200', () => {
    expect(statusToHttpCode('ok')).toBe(200);
  });

  it('maps degraded to 503', () => {
    expect(statusToHttpCode('degraded')).toBe(503);
  });
});

describe('withTimeout', () => {
  it('resolves with the underlying value when it settles before the deadline', async () => {
    await expect(withTimeout(Promise.resolve('fast'), 200)).resolves.toBe('fast');
  });

  it('rejects when the underlying promise never settles before the deadline', async () => {
    const neverResolves = new Promise<string>(() => {
      /* intentionally never settles */
    });
    await expect(withTimeout(neverResolves, 30)).rejects.toThrow(/timed out/i);
  });

  it('propagates rejection from the underlying promise', async () => {
    await expect(withTimeout(Promise.reject(new Error('boom')), 200)).rejects.toThrow('boom');
  });
});

describe('guardedProbe', () => {
  it('never throws: a timeout becomes down', async () => {
    const hanging = () => new Promise<'up'>(() => {});
    await expect(guardedProbe(hanging, 30)).resolves.toBe('down');
  });

  it('never throws: a rejection becomes down', async () => {
    const failing = () => Promise.reject(new Error('connection refused'));
    await expect(guardedProbe(failing, 200)).resolves.toBe('down');
  });

  it('passes through a resolved status unchanged', async () => {
    await expect(guardedProbe(() => Promise.resolve('not_configured'), 200)).resolves.toBe(
      'not_configured',
    );
  });
});
