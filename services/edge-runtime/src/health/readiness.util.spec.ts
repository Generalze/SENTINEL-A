import { describe, expect, it, vi } from 'vitest';
import { computeReadinessStatus, guardedProbe, statusToHttpCode, withTimeout } from './readiness.util';
import { EdgeHealthService, EDGE_READINESS_PROBES } from './health.service';
import type { DependencyStatus, EdgeReadinessProbe } from './health.types';

function probe(name: string, behaviour: DependencyStatus | 'throw' | 'hang'): EdgeReadinessProbe {
  return {
    name,
    check: () => {
      if (behaviour === 'throw') return Promise.reject(new Error('connection refused'));
      if (behaviour === 'hang') return new Promise<DependencyStatus>(() => {});
      return Promise.resolve(behaviour);
    },
  };
}

describe('computeReadinessStatus', () => {
  it('is ok when everything is up', () => {
    expect(computeReadinessStatus({ queue_storage: 'up' })).toBe('ok');
  });

  it('is ok with no dependencies at all', () => {
    expect(computeReadinessStatus({})).toBe('ok');
  });

  it('is degraded when any dependency is down', () => {
    expect(computeReadinessStatus({ queue_storage: 'down', other: 'up' })).toBe('degraded');
  });

  it('treats not_configured as neutral', () => {
    // A dependency this deployment does not have must never by itself hold an
    // Edge out of service.
    expect(computeReadinessStatus({ queue_storage: 'up', other: 'not_configured' })).toBe('ok');
  });
});

describe('statusToHttpCode', () => {
  it('maps ok to 200 and degraded to 503', () => {
    expect(statusToHttpCode('ok')).toBe(200);
    expect(statusToHttpCode('degraded')).toBe(503);
  });
});

describe('withTimeout', () => {
  it('resolves when the underlying promise settles first', async () => {
    await expect(withTimeout(Promise.resolve('fast'), 200)).resolves.toBe('fast');
  });

  it('rejects when the underlying promise never settles', async () => {
    await expect(withTimeout(new Promise<string>(() => {}), 30)).rejects.toThrow(/timed out/i);
  });

  it('propagates the underlying rejection', async () => {
    await expect(withTimeout(Promise.reject(new Error('boom')), 200)).rejects.toThrow('boom');
  });
});

describe('guardedProbe never throws', () => {
  it('turns a hang into down within the deadline', async () => {
    await expect(guardedProbe(() => new Promise<DependencyStatus>(() => {}), 30)).resolves.toBe('down');
  });

  it('turns a rejection into down', async () => {
    await expect(guardedProbe(() => Promise.reject(new Error('nope')), 200)).resolves.toBe('down');
  });

  it('passes a resolved status through unchanged', async () => {
    await expect(guardedProbe(() => Promise.resolve('not_configured'), 200)).resolves.toBe('not_configured');
  });
});

describe('EdgeHealthService', () => {
  it('reports every registered probe honestly', async () => {
    const service = new EdgeHealthService([probe('queue_storage', 'up'), probe('other', 'down')]);
    await expect(service.checkReadiness()).resolves.toEqual({
      status: 'degraded',
      dependencies: { queue_storage: 'up', other: 'down' },
    });
  });

  it('reports a throwing probe as down rather than failing the endpoint', async () => {
    // The load-bearing property: a readiness endpoint that can 500 tells an
    // operator nothing about WHICH dependency is unhappy.
    const service = new EdgeHealthService([probe('queue_storage', 'throw')]);
    await expect(service.checkReadiness()).resolves.toEqual({
      status: 'degraded',
      dependencies: { queue_storage: 'down' },
    });
  });

  it('never hangs on a stalled probe', async () => {
    const service = new EdgeHealthService([probe('queue_storage', 'hang')]);
    const started = Date.now();
    const result = await service.checkReadiness();
    expect(result.dependencies.queue_storage).toBe('down');
    expect(Date.now() - started).toBeLessThan(3_000);
  }, 5_000);

  it('is ok with no probes registered, because Edge has no remote dependency to be ready for', async () => {
    // Central being unreachable is Edge's reason to exist, not a readiness
    // failure — an Edge taken out of service the moment the WAN drops is an
    // Edge that fails at exactly the moment the site depends on it.
    const service = new EdgeHealthService(null);
    await expect(service.checkReadiness()).resolves.toEqual({ status: 'ok', dependencies: {} });
  });

  it('discloses nothing but dependency names and up/down', async () => {
    // Edge is on a customer LAN; this endpoint is reachable by anything on it.
    const service = new EdgeHealthService([probe('queue_storage', 'up')]);
    const result = await service.checkReadiness();
    expect(Object.keys(result)).toEqual(['status', 'dependencies']);
    for (const value of Object.values(result.dependencies)) {
      expect(['up', 'down', 'not_configured']).toContain(value);
    }
  });

  it('exposes its multi-provider token so a lane can register a probe beside its dependency', () => {
    expect(typeof EDGE_READINESS_PROBES).toBe('symbol');
    expect(vi.isMockFunction(EDGE_READINESS_PROBES)).toBe(false);
  });
});
