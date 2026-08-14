import { describe, expect, it, vi } from 'vitest';
import { HealthService } from './health.service';
import type { PrismaService } from '../prisma/prisma.service';
import type { NatsProvider } from '../infra/nats.provider';
import type { RedisProvider } from '../infra/redis.provider';

function makePrisma(behaviour: 'up' | 'down' | 'hang'): PrismaService {
  const queryRaw =
    behaviour === 'up'
      ? vi.fn(() => Promise.resolve([{ '?column?': 1 }]))
      : behaviour === 'down'
        ? vi.fn(() => Promise.reject(new Error('connection refused')))
        : vi.fn(() => new Promise(() => {}));
  return { $queryRaw: queryRaw } as unknown as PrismaService;
}

function makeNats(status: 'up' | 'down' | 'not_configured'): NatsProvider {
  return { checkHealth: vi.fn(() => Promise.resolve(status)) } as unknown as NatsProvider;
}

function makeRedis(status: 'up' | 'down' | 'not_configured'): RedisProvider {
  return { checkHealth: vi.fn(() => Promise.resolve(status)) } as unknown as RedisProvider;
}

describe('HealthService.checkReadiness', () => {
  it('reports ok/200-worthy status when every dependency is up', async () => {
    const service = new HealthService(makePrisma('up'), makeNats('up'), makeRedis('up'));
    const result = await service.checkReadiness();

    expect(result).toEqual({
      status: 'ok',
      dependencies: { database: 'up', nats: 'up', redis: 'up' },
    });
  });

  it('reports degraded when redis is down and leaves the others honestly reported', async () => {
    const service = new HealthService(makePrisma('up'), makeNats('up'), makeRedis('down'));
    const result = await service.checkReadiness();

    expect(result).toEqual({
      status: 'degraded',
      dependencies: { database: 'up', nats: 'up', redis: 'down' },
    });
  });

  it('reports database down when the SELECT 1 probe rejects', async () => {
    const service = new HealthService(makePrisma('down'), makeNats('up'), makeRedis('up'));
    const result = await service.checkReadiness();

    expect(result.status).toBe('degraded');
    expect(result.dependencies.database).toBe('down');
  });

  it(
    'never hangs: a stalled database probe is reported down within the probe deadline',
    async () => {
      const service = new HealthService(makePrisma('hang'), makeNats('up'), makeRedis('up'));
      const start = Date.now();
      const result = await service.checkReadiness();
      const elapsed = Date.now() - start;

      expect(result.dependencies.database).toBe('down');
      expect(result.status).toBe('degraded');
      // Bounded by the ~1.5s per-probe timeout, with generous slack for CI jitter.
      expect(elapsed).toBeLessThan(3000);
    },
    5000,
  );
});
