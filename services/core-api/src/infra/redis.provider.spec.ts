import { describe, expect, it } from 'vitest';
import { RedisProvider } from './redis.provider';
import type { AppConfigService } from '../config/config.service';

function fakeConfig(redisUrl: string): AppConfigService {
  return { values: { REDIS_URL: redisUrl } } as unknown as AppConfigService;
}

describe('RedisProvider', () => {
  it('reports not_configured and never touches the network when REDIS_URL is blank', async () => {
    const provider = new RedisProvider(fakeConfig(''));

    expect(provider.isConfigured()).toBe(false);
    await expect(provider.checkHealth()).resolves.toBe('not_configured');

    provider.onModuleDestroy();
  });

  it('is configured when REDIS_URL is set', () => {
    const provider = new RedisProvider(fakeConfig('redis://localhost:6379'));
    expect(provider.isConfigured()).toBe(true);
    provider.onModuleDestroy();
  });

  it(
    'reports down (never throws) when the configured server is unreachable',
    async () => {
      const provider = new RedisProvider(fakeConfig('redis://127.0.0.1:4'));
      await expect(provider.checkHealth()).resolves.toBe('down');
      provider.onModuleDestroy();
    },
    10_000,
  );
});
