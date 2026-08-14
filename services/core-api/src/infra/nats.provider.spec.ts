import { describe, expect, it } from 'vitest';
import { NatsProvider } from './nats.provider';
import type { AppConfigService } from '../config/config.service';

function fakeConfig(natsUrl: string): AppConfigService {
  return { values: { NATS_URL: natsUrl } } as unknown as AppConfigService;
}

describe('NatsProvider', () => {
  it('reports not_configured and never touches the network when NATS_URL is blank', async () => {
    const provider = new NatsProvider(fakeConfig(''));

    expect(provider.isConfigured()).toBe(false);
    await expect(provider.checkHealth()).resolves.toBe('not_configured');
  });

  it('is configured when NATS_URL is set', () => {
    const provider = new NatsProvider(fakeConfig('nats://localhost:4222'));
    expect(provider.isConfigured()).toBe(true);
  });

  it(
    'reports down (never throws) when the configured server is unreachable',
    async () => {
      const provider = new NatsProvider(fakeConfig('nats://127.0.0.1:4'));
      await expect(provider.checkHealth()).resolves.toBe('down');
    },
    10_000,
  );
});
