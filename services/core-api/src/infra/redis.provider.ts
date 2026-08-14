import { Inject, Injectable, OnModuleDestroy } from '@nestjs/common';
import Redis from 'ioredis';
import { AppConfigService } from '../config/config.service';
import type { DependencyStatus } from '../health/health.types';

const CONNECT_TIMEOUT_MS = 1500;

/**
 * Thin, lazy wrapper around ioredis. `lazyConnect` defers the initial
 * TCP connection until the first command, so constructing this provider
 * in a unit test never touches the network. A no-op error listener is
 * required so ioredis's background reconnect attempts (e.g. while Redis
 * is down) don't crash the process via an unhandled 'error' event.
 */
@Injectable()
export class RedisProvider implements OnModuleDestroy {
  private client: Redis | undefined;

  constructor(@Inject(AppConfigService) private readonly appConfig: AppConfigService) {}

  isConfigured(): boolean {
    return this.appConfig.values.REDIS_URL.trim().length > 0;
  }

  private getClient(): Redis {
    if (!this.client) {
      this.client = new Redis(this.appConfig.values.REDIS_URL, {
        lazyConnect: true,
        maxRetriesPerRequest: 1,
        connectTimeout: CONNECT_TIMEOUT_MS,
      });
      this.client.on('error', () => {
        // Swallowed intentionally: connectivity is surfaced via checkHealth().
      });
    }
    return this.client;
  }

  async checkHealth(): Promise<DependencyStatus> {
    if (!this.isConfigured()) {
      return 'not_configured';
    }
    try {
      const result = await this.getClient().ping();
      return result === 'PONG' ? 'up' : 'down';
    } catch {
      return 'down';
    }
  }

  onModuleDestroy(): void {
    if (this.client) {
      this.client.disconnect();
    }
  }
}
