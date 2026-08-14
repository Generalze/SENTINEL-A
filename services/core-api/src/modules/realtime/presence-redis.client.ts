import { Inject, Injectable, Logger, type OnModuleDestroy } from '@nestjs/common';
import Redis from 'ioredis';
import { AppConfigService } from '../../config/config.service';

const CONNECT_TIMEOUT_MS = 1500;

/**
 * TODO-WIRED(lead): `src/infra/redis.provider.ts` only exposes
 * `isConfigured()`/`checkHealth()` today — no consumer needed raw Redis
 * commands before this module. Per WP-12 coordination rules this module's
 * lane is `src/modules/realtime/**` only (infra/** is out of lane while
 * three other agents work concurrently in this tree), so rather than
 * editing `RedisProvider` to add a public client accessor, this is a
 * small local client that mirrors its exact connection posture —
 * `lazyConnect` (no network touched until the first command) and a
 * no-op-ish (logged, not thrown) `error` listener so ioredis's background
 * reconnect attempts never crash the process. The lead can fold this into
 * `RedisProvider` (e.g. a `getClient()` accessor) once the concurrent
 * build settles; nothing else in this module would need to change.
 */
@Injectable()
export class PresenceRedisClient implements OnModuleDestroy {
  private readonly logger = new Logger(PresenceRedisClient.name);
  private client: Redis | undefined;

  constructor(@Inject(AppConfigService) private readonly appConfig: AppConfigService) {}

  isConfigured(): boolean {
    return this.appConfig.values.REDIS_URL.trim().length > 0;
  }

  getClient(): Redis {
    if (!this.client) {
      this.client = new Redis(this.appConfig.values.REDIS_URL, {
        lazyConnect: true,
        maxRetriesPerRequest: 1,
        connectTimeout: CONNECT_TIMEOUT_MS,
      });
      this.client.on('error', (error: Error) => {
        // Deliverable #5: presence must degrade gracefully, never crash
        // the gateway. Actual command failures are handled (and logged)
        // at the call site in presence.service.ts; this listener exists
        // only so ioredis's own background reconnect churn can't produce
        // an unhandled 'error' event.
        this.logger.warn(`presence redis client error (degrading gracefully): ${error.message}`);
      });
    }
    return this.client;
  }

  onModuleDestroy(): void {
    this.client?.disconnect();
  }
}
