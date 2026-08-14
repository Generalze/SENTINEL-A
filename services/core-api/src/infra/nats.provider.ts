import { Inject, Injectable, OnModuleDestroy } from '@nestjs/common';
import { connect, type NatsConnection } from 'nats';
import { AppConfigService } from '../config/config.service';
import type { DependencyStatus } from '../health/health.types';

const CONNECT_TIMEOUT_MS = 1500;

/**
 * Thin, lazy wrapper around the `nats` client. No connection is made
 * until something actually needs one (first `getConnection()`/
 * `checkHealth()` call) — this lets the provider be constructed safely
 * in unit tests without a running NATS server.
 */
@Injectable()
export class NatsProvider implements OnModuleDestroy {
  private connection: NatsConnection | undefined;
  private connecting: Promise<NatsConnection> | undefined;

  constructor(@Inject(AppConfigService) private readonly appConfig: AppConfigService) {}

  isConfigured(): boolean {
    return this.appConfig.values.NATS_URL.trim().length > 0;
  }

  async getConnection(): Promise<NatsConnection> {
    if (this.connection && !this.connection.isClosed()) {
      return this.connection;
    }
    if (!this.connecting) {
      this.connecting = connect({
        servers: this.appConfig.values.NATS_URL,
        timeout: CONNECT_TIMEOUT_MS,
      })
        .then((nc) => {
          this.connection = nc;
          return nc;
        })
        .finally(() => {
          this.connecting = undefined;
        });
    }
    return this.connecting;
  }

  async checkHealth(): Promise<DependencyStatus> {
    if (!this.isConfigured()) {
      return 'not_configured';
    }
    try {
      const nc = await this.getConnection();
      return nc.isClosed() ? 'down' : 'up';
    } catch {
      return 'down';
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (this.connection && !this.connection.isClosed()) {
      await this.connection.close();
    }
  }
}
