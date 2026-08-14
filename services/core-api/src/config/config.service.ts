import { Injectable } from '@nestjs/common';
import { loadConfig, type AppConfig } from './env.schema';

/**
 * Validates process.env exactly once at construction time (via zod) and
 * exposes the typed, immutable result. Because this is instantiated by
 * Nest's DI container during application bootstrap, a validation failure
 * here propagates out of `NestFactory.create(...)` and aborts boot before
 * any HTTP listener starts — satisfying "fail fast" for bad config.
 */
@Injectable()
export class AppConfigService {
  public readonly values: AppConfig;

  constructor() {
    this.values = loadConfig();
  }
}
