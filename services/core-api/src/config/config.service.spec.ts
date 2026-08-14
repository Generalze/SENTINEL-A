import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { AppConfigService } from './config.service';
import { ConfigValidationError } from './env.schema';

const REQUIRED_KEYS = [
  'DATABASE_URL',
  'NATS_URL',
  'REDIS_URL',
  'S3_ENDPOINT',
  'S3_ACCESS_KEY',
  'S3_SECRET_KEY',
  'S3_BUCKET',
] as const;

const validValues: Record<(typeof REQUIRED_KEYS)[number], string> = {
  DATABASE_URL: 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
  NATS_URL: 'nats://localhost:4222',
  REDIS_URL: 'redis://localhost:6379',
  S3_ENDPOINT: 'http://localhost:9000',
  S3_ACCESS_KEY: 'sentinel',
  S3_SECRET_KEY: 'sentinel123',
  S3_BUCKET: 'sentinel-dev',
};

describe('AppConfigService', () => {
  let originalEnv: typeof process.env;

  beforeEach(() => {
    originalEnv = { ...process.env };
    for (const key of REQUIRED_KEYS) {
      process.env[key] = validValues[key];
    }
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('reads process.env by default and exposes typed values', () => {
    const service = new AppConfigService();
    expect(service.values.DATABASE_URL).toBe(validValues.DATABASE_URL);
    expect(service.values.PORT).toBe(3000);
  });

  it('throws ConfigValidationError listing the missing variable when boot config is incomplete', () => {
    delete process.env.DATABASE_URL;
    expect(() => new AppConfigService()).toThrow(ConfigValidationError);
    try {
      new AppConfigService();
    } catch (error) {
      expect((error as ConfigValidationError).message).toContain('DATABASE_URL');
    }
  });
});
