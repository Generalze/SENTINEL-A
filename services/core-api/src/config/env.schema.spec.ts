import { describe, expect, it } from 'vitest';
import { ConfigValidationError, loadConfig } from './env.schema';

const validEnv = {
  DATABASE_URL: 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
  NATS_URL: 'nats://localhost:4222',
  REDIS_URL: 'redis://localhost:6379',
  S3_ENDPOINT: 'http://localhost:9000',
  S3_ACCESS_KEY: 'sentinel',
  S3_SECRET_KEY: 'sentinel123',
  S3_BUCKET: 'sentinel-dev',
};

describe('loadConfig', () => {
  it('parses a fully valid environment and applies defaults', () => {
    const config = loadConfig(validEnv);

    expect(config.DATABASE_URL).toBe(validEnv.DATABASE_URL);
    expect(config.NATS_URL).toBe(validEnv.NATS_URL);
    expect(config.REDIS_URL).toBe(validEnv.REDIS_URL);
    expect(config.S3_ENDPOINT).toBe(validEnv.S3_ENDPOINT);
    expect(config.S3_REGION).toBe('us-east-1');
    expect(config.PORT).toBe(3000);
    expect(config.LOG_LEVEL).toBe('info');
    expect(config.DEV_AUTH_ENABLED).toBe(false);
  });

  it('respects explicit overrides for defaulted variables', () => {
    const config = loadConfig({
      ...validEnv,
      PORT: '4100',
      LOG_LEVEL: 'debug',
      DEV_AUTH_ENABLED: 'true',
      S3_REGION: 'eu-west-1',
    });

    expect(config.PORT).toBe(4100);
    expect(config.LOG_LEVEL).toBe('debug');
    expect(config.DEV_AUTH_ENABLED).toBe(true);
    expect(config.S3_REGION).toBe('eu-west-1');
  });

  it.each(['false', 'FALSE', '0'])('coerces %s to boolean false for DEV_AUTH_ENABLED', (raw) => {
    const config = loadConfig({ ...validEnv, DEV_AUTH_ENABLED: raw });
    expect(config.DEV_AUTH_ENABLED).toBe(false);
  });

  it.each(['true', 'TRUE', '1'])('coerces %s to boolean true for DEV_AUTH_ENABLED', (raw) => {
    const config = loadConfig({ ...validEnv, DEV_AUTH_ENABLED: raw });
    expect(config.DEV_AUTH_ENABLED).toBe(true);
  });

  it('throws a ConfigValidationError when a required variable is missing', () => {
    const rest: Partial<typeof validEnv> = { ...validEnv };
    delete rest.DATABASE_URL;
    expect(() => loadConfig(rest)).toThrow(ConfigValidationError);
  });

  it('lists every missing/invalid variable in one error, not just the first', () => {
    const rest: Partial<typeof validEnv> = { ...validEnv };
    delete rest.DATABASE_URL;
    delete rest.NATS_URL;

    try {
      loadConfig({ ...rest, REDIS_URL: 'not-a-url', PORT: 'not-a-number' });
      throw new Error('expected loadConfig to throw');
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigValidationError);
      const configError = error as ConfigValidationError;
      const joined = configError.issues.join('\n');
      expect(joined).toContain('DATABASE_URL');
      expect(joined).toContain('NATS_URL');
      expect(joined).toContain('REDIS_URL');
      expect(joined).toContain('PORT');
      expect(configError.issues.length).toBeGreaterThanOrEqual(4);
    }
  });

  it('rejects an empty DATABASE_URL', () => {
    expect(() => loadConfig({ ...validEnv, DATABASE_URL: '' })).toThrow(ConfigValidationError);
  });

  it('rejects a malformed LOG_LEVEL', () => {
    expect(() => loadConfig({ ...validEnv, LOG_LEVEL: 'verbose' })).toThrow(ConfigValidationError);
  });
});
