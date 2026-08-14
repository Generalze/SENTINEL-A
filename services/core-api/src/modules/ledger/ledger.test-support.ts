import type { AppConfig } from '../../config/env.schema';
import type { AppConfigService } from '../../config/config.service';

/**
 * Test-only support for the live-stack integration specs in this module. Not a *.spec.ts/
 * *.test.ts file, so vitest does not try to run it. Mirrors
 * events/test-integration-support.ts's `makeAppConfig`/`uniqueOrgId` helpers exactly.
 */
export function makeAppConfig(overrides: Partial<AppConfig> = {}): AppConfigService {
  const values: AppConfig = {
    DATABASE_URL: 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
    NATS_URL: 'nats://localhost:4222',
    REDIS_URL: 'redis://localhost:6379',
    S3_ENDPOINT: 'http://localhost:9000',
    S3_ACCESS_KEY: 'sentinel',
    S3_SECRET_KEY: 'sentinel123',
    S3_BUCKET: 'sentinel-dev',
    S3_REGION: 'us-east-1',
    S3_EVIDENCE_BUCKET: 'sentinel-evidence',
    PORT: 3000,
    LOG_LEVEL: 'info',
    DEV_AUTH_ENABLED: false,
    ...overrides,
  };
  return { values } as AppConfigService;
}

let orgCounter = 0;

/** A fresh, collision-free organisation id so integration tests never see each other's rows. */
export function uniqueOrgId(label: string): string {
  orgCounter += 1;
  return `org_wp08_${label}_${Date.now()}_${orgCounter}`;
}
