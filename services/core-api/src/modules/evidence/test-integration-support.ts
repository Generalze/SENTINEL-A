import type { ServerResponse } from 'node:http';
import type { AppConfig } from '../../config/env.schema';
import type { AppConfigService } from '../../config/config.service';
import { buildPrincipal, type RequestWithPrincipal } from '../../common/security/principal';

/**
 * Test-only support for the live-stack integration specs in this module.
 * Not a *.spec.ts / *.test.ts file, so vitest does not try to run it.
 * Local copy of modules/events/test-integration-support.ts's approach:
 * constructs real collaborators the same way this repo's other provider
 * unit tests do (see src/infra/nats.provider.spec.ts's `fakeConfig()`) by
 * handing them an object shaped like AppConfigService rather than going
 * through the full Nest DI container or process.env/.env loading.
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

/** A fresh, collision-free organisation id so integration tests never see each other's rows (or each other's evidence, since object keys are prefixed by organisation_id). */
export function uniqueOrgId(label: string): string {
  orgCounter += 1;
  return `org_wp09_${label}_${Date.now()}_${orgCounter}`;
}

export function principalRequest(organisationId: string, userId?: string, traceId = 'it-trace', headers: Record<string, string> = {}): RequestWithPrincipal {
  return {
    traceId,
    headers,
    principal: buildPrincipal({
      user: { id: userId ?? `user_${organisationId}`, clearance: 5 },
      organisation_id: organisationId,
      roles: [{ role: 'evidence.custodian', site_id: null }],
    }),
  } as unknown as RequestWithPrincipal;
}

export function makeCapturingRes(): ServerResponse & { statusCode: number; body?: string; headers: Record<string, string>; endedBuffer?: Buffer } {
  const headers: Record<string, string> = {};
  const res = {
    setHeader: (name: string, value: string) => {
      headers[name.toLowerCase()] = value;
    },
    headers,
    end: function end(this: { body?: string; endedBuffer?: Buffer }, chunk?: string | Buffer) {
      if (Buffer.isBuffer(chunk)) {
        this.endedBuffer = chunk;
      } else if (typeof chunk === 'string') {
        this.body = chunk;
      }
    },
    statusCode: 0,
  };
  return res as unknown as ServerResponse & { statusCode: number; body?: string; headers: Record<string, string>; endedBuffer?: Buffer };
}
