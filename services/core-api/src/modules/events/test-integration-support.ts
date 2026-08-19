import type { ServerResponse } from 'node:http';
import type { AppConfig } from '../../config/env.schema';
import type { AppConfigService } from '../../config/config.service';
import { buildPrincipal, type RequestWithPrincipal } from '../../common/security/principal';

/**
 * Test-only support for the live-stack integration specs in this module.
 * Not a *.spec.ts / *.test.ts file, so vitest does not try to run it.
 *
 * Constructs real collaborators (PrismaService, NatsProvider, ...) the
 * same way the rest of this repo's provider unit tests do — see
 * src/infra/nats.provider.spec.ts's `fakeConfig()` — by handing them an
 * object shaped like AppConfigService rather than going through the full
 * Nest DI container or process.env/.env loading.
 */
export function makeAppConfig(overrides: Partial<AppConfig> = {}): AppConfigService {
  const values: AppConfig = {
    DATABASE_URL: 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
    NATS_URL: 'nats://127.0.0.1:4222',
    REDIS_URL: 'redis://localhost:6379',
    S3_ENDPOINT: 'http://localhost:9000',
    S3_ACCESS_KEY: 'sentinel',
    S3_SECRET_KEY: 'sentinel123',
    S3_BUCKET: 'sentinel-dev',
    S3_REGION: 'us-east-1',
    // WP-09 addition to AppConfig (services/core-api/src/config/env.schema.ts);
    // listed here only to satisfy the AppConfig type, this module has no use for it.
    S3_EVIDENCE_BUCKET: 'sentinel-evidence',
    PORT: 3000,
    LOG_LEVEL: 'info',
    DEV_AUTH_ENABLED: false, PATROL_SWEEP_INTERVAL_MS: 0,
    ...overrides,
  };
  return { values } as AppConfigService;
}

let orgCounter = 0;

/** A fresh, collision-free organisation id so integration tests never see each other's rows. */
export function uniqueOrgId(label: string): string {
  orgCounter += 1;
  return `org_wp04_${label}_${Date.now()}_${orgCounter}`;
}

export function principalRequest(organisationId: string, traceId = 'it-trace'): RequestWithPrincipal {
  return {
    traceId,
    principal: buildPrincipal({
      user: { id: `user_${organisationId}`, clearance: 5 },
      organisation_id: organisationId,
      roles: [{ role: 'operator', site_id: null }],
    }),
  } as unknown as RequestWithPrincipal;
}

export function makeCapturingRes(): ServerResponse & { statusCode: number; body?: string } {
  const res = {
    setHeader: () => undefined,
    end: function end(this: { body?: string }, chunk: string) {
      this.body = chunk;
    },
    statusCode: 0,
  };
  return res as unknown as ServerResponse & { statusCode: number; body?: string };
}

/** Polls `check` until it returns true or `timeoutMs` elapses. */
export async function waitUntil(check: () => Promise<boolean>, timeoutMs: number, intervalMs = 200): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await check()) {
      return true;
    }
    if (Date.now() >= deadline) {
      return false;
    }
    await new Promise((resolve) => {
      globalThis.setTimeout(resolve, intervalMs);
    });
  }
}
