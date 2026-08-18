import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { Module, type INestApplication } from '@nestjs/common';
import { ConfigModule } from '../../config/config.module';
import { InfraModule } from '../../infra/infra.module';
import { NatsProvider } from '../../infra/nats.provider';
import { PrismaModule } from '../../prisma/prisma.module';
import { PrismaService } from '../../prisma/prisma.service';
import { RealtimeModule } from './realtime.module';

/**
 * Test-only support for this module's live-stack integration specs. Not a
 * *.spec.ts/*.test.ts file, so vitest does not try to run it. Deliberately
 * self-contained (not imported from ../events/test-integration-support.ts)
 * per this module's exclusive-lane coordination rule.
 */

/**
 * The full set of env vars `AppConfigService` (via `env.schema.ts`)
 * requires. Set explicitly in `beforeAll`/restored in `afterAll` rather
 * than relying on `services/core-api/.env` being auto-loaded by the test
 * runner — vitest does not load `.env` into `process.env` on its own
 * (mirrors `config.service.spec.ts`'s own approach for the same reason).
 */
export const LIVE_STACK_ENV: Readonly<Record<string, string>> = {
  DATABASE_URL: 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
  /**
   * CI-stability fix: `127.0.0.1`, NOT `localhost`.
   *
   * The compose stack publishes NATS on 127.0.0.1 only (IPv4 loopback). On a
   * host where `localhost` resolves to `::1` first — Windows does — the `nats`
   * client attempts IPv6 and stalls for ~27 SECONDS before falling back, and
   * its own `timeout` option does not bound that. Measured on this stack:
   *
   *     nats://localhost:4222  -> 27,223ms
   *     nats://127.0.0.1:4222  ->      2ms
   *
   * That single connect is what pushed this module's `beforeAll` hooks up
   * against their 30s timeout, producing an intermittent "Hook timed out"
   * failure that looks like a realtime bug and is not one. Addressing the
   * loopback address removes the cause rather than raising the timeout to
   * accommodate it. Production is unaffected: it reads NATS_URL from real
   * configuration and never uses this fixture.
   */
  NATS_URL: 'nats://127.0.0.1:4222',
  REDIS_URL: 'redis://localhost:6379',
  S3_ENDPOINT: 'http://localhost:9000',
  S3_ACCESS_KEY: 'sentinel',
  S3_SECRET_KEY: 'sentinel123',
  S3_BUCKET: 'sentinel-dev',
  S3_REGION: 'us-east-1',
  // Unused by these specs (they call app.listen(0) directly for an
  // ephemeral port) — just needs to satisfy env.schema.ts's `.positive()`.
  PORT: '3000',
  LOG_LEVEL: 'error',
  DEV_AUTH_ENABLED: 'true',
};

@Module({ imports: [ConfigModule, PrismaModule, InfraModule, RealtimeModule] })
export class RealtimeTestAppModule {}

export interface BootstrappedApp {
  readonly app: INestApplication;
  readonly baseUrl: string;
  readonly prisma: PrismaService;
  /**
   * The SAME `NatsProvider` instance the app's own `RealtimeNatsBridgeService`
   * uses. Specs that need to publish test NATS messages should call
   * `(await natsProvider.getConnection()).publish(...)` on this rather than
   * opening a second, independent `connect()` in the same process — the
   * `nats` client (v2.29.x) has a reconnect quirk where a second `connect()`
   * call in a process that already holds an open connection stalls for
   * ~25-30s before succeeding (same quirk documented in
   * events/events.nats-down.integration.spec.ts, reproduced independently
   * here). Reusing the app's own connection sidesteps it entirely and is
   * also just simpler: it's the same live NATS server either way.
   */
  readonly natsProvider: NatsProvider;
}

/** Sets every LIVE_STACK_ENV var, returning a restorer to put process.env back exactly as it was. */
export function withLiveStackEnv(): () => void {
  const original = { ...process.env };
  Object.assign(process.env, LIVE_STACK_ENV);
  return () => {
    process.env = original;
  };
}

/** Boots a real Nest application (RealtimeModule + shared infra) on an ephemeral port, against the live stack. */
export async function bootstrapRealtimeApp(): Promise<BootstrappedApp> {
  // Lazy import so this only pulls in @nestjs/testing from the spec files that actually bootstrap an app.
  const { Test } = await import('@nestjs/testing');
  const moduleRef = await Test.createTestingModule({ imports: [RealtimeTestAppModule] }).compile();
  const app = moduleRef.createNestApplication();
  await app.listen(0);

  const address = app.getHttpServer().address() as AddressInfo;
  const baseUrl = `http://127.0.0.1:${address.port}`;
  const prisma = moduleRef.get(PrismaService);
  await prisma.$connect();
  const natsProvider = moduleRef.get(NatsProvider);

  return { app, baseUrl, prisma, natsProvider };
}

export interface TestOrgUser {
  readonly organisationId: string;
  readonly userId: string;
}

/** Creates a fresh Organisation + User directly via Prisma (not through the identity module) for a test to authenticate as. */
export async function makeOrgAndUser(prisma: PrismaService, label: string): Promise<TestOrgUser> {
  const suffix = `${label}-${randomUUID()}`;
  const organisation = await prisma.organisation.create({ data: { name: `wp12-${suffix}` } });
  const user = await prisma.user.create({
    data: {
      organisationId: organisation.id,
      email: `${suffix}@example.invalid`,
      displayName: `WP-12 ${label}`,
    },
  });
  return { organisationId: organisation.id, userId: user.id };
}

/** WP-17: one §62 role assignment for a fixture user. `siteId: null` is organisation-wide. */
export interface TestRoleSpec {
  readonly role: string;
  readonly siteId: string | null;
}

/** WP-17: a site inside an existing fixture organisation, for site-scoped room tests. */
export async function makeSite(prisma: PrismaService, organisationId: string, label: string): Promise<string> {
  const site = await prisma.site.create({ data: { organisationId, name: `wp17-${label}-${randomUUID()}` } });
  return site.id;
}

/** WP-17: a fixture user carrying real §62 role assignments, so Field room derivation is exercised against real rows. */
export async function makeUserWithRoles(prisma: PrismaService, organisationId: string, label: string, roles: readonly TestRoleSpec[]): Promise<TestOrgUser> {
  const suffix = `${label}-${randomUUID()}`;
  const user = await prisma.user.create({
    data: {
      organisationId,
      email: `${suffix}@example.invalid`,
      displayName: `WP-17 ${label}`,
      clearance: 5,
      roles: { create: roles.map((spec) => ({ role: spec.role, siteId: spec.siteId })) },
    },
  });
  return { organisationId, userId: user.id };
}

/**
 * Deletes everything the fixture helpers created for the given orgs, in FK
 * order: role assignments, then users, then sites, then organisations.
 * (`UserRole` references both `User` and `Site` without a cascade, so both
 * must go first — see prisma/schema/identity.prisma.)
 */
export async function cleanupOrgsAndUsers(prisma: PrismaService, organisationIds: readonly string[]): Promise<void> {
  if (organisationIds.length === 0) {
    return;
  }
  const ids = [...organisationIds];
  await prisma.userRole.deleteMany({ where: { user: { organisationId: { in: ids } } } });
  await prisma.user.deleteMany({ where: { organisationId: { in: ids } } });
  await prisma.zone.deleteMany({ where: { site: { organisationId: { in: ids } } } });
  await prisma.site.deleteMany({ where: { organisationId: { in: ids } } });
  await prisma.organisation.deleteMany({ where: { id: { in: ids } } });
}

/** Resolves with the next `event` emitted on `emitter`, or rejects if none arrives within `timeoutMs`. */
export function waitForEvent<T = unknown>(
  emitter: { once: (event: string, cb: (payload: T) => void) => void },
  event: string,
  timeoutMs = 4000,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`timed out after ${timeoutMs}ms waiting for '${event}'`));
    }, timeoutMs);
    emitter.once(event, (payload: T) => {
      clearTimeout(timer);
      resolve(payload);
    });
  });
}

/** Resolves after `windowMs` iff `event` was NOT emitted on `emitter` during that window; rejects if it was. */
export function assertNoEvent(
  emitter: { once: (event: string, cb: (payload: unknown) => void) => void; off: (event: string, cb: (payload: unknown) => void) => void },
  event: string,
  windowMs: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const handler = (payload: unknown): void => {
      reject(new Error(`unexpected '${event}' received: ${JSON.stringify(payload)}`));
    };
    emitter.once(event, handler);
    setTimeout(() => {
      emitter.off(event, handler);
      resolve();
    }, windowMs);
  });
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * Publishes `payload` on `subject` repeatedly until `awaited` settles.
 *
 * The bridge establishes its NATS subscriptions in the background from
 * `onModuleInit`, so a single publish issued immediately after boot can race
 * ahead of the subscription and be dropped by the server — NATS has no
 * store-and-forward for plain subscriptions. This module previously papered
 * over that with a fixed `sleep(700)` in `beforeAll`, which is a guess: too
 * short on a loaded machine, and pure dead time otherwise.
 *
 * Republishing until the expectation resolves is the convergence form of the
 * same intent, and it is safe for these specs: the waiter takes the FIRST
 * matching event, and a duplicate delivery of an identical payload changes no
 * assertion. Any negative assertion running alongside (`assertNoEvent` for
 * another organisation) is strengthened, not weakened, by the extra publishes —
 * more chances to leak, not fewer.
 */
export async function publishUntilReceived<T>(
  nc: { publish: (subject: string, data: Uint8Array) => void },
  subject: string,
  data: Uint8Array,
  awaited: Promise<T>,
  intervalMs = 200,
): Promise<T> {
  let settled = false;
  const tracked = awaited.finally(() => {
    settled = true;
  });

  nc.publish(subject, data);
  while (!settled) {
    await sleep(intervalMs);
    if (settled) break;
    nc.publish(subject, data);
  }
  return tracked;
}
