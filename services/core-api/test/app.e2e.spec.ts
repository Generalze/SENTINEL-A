import type { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../src/app.module';
import { PrismaService } from '../src/prisma/prisma.service';

/**
 * WP-14 (H2 requirement) — AppModule end-to-end boot test.
 *
 * Boots the WHOLE application on an ephemeral port against the live stack
 * (Postgres/NATS/Redis/MinIO) and drives it over real HTTP, proving the single
 * global guard chain (DevAuthGuard -> AccessGuard) is wired and enforcing:
 *   - authorised request            -> 200
 *   - wrong-role request            -> 403
 *   - cross-organisation resource   -> 404 (never reveals existence)
 *   - an events ingest works end to end
 *   - /health is reachable with DEV_AUTH_ENABLED=false
 *
 * These are the concrete guarantees the Wave-2 review demanded and that no
 * per-module unit test can give, because they only hold once the real guards
 * are globally bound and reading the ONE canonical principal.
 */

const STACK_ENV: Record<string, string> = {
  DATABASE_URL: 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
  NATS_URL: 'nats://127.0.0.1:4222',
  REDIS_URL: 'redis://localhost:6379',
  S3_ENDPOINT: 'http://localhost:9000',
  S3_ACCESS_KEY: 'sentinel',
  S3_SECRET_KEY: 'sentinel123',
  S3_BUCKET: 'sentinel-dev',
  LOG_LEVEL: 'warn',
};

function applyEnv(devAuth: boolean): void {
  for (const [k, v] of Object.entries(STACK_ENV)) process.env[k] = v;
  process.env.DEV_AUTH_ENABLED = devAuth ? 'true' : 'false';
}

async function bootApp(devAuth: boolean): Promise<{ app: INestApplication; base: string }> {
  applyEnv(devAuth);
  const app = await NestFactory.create(AppModule, { logger: false });
  await app.listen(0, '127.0.0.1');
  const address = app.getHttpServer().address();
  const port = typeof address === 'object' && address ? address.port : 0;
  return { app, base: `http://127.0.0.1:${port}` };
}

const ts = Date.now();
const ORG_A = `e2e_orgA_${ts}`;
const ORG_B = `e2e_orgB_${ts}`;
const SITE_A = `e2e_siteA_${ts}`;
const SITE_B = `e2e_siteB_${ts}`;
const ADMIN_ID = `e2e_admin_${ts}`;
const OPERATOR_ID = `e2e_operator_${ts}`;

async function seed(prisma: PrismaService): Promise<void> {
  await prisma.organisation.create({ data: { id: ORG_A, name: 'E2E Org A' } });
  await prisma.organisation.create({ data: { id: ORG_B, name: 'E2E Org B' } });
  await prisma.site.create({ data: { id: SITE_A, organisationId: ORG_A, name: 'Site A' } });
  await prisma.site.create({ data: { id: SITE_B, organisationId: ORG_B, name: 'Site B' } });
  await prisma.user.create({
    data: { id: ADMIN_ID, organisationId: ORG_A, email: `admin_${ts}@a.test`, displayName: 'Admin', clearance: 5, roles: { create: [{ role: 'admin', siteId: null }] } },
  });
  await prisma.user.create({
    data: { id: OPERATOR_ID, organisationId: ORG_A, email: `op_${ts}@a.test`, displayName: 'Operator', clearance: 3, roles: { create: [{ role: 'operator', siteId: null }] } },
  });
}

async function cleanup(prisma: PrismaService): Promise<void> {
  await prisma.event.deleteMany({ where: { organisationId: { in: [ORG_A, ORG_B] } } });
  await prisma.userRole.deleteMany({ where: { userId: { in: [ADMIN_ID, OPERATOR_ID] } } });
  await prisma.user.deleteMany({ where: { id: { in: [ADMIN_ID, OPERATOR_ID] } } });
  await prisma.zone.deleteMany({ where: { siteId: { in: [SITE_A, SITE_B] } } });
  await prisma.site.deleteMany({ where: { id: { in: [SITE_A, SITE_B] } } });
  await prisma.organisation.deleteMany({ where: { id: { in: [ORG_A, ORG_B] } } });
}

function validEvent(): Record<string, unknown> {
  const now = new Date().toISOString();
  return {
    event_id: `evt_e2e_${ts}`,
    schema_version: 1,
    organisation_id: ORG_A,
    site_id: SITE_A,
    source_type: 'camera',
    source_id: 'cam-e2e',
    source_trust: 'trusted',
    event_type: 'motion',
    confidence: 0.9,
    occurred_at: now,
    ingested_at: now,
    trace_id: `trace_e2e_${ts}`,
  };
}

describe('AppModule e2e (DEV_AUTH_ENABLED=true, live stack)', () => {
  let app: INestApplication;
  let base: string;

  beforeAll(async () => {
    ({ app, base } = await bootApp(true));
    await seed(app.get(PrismaService));
  }, 60_000);

  afterAll(async () => {
    if (app) {
      await cleanup(app.get(PrismaService));
      await app.close();
    }
  }, 30_000);

  it('authorised request -> 200 (admin lists its own organisation)', async () => {
    const res = await fetch(`${base}/api/v1/organisations`, { headers: { 'x-dev-user-id': ADMIN_ID } });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { items: Array<{ id: string }> };
    expect(body.items.some((o) => o.id === ORG_A)).toBe(true);
  });

  it('wrong-role -> 403 (operator has no org.admin)', async () => {
    const res = await fetch(`${base}/api/v1/organisations`, { headers: { 'x-dev-user-id': OPERATOR_ID } });
    expect(res.status).toBe(403);
  });

  it('missing/unknown principal -> 401', async () => {
    const res = await fetch(`${base}/api/v1/organisations`, { headers: { 'x-dev-user-id': 'nobody' } });
    expect(res.status).toBe(401);
  });

  it('cross-organisation resource -> 404 (admin cannot reach another org\'s site)', async () => {
    const res = await fetch(`${base}/api/v1/sites/${SITE_B}/zones`, { headers: { 'x-dev-user-id': ADMIN_ID } });
    expect(res.status).toBe(404);
  });

  it('events ingest works end to end (operator ingests, 201 not duplicate)', async () => {
    const res = await fetch(`${base}/api/v1/events`, {
      method: 'POST',
      headers: { 'x-dev-user-id': OPERATOR_ID, 'content-type': 'application/json' },
      body: JSON.stringify(validEvent()),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { duplicate: boolean };
    expect(body.duplicate).toBe(false);
  });

  it('/health is reachable (200) even behind the global auth chain', async () => {
    const res = await fetch(`${base}/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: 'ok' });
  });

  // L2 regression (WP-14): organisation creation is rate-limited (@Throttle
  // limit 5) so an admin cannot mint unbounded orphan tenants — the 6th
  // request in the window is rejected with 429.
  it('L2: organisation creation is rate-limited (6th request -> 429)', async () => {
    const prisma = app.get(PrismaService);
    const createdIds: string[] = [];
    let throttledStatus = 0;
    for (let i = 0; i < 6; i += 1) {
      const res = await fetch(`${base}/api/v1/organisations`, {
        method: 'POST',
        headers: { 'x-dev-user-id': ADMIN_ID, 'content-type': 'application/json' },
        body: JSON.stringify({ name: `e2e-l2-${ts}-${i}` }),
      });
      if (res.status === 201) {
        createdIds.push(((await res.json()) as { id: string }).id);
      } else {
        throttledStatus = res.status;
        break;
      }
    }
    if (createdIds.length > 0) await prisma.organisation.deleteMany({ where: { id: { in: createdIds } } });
    expect(throttledStatus).toBe(429);
    expect(createdIds).toHaveLength(5);
  });
});

describe('AppModule e2e (DEV_AUTH_ENABLED=false, live stack)', () => {
  let app: INestApplication;
  let base: string;

  beforeAll(async () => {
    ({ app, base } = await bootApp(false));
  }, 60_000);

  afterAll(async () => {
    if (app) await app.close();
  }, 30_000);

  it('/health is @Public: reachable (200) with authentication disabled', async () => {
    const res = await fetch(`${base}/health`);
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: 'ok' });
  });

  it('/health/ready is @Public: reachable (not 401) with authentication disabled', async () => {
    const res = await fetch(`${base}/health/ready`);
    expect(res.status).not.toBe(401);
    expect([200, 503]).toContain(res.status);
  });

  it('a protected route still fails closed with 401 when auth is disabled', async () => {
    const res = await fetch(`${base}/api/v1/organisations`, { headers: { 'x-dev-user-id': ADMIN_ID } });
    expect(res.status).toBe(401);
  });
});
