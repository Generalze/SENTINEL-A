import { randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { io, type Socket as ClientSocket } from 'socket.io-client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../../app.module';
import { PrismaService } from '../../prisma/prisma.service';
import { WS_EVENT_FIELD_UPDATED, WS_PATH } from '../realtime/realtime.constants';

/**
 * WP-19 whole-system audit, correction batch regressions.
 *
 * One spec per correction, each pinning the exact failure the audit named:
 *  1. the verification evidence tuple is enforced below the service layer;
 *  2. idempotency is request-bound — a reused key with materially different
 *     input is a 409 with zero mutation, and a replay returns the
 *     representation the ORIGINAL request established;
 *  3. incident-assignment eligibility and version pinning are judged from
 *     rows locked inside the patrol transaction, so a concurrent transition
 *     cannot slip between check and commit;
 *  4. START is fail-closed when the pinned version materialises nothing;
 *  5. the contract's bounded-JSON budget is enforced before any transaction;
 * plus the inherited C7-08 protection as a permanent WP-19 regression: a
 * same-site peer's WebSocket payload carries scope + kind and NO run identity.
 */

const STACK_ENV: Record<string, string> = {
  DATABASE_URL: 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
  NATS_URL: 'nats://localhost:4222',
  REDIS_URL: 'redis://localhost:6379',
  S3_ENDPOINT: 'http://localhost:9000',
  S3_ACCESS_KEY: 'sentinel',
  S3_SECRET_KEY: 'sentinel123',
  S3_BUCKET: 'sentinel-dev',
  LOG_LEVEL: 'error',
  DEV_AUTH_ENABLED: 'true',
};

const tag = `wp19a_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;
const fx = {
  orgA: `${tag}_orgA`,
  siteA1: `${tag}_siteA1`,
  commanderA1: `${tag}_commanderA1`,
  dispatcherA1: `${tag}_dispatcherA1`,
  opAlpha: `${tag}_opAlpha`,
  opBravo: `${tag}_opBravo`,
  incidentA1: randomUUID(),
};

async function seed(prisma: PrismaService): Promise<void> {
  await prisma.organisation.create({ data: { id: fx.orgA, name: 'WP-19A Org A' } });
  await prisma.site.create({ data: { id: fx.siteA1, organisationId: fx.orgA, name: 'A1' } });
  const users: Array<{ id: string; role: string }> = [
    { id: fx.commanderA1, role: 'site.commander' },
    { id: fx.dispatcherA1, role: 'dispatcher' },
    { id: fx.opAlpha, role: 'field.operative' },
    { id: fx.opBravo, role: 'field.operative' },
  ];
  for (const u of users) {
    await prisma.user.create({
      data: {
        id: u.id, organisationId: fx.orgA, email: `${u.id}@example.invalid`, displayName: u.id, clearance: 5,
        roles: { create: [{ role: u.role, siteId: fx.siteA1 }] },
      },
    });
  }
  // B11-13: an incident now states its ORIGIN. This fixture is Fusion-shaped,
  // so source_ref IS the hypothesis id, exactly as the WP-21B migration
  // backfills every pre-existing row.
  const fixtureHypothesisId = randomUUID();
  await prisma.incident.create({
    data: {
      id: fx.incidentA1, hypothesisId: fixtureHypothesisId, incidentCandidateId: randomUUID(), sourceKind: 'FUSION_HYPOTHESIS', sourceRef: fixtureHypothesisId,
      organisationId: fx.orgA, siteId: fx.siteA1, incidentType: 'wp19a.test', severity: 'SEV3',
      threatState: 2, confidence: 0.9, responseMode: 'STANDARD',
    },
  });
  await prisma.fieldAssignment.create({
    data: {
      organisationId: fx.orgA, siteId: fx.siteA1, incidentId: fx.incidentA1, assigneeUserId: fx.opAlpha,
      assignmentType: 'INCIDENT_RESPONSE', priority: 'SEV3', status: 'ACCEPTED', deliveryState: 'REQUESTED',
      needToKnowSummary: 'wp19a fixture', idempotencyKey: `${tag}-alpha-accepted`,
      createdByUserId: fx.commanderA1, updatedByUserId: fx.commanderA1,
    },
  });
}

async function cleanup(prisma: PrismaService): Promise<void> {
  const orgs = [fx.orgA];
  await prisma.patrolRunActionIdempotency.deleteMany({ where: { run: { organisationId: { in: orgs } } } });
  await prisma.patrolRunCheckpoint.updateMany({ where: { organisationId: { in: orgs } }, data: { verificationId: null } });
  await prisma.patrolCheckpointVerification.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolRunCheckpoint.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolRun.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolCheckpoint.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolRouteVersion.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolRoute.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldAssignment.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldAuditLog.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldOutbox.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incidentTimelineEntry.deleteMany({ where: { incident: { organisationId: { in: orgs } } } });
  await prisma.incident.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.userRole.deleteMany({ where: { user: { organisationId: { in: orgs } } } });
  await prisma.user.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.site.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.organisation.deleteMany({ where: { id: { in: orgs } } });
}

interface RouteResponse {
  id: string;
  route_version: number;
  checkpoints: Array<{ id: string; sequence_number: number; window_open_offset_ms: number }>;
}

interface RunResponse {
  id: string;
  status: string;
  route_version: number;
  checkpoints: Array<{ id: string; state: string; patrol_checkpoint_id: string }>;
}

interface VerifyResponse {
  verification: { id: string; route_version: number };
  run_checkpoint: { id: string; state: string };
  run_status: string;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

describe('WP-19 audit correction batch (live stack)', () => {
  let app: INestApplication;
  let base: string;
  let prisma: PrismaService;
  const openSockets: ClientSocket[] = [];

  const post = (path: string, userId: string, body: unknown) =>
    fetch(`${base}${path}`, { method: 'POST', headers: { 'x-dev-user-id': userId, 'content-type': 'application/json' }, body: JSON.stringify(body) });

  function routeBody(offsets: Array<[number, number, number]>, overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      site_id: fx.siteA1,
      name: 'Audit walk',
      checkpoints: offsets.map(([open, late, missed], index) => ({
        name: `Checkpoint ${index + 1}`,
        zone_id: null,
        location: null,
        window_open_offset_ms: open,
        late_after_offset_ms: late,
        missed_after_offset_ms: missed,
      })),
      idempotency_key: `route-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
      ...overrides,
    };
  }

  async function createRoute(offsets: Array<[number, number, number]>): Promise<RouteResponse> {
    const res = await post('/api/v1/patrol/routes', fx.commanderA1, routeBody(offsets));
    expect(res.status).toBe(201);
    return (await res.json()) as RouteResponse;
  }

  function scheduleBody(routeId: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      patrol_route_id: routeId,
      assigned_operative_user_id: fx.opAlpha,
      incident_id: null,
      scheduled_start_at: new Date().toISOString(),
      idempotency_key: `run-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
      ...overrides,
    };
  }

  async function scheduleRun(routeId: string, overrides: Record<string, unknown> = {}): Promise<RunResponse> {
    const res = await post('/api/v1/patrol/runs', fx.dispatcherA1, scheduleBody(routeId, overrides));
    expect(res.status).toBe(201);
    return (await res.json()) as RunResponse;
  }

  async function startRun(runId: string): Promise<RunResponse> {
    const res = await post(`/api/v1/patrol/runs/${runId}/start`, fx.opAlpha, { idempotency_key: `start-${randomUUID()}`, trace_id: `trace-${randomUUID()}` });
    expect(res.status).toBe(201);
    return (await res.json()) as RunResponse;
  }

  function verifyBody(overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      device_id: 'device-1',
      verification_method: 'manual',
      source_at: new Date().toISOString(),
      idempotency_key: `verify-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
      ...overrides,
    };
  }

  const verify = (runId: string, runCheckpointId: string, body: Record<string, unknown> = {}) =>
    post(`/api/v1/patrol/runs/${runId}/checkpoints/${runCheckpointId}/verify`, fx.opAlpha, verifyBody(body));

  async function restoreAssignmentAccepted(): Promise<void> {
    await prisma.fieldAssignment.updateMany({
      where: { organisationId: fx.orgA, incidentId: fx.incidentA1, assigneeUserId: fx.opAlpha },
      data: { status: 'ACCEPTED' },
    });
  }

  beforeAll(async () => {
    for (const [key, value] of Object.entries(STACK_ENV)) process.env[key] = value;
    app = await NestFactory.create(AppModule, { logger: false });
    await app.listen(0, '127.0.0.1');
    const address = app.getHttpServer().address();
    base = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
    prisma = app.get(PrismaService);
    await seed(prisma);
  }, 60_000);

  afterAll(async () => {
    for (const socket of openSockets.splice(0)) socket.close();
    if (app) {
      await cleanup(prisma);
      await app.close();
    }
  }, 30_000);

  // --- Correction 1: the evidence tuple is enforced below the service -------

  it('a service-bypassing writer cannot record a verification whose evidence disagrees with its run checkpoint', async () => {
    const route = await createRoute([[0, 60_000, 120_000]]);
    const run = await scheduleRun(route.id);
    const started = await startRun(run.id);
    const runCheckpointId = started.checkpoints[0].id;
    const checkpointId = started.checkpoints[0].patrol_checkpoint_id;

    const rawInsert = (overrides: Partial<Record<'site' | 'route' | 'version' | 'checkpoint', string | number>>) =>
      prisma.$executeRawUnsafe(
        `INSERT INTO patrol_checkpoint_verifications
           (id, organisation_id, site_id, patrol_run_id, patrol_run_checkpoint_id, patrol_route_id, route_version,
            patrol_checkpoint_id, operative_user_id, device_id, verification_method, verification_context,
            source_at, recorded_at, idempotency_key, trace_id)
         VALUES ($1::uuid, $2, $3, $4::uuid, $5::uuid, $6::uuid, $7, $8::uuid, $9, $10, $11, '{}', now(), now(), $12, $13)`,
        randomUUID(),
        fx.orgA,
        (overrides.site as string) ?? fx.siteA1,
        run.id,
        runCheckpointId,
        (overrides.route as string) ?? route.id,
        (overrides.version as number) ?? run.route_version,
        (overrides.checkpoint as string) ?? checkpointId,
        fx.opAlpha,
        'device-x',
        'manual',
        `forged-${randomUUID()}`,
        'trace-forged',
      );

    // Each forged dimension of the evidence tuple must be refused by the
    // composite foreign key, not by service-layer politeness.
    await expect(rawInsert({ site: `${tag}_other_site` })).rejects.toThrow(/foreign key|violates/i);
    await expect(rawInsert({ route: randomUUID() })).rejects.toThrow(/foreign key|violates/i);
    await expect(rawInsert({ version: 99 })).rejects.toThrow(/foreign key|violates/i);
    await expect(rawInsert({ checkpoint: randomUUID() })).rejects.toThrow(/foreign key|violates/i);
    expect(await prisma.patrolCheckpointVerification.count({ where: { patrolRunId: run.id } })).toBe(0);

    // The honest path still works and the evidence carries the pinned version.
    const res = await verify(run.id, runCheckpointId);
    expect(res.status).toBe(201);
    expect(((await res.json()) as VerifyResponse).verification.route_version).toBe(run.route_version);
  });

  // --- Correction 2: request-bound idempotency -------------------------------

  it('a reused verification key with materially different input is a 409 with zero mutation; a fresh trace is still a replay', async () => {
    const route = await createRoute([[0, 60_000, 120_000], [0, 120_000, 240_000]]);
    const run = await scheduleRun(route.id);
    const started = await startRun(run.id);
    const body = verifyBody({ verification_context: { gate: 'north' } });

    const first = await verify(run.id, started.checkpoints[0].id, body);
    expect(first.status).toBe(201);
    const established = (await first.json()) as VerifyResponse;

    // Same key, different device / context / source time: conflict, no mutation.
    for (const different of [{ device_id: 'device-2' }, { verification_context: { gate: 'south' } }, { source_at: new Date(Date.now() + 1000).toISOString() }]) {
      const res = await verify(run.id, started.checkpoints[0].id, { ...body, ...different });
      expect(res.status).toBe(409);
    }
    expect(await prisma.patrolCheckpointVerification.count({ where: { patrolRunId: run.id } })).toBe(1);

    // trace_id is NOT semantic: a legitimate retry carries a new trace.
    const retried = await verify(run.id, started.checkpoints[0].id, { ...body, trace_id: `trace-${randomUUID()}` });
    expect(retried.status).toBe(201);
    expect(((await retried.json()) as VerifyResponse).verification.id).toBe(established.verification.id);
  });

  it('a route-create replay returns the representation the original creation established, and a changed body conflicts', async () => {
    const body = routeBody([[0, 1_000, 2_000]]);
    const createdRes = await post('/api/v1/patrol/routes', fx.commanderA1, body);
    expect(createdRes.status).toBe(201);
    const created = (await createdRes.json()) as RouteResponse;

    // Move the route on: v2 with two checkpoints.
    const publishBody = {
      checkpoints: [1, 2].map((n) => ({
        name: `V2 checkpoint ${n}`, zone_id: null, location: null,
        window_open_offset_ms: 0, late_after_offset_ms: 60_000, missed_after_offset_ms: 120_000,
      })),
      idempotency_key: `publish-${randomUUID()}`,
      trace_id: 't',
    };
    expect((await post(`/api/v1/patrol/routes/${created.id}/versions`, fx.commanderA1, publishBody)).status).toBe(201);

    // Replay of the CREATE returns version 1 with its original checkpoint —
    // not whatever the route's current version has since become.
    const replay = await post('/api/v1/patrol/routes', fx.commanderA1, { ...body, trace_id: `trace-${randomUUID()}` });
    expect(replay.status).toBe(201);
    const replayed = (await replay.json()) as RouteResponse;
    expect(replayed.id).toBe(created.id);
    expect(replayed.route_version).toBe(1);
    expect(replayed.checkpoints).toHaveLength(1);

    // Same key, different checkpoints: 409, and no third version appears.
    const conflicting = { ...body, checkpoints: [{ name: 'Changed', zone_id: null, location: null, window_open_offset_ms: 5, late_after_offset_ms: 6, missed_after_offset_ms: 7 }] };
    expect((await post('/api/v1/patrol/routes', fx.commanderA1, conflicting)).status).toBe(409);
    expect(await prisma.patrolRouteVersion.count({ where: { patrolRouteId: created.id } })).toBe(2);

    // Publish replays follow the same rule.
    const publishReplay = await post(`/api/v1/patrol/routes/${created.id}/versions`, fx.commanderA1, publishBody);
    expect(publishReplay.status).toBe(201);
    expect(((await publishReplay.json()) as RouteResponse).route_version).toBe(2);
    const publishConflict = { ...publishBody, checkpoints: publishBody.checkpoints.slice(0, 1) };
    expect((await post(`/api/v1/patrol/routes/${created.id}/versions`, fx.commanderA1, publishConflict)).status).toBe(409);
  });

  it('schedule and abandon idempotency are request-bound too', async () => {
    const route = await createRoute([[0, 300_000, 600_000]]);
    const body = scheduleBody(route.id);
    const first = await post('/api/v1/patrol/runs', fx.dispatcherA1, body);
    expect(first.status).toBe(201);
    const run = (await first.json()) as RunResponse;

    const replay = await post('/api/v1/patrol/runs', fx.dispatcherA1, { ...body, trace_id: `trace-${randomUUID()}` });
    expect(replay.status).toBe(201);
    expect(((await replay.json()) as RunResponse).id).toBe(run.id);

    // Same dispatcher, same key, different operative: conflict, no second run.
    expect((await post('/api/v1/patrol/runs', fx.dispatcherA1, { ...body, assigned_operative_user_id: fx.opBravo })).status).toBe(409);
    expect(await prisma.patrolRun.count({ where: { organisationId: fx.orgA, patrolRouteId: route.id } })).toBe(1);

    await startRun(run.id);
    const abandonKey = `abandon-${randomUUID()}`;
    expect((await post(`/api/v1/patrol/runs/${run.id}/abandon`, fx.opAlpha, { idempotency_key: abandonKey, trace_id: 't', reason: 'equipment failure' })).status).toBe(201);
    // Same key, different reason: the audited reason is part of the request.
    expect((await post(`/api/v1/patrol/runs/${run.id}/abandon`, fx.opAlpha, { idempotency_key: abandonKey, trace_id: 't', reason: 'changed my mind' })).status).toBe(409);
    expect((await post(`/api/v1/patrol/runs/${run.id}/abandon`, fx.opAlpha, { idempotency_key: abandonKey, trace_id: 't2', reason: 'equipment failure' })).status).toBe(201);
  });

  // --- Correction 3: locked mutable dependencies -----------------------------

  it('an assignment transitioning to terminal cannot race START: the gate reads rows locked in the patrol transaction', async () => {
    const route = await createRoute([[0, 60_000, 120_000]]);
    const run = await scheduleRun(route.id, { incident_id: fx.incidentA1 });

    let startPromise: Promise<Awaited<ReturnType<typeof post>>> | undefined;
    await prisma.$transaction(async (tx) => {
      // Hold the assignment row exactly as a Field-assignment transition would.
      await tx.$queryRawUnsafe(
        `SELECT id FROM field_assignments WHERE organisation_id = $1 AND incident_id = $2::uuid AND assignee_user_id = $3 ORDER BY id FOR UPDATE`,
        fx.orgA, fx.incidentA1, fx.opAlpha,
      );
      await tx.fieldAssignment.updateMany({
        where: { organisationId: fx.orgA, incidentId: fx.incidentA1, assigneeUserId: fx.opAlpha },
        data: { status: 'COMPLETED' },
      });
      // START must now block on the assignment lock inside its own transaction.
      startPromise = post(`/api/v1/patrol/runs/${run.id}/start`, fx.opAlpha, { idempotency_key: `start-${randomUUID()}`, trace_id: 't' });
      await sleep(600);
    });

    const res = await startPromise!;
    expect(res.status).toBe(409);
    const row = await prisma.patrolRun.findUniqueOrThrow({ where: { id: run.id } });
    expect(row.status).toBe('SCHEDULED');
    expect(row.startedAt).toBeNull();
    expect(await prisma.patrolRunCheckpoint.count({ where: { patrolRunId: run.id } })).toBe(0);
    expect(await prisma.fieldAuditLog.count({ where: { kind: 'PATROL_RUN_STARTED', payload: { path: ['patrol_run_id'], equals: run.id } } })).toBe(0);

    // With the assignment live again, the same gate admits the start.
    await restoreAssignmentAccepted();
    await startRun(run.id);
  });

  it('an assignment transitioning to terminal cannot race VERIFY either', async () => {
    const route = await createRoute([[0, 60_000, 120_000]]);
    const run = await scheduleRun(route.id, { incident_id: fx.incidentA1 });
    const started = await startRun(run.id);

    let verifyPromise: Promise<Awaited<ReturnType<typeof post>>> | undefined;
    await prisma.$transaction(async (tx) => {
      await tx.$queryRawUnsafe(
        `SELECT id FROM field_assignments WHERE organisation_id = $1 AND incident_id = $2::uuid AND assignee_user_id = $3 ORDER BY id FOR UPDATE`,
        fx.orgA, fx.incidentA1, fx.opAlpha,
      );
      await tx.fieldAssignment.updateMany({
        where: { organisationId: fx.orgA, incidentId: fx.incidentA1, assigneeUserId: fx.opAlpha },
        data: { status: 'COMPLETED' },
      });
      verifyPromise = verify(run.id, started.checkpoints[0].id);
      await sleep(600);
    });

    const res = await verifyPromise!;
    expect(res.status).toBe(409);
    expect(await prisma.patrolCheckpointVerification.count({ where: { patrolRunId: run.id } })).toBe(0);
    const checkpoint = await prisma.patrolRunCheckpoint.findUniqueOrThrow({ where: { id: started.checkpoints[0].id } });
    expect(checkpoint.state).toBe('PENDING');

    await restoreAssignmentAccepted();
    expect((await verify(run.id, started.checkpoints[0].id)).status).toBe(201);
  });

  it('a schedule racing a version publish pins the version current when its row is inserted, never a stale one', async () => {
    const route = await createRoute([[0, 60_000, 120_000]]);

    let schedulePromise: Promise<Awaited<ReturnType<typeof post>>> | undefined;
    await prisma.$transaction(async (tx) => {
      // Hold the route row exactly as publishVersion does, and move the
      // standard to version 2 while holding it.
      await tx.$queryRawUnsafe(`SELECT id FROM patrol_routes WHERE id = $1::uuid FOR UPDATE`, route.id);
      await tx.patrolRouteVersion.create({
        data: {
          patrolRouteId: route.id, version: 2, organisationId: fx.orgA, siteId: fx.siteA1,
          publishedByUserId: fx.commanderA1, idempotencyKey: `publish-${randomUUID()}`, traceId: 't',
        },
      });
      await tx.patrolCheckpoint.createMany({
        data: [1, 2].map((sequenceNumber) => ({
          patrolRouteId: route.id, routeVersion: 2, organisationId: fx.orgA, siteId: fx.siteA1,
          sequenceNumber, name: `V2 checkpoint ${sequenceNumber}`,
          windowOpenOffsetMs: 0, lateAfterOffsetMs: 60_000, missedAfterOffsetMs: 120_000, traceId: 't',
        })),
      });
      await tx.patrolRoute.update({ where: { id: route.id }, data: { currentVersion: 2 } });
      // The schedule must block on the route lock inside its own transaction.
      schedulePromise = post('/api/v1/patrol/runs', fx.dispatcherA1, scheduleBody(route.id));
      await sleep(600);
    });

    const res = await schedulePromise!;
    expect(res.status).toBe(201);
    const run = (await res.json()) as RunResponse;
    expect(run.route_version).toBe(2);
    // And materialisation follows the pinned version: two checkpoints, not one.
    const started = await startRun(run.id);
    expect(started.checkpoints).toHaveLength(2);
  });

  // --- Correction 4: START fails closed on an empty materialisation ----------

  it('a run whose pinned version yields no checkpoints cannot START, and no partial state survives', async () => {
    const route = await createRoute([[0, 60_000, 120_000]]);
    const run = await scheduleRun(route.id);
    // Service-bypass: hollow out the pinned version's definitions.
    await prisma.patrolCheckpoint.deleteMany({ where: { patrolRouteId: route.id, routeVersion: run.route_version } });

    const res = await post(`/api/v1/patrol/runs/${run.id}/start`, fx.opAlpha, { idempotency_key: `start-${randomUUID()}`, trace_id: 't' });
    expect(res.status).toBe(409);
    const row = await prisma.patrolRun.findUniqueOrThrow({ where: { id: run.id } });
    expect(row.status).toBe('SCHEDULED');
    expect(row.startedAt).toBeNull();
    expect(await prisma.patrolRunCheckpoint.count({ where: { patrolRunId: run.id } })).toBe(0);
    expect(await prisma.fieldAuditLog.count({ where: { kind: 'PATROL_RUN_STARTED', payload: { path: ['patrol_run_id'], equals: run.id } } })).toBe(0);
  });

  // --- Correction 5: bounded JSON is refused at the boundary ------------------

  it('an oversized location or verification_context is a 400 before any durable write', async () => {
    const oversized = { blob: 'x'.repeat(17_000) };

    const routeKey = `route-${randomUUID()}`;
    const body = routeBody([[0, 1_000, 2_000]], { idempotency_key: routeKey });
    (body.checkpoints as Array<Record<string, unknown>>)[0].location = oversized;
    expect((await post('/api/v1/patrol/routes', fx.commanderA1, body)).status).toBe(400);
    expect(await prisma.patrolRoute.count({ where: { organisationId: fx.orgA, idempotencyKey: routeKey } })).toBe(0);

    const route = await createRoute([[0, 60_000, 120_000]]);
    const run = await scheduleRun(route.id);
    const started = await startRun(run.id);
    expect((await verify(run.id, started.checkpoints[0].id, { verification_context: oversized })).status).toBe(400);
    expect(await prisma.patrolCheckpointVerification.count({ where: { patrolRunId: run.id } })).toBe(0);
    const checkpoint = await prisma.patrolRunCheckpoint.findUniqueOrThrow({ where: { id: started.checkpoints[0].id } });
    expect(checkpoint.state).toBe('PENDING');
  });

  // --- Inherited C7-08 protection, pinned as a WP-19 regression ---------------

  it('a same-site peer socket receives scope and kind only — never a patrol_run_id', async () => {
    const socket = io(base, {
      path: WS_PATH,
      transports: ['websocket'],
      reconnection: false,
      forceNew: true,
      auth: { userId: fx.opBravo },
    });
    openSockets.push(socket);

    const patrolEvent = new Promise<Record<string, unknown>>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error('timed out waiting for a PATROL_RUN_UPDATED field.updated event'));
      }, 20_000);
      socket.on(WS_EVENT_FIELD_UPDATED, (payload: Record<string, unknown>) => {
        if (payload && payload.kind === 'PATROL_RUN_UPDATED') {
          clearTimeout(timer);
          resolve(payload);
        }
      });
    });
    await new Promise<void>((resolve, reject) => {
      socket.once('connect', () => resolve());
      socket.once('connect_error', (error) => reject(error));
    });

    // A patrol mutation the peer must hear about only as "something changed".
    const route = await createRoute([[0, 60_000, 120_000]]);
    const run = await scheduleRun(route.id);

    const payload = await patrolEvent;
    expect(Object.keys(payload).sort()).toEqual(['kind', 'organisation_id', 'site_id']);
    expect(payload).toMatchObject({ kind: 'PATROL_RUN_UPDATED', organisation_id: fx.orgA, site_id: fx.siteA1 });
    expect('patrol_run_id' in payload).toBe(false);
    // REST keeps the same boundary the socket just respected: the peer's read
    // of that run is the 404 the C7-08 rule pairs this projection with.
    expect((await fetch(`${base}/api/v1/patrol/runs/${run.id}`, { headers: { 'x-dev-user-id': fx.opBravo } })).status).toBe(404);
  }, 30_000);
});
