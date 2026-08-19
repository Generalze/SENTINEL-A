import { randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AppModule } from '../../app.module';
import { PrismaService } from '../../prisma/prisma.service';
import { PatrolMissedSweeper } from './patrol-missed.sweeper';
import { PATROL_SWEEP_SCHEDULER } from './patrol-sweep.scheduler';
import { NoopPatrolSweepScheduler } from './patrol-sweep.scheduler.test-support';

/**
 * WP-19 patrol foundation end to end, through the real guard chain against the
 * live stack: version pinning and immutability (C9-04), materialised timing and
 * the TOO_EARLY/LATE/EXPIRED boundaries (C9-02), server-authoritative ordering,
 * MISSED as the sweep's judgement alone, C9-08 completion, C9-03 abandonment
 * laundering, the C9-05 authorization matrix with 404 need-to-know, C9-06
 * replay and race behaviour, and the audit/timeline/outbox evidence trail.
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

const tag = `wp19_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;
const fx = {
  orgA: `${tag}_orgA`,
  orgB: `${tag}_orgB`,
  siteA1: `${tag}_siteA1`,
  siteA2: `${tag}_siteA2`,
  siteB1: `${tag}_siteB1`,
  zoneA1: `${tag}_zoneA1`,
  commanderA1: `${tag}_commanderA1`,
  dispatcherA1: `${tag}_dispatcherA1`,
  operatorA1: `${tag}_operatorA1`,
  opAlpha: `${tag}_opAlpha`,
  opBravo: `${tag}_opBravo`,
  operativeA2: `${tag}_operativeA2`,
  dispatcherB1: `${tag}_dispatcherB1`,
  incidentA1: randomUUID(),
};

async function seed(prisma: PrismaService): Promise<void> {
  await prisma.organisation.createMany({ data: [{ id: fx.orgA, name: 'WP-19 Org A' }, { id: fx.orgB, name: 'WP-19 Org B' }] });
  await prisma.site.createMany({
    data: [
      { id: fx.siteA1, organisationId: fx.orgA, name: 'A1' },
      { id: fx.siteA2, organisationId: fx.orgA, name: 'A2' },
      { id: fx.siteB1, organisationId: fx.orgB, name: 'B1' },
    ],
  });
  await prisma.zone.create({ data: { id: fx.zoneA1, siteId: fx.siteA1, name: 'North gate' } });

  const users: Array<{ id: string; org: string; role: string; site: string }> = [
    { id: fx.commanderA1, org: fx.orgA, role: 'site.commander', site: fx.siteA1 },
    { id: fx.dispatcherA1, org: fx.orgA, role: 'dispatcher', site: fx.siteA1 },
    { id: fx.operatorA1, org: fx.orgA, role: 'operator', site: fx.siteA1 },
    { id: fx.opAlpha, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.opBravo, org: fx.orgA, role: 'field.operative', site: fx.siteA1 },
    { id: fx.operativeA2, org: fx.orgA, role: 'field.operative', site: fx.siteA2 },
    { id: fx.dispatcherB1, org: fx.orgB, role: 'dispatcher', site: fx.siteB1 },
  ];
  for (const u of users) {
    await prisma.user.create({
      data: {
        id: u.id, organisationId: u.org, email: `${u.id}@example.invalid`, displayName: u.id, clearance: 5,
        roles: { create: [{ role: u.role, siteId: u.site }] },
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
      organisationId: fx.orgA, siteId: fx.siteA1, incidentType: 'wp19.test', severity: 'SEV3',
      threatState: 2, confidence: 0.9, responseMode: 'STANDARD',
    },
  });
  // C9-05 fixture: opAlpha has taken the incident duty on; opBravo has none.
  await prisma.fieldAssignment.create({
    data: {
      organisationId: fx.orgA, siteId: fx.siteA1, incidentId: fx.incidentA1, assigneeUserId: fx.opAlpha,
      assignmentType: 'INCIDENT_RESPONSE', priority: 'SEV3', status: 'ACCEPTED', deliveryState: 'REQUESTED',
      needToKnowSummary: 'wp19 fixture', idempotencyKey: `${tag}-alpha-accepted`,
      createdByUserId: fx.commanderA1, updatedByUserId: fx.commanderA1,
    },
  });
}

async function cleanup(prisma: PrismaService): Promise<void> {
  const orgs = [fx.orgA, fx.orgB];
  await prisma.patrolRunActionIdempotency.deleteMany({ where: { run: { organisationId: { in: orgs } } } });
  await prisma.patrolRunCheckpoint.updateMany({ where: { organisationId: { in: orgs } }, data: { verificationId: null } });
  await prisma.patrolCheckpointVerification.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolRunCheckpoint.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolRun.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolCheckpoint.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolRouteVersion.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.patrolRoute.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldAssignmentActionIdempotency.deleteMany({ where: { assignment: { organisationId: { in: orgs } } } });
  await prisma.fieldAssignment.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldAuditLog.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.fieldOutbox.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.incidentTimelineEntry.deleteMany({ where: { incident: { organisationId: { in: orgs } } } });
  await prisma.incident.deleteMany({ where: { organisationId: { in: orgs } } });
  await prisma.zone.deleteMany({ where: { siteId: { in: [fx.siteA1, fx.siteA2, fx.siteB1] } } });
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
  started_at: string | null;
  ended_at: string | null;
  abandon_reason: string | null;
  checkpoints: Array<{
    id: string;
    sequence_number: number;
    state: string;
    window_opens_at: string;
    late_after: string;
    missed_after: string;
    resolved_at: string | null;
    checkpoint_verification_id: string | null;
  }>;
}

interface VerifyResponse {
  verification: { id: string; recorded_at: string; timing_outcome: string };
  run_checkpoint: { id: string; state: string };
  run_status: string;
}

describe('WP-19 patrol foundation (live stack)', () => {
  let app: INestApplication;
  let base: string;
  let prisma: PrismaService;
  let sweeper: PatrolMissedSweeper;

  const post = (path: string, userId: string, body: unknown) =>
    fetch(`${base}${path}`, { method: 'POST', headers: { 'x-dev-user-id': userId, 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const get = (path: string, userId: string) => fetch(`${base}${path}`, { headers: { 'x-dev-user-id': userId } });

  /** offsets: [window_open, late_after, missed_after] per checkpoint, in ms. */
  function routeBody(offsets: Array<[number, number, number]>, overrides: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      site_id: fx.siteA1,
      name: 'Perimeter walk',
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

  async function createRoute(offsets: Array<[number, number, number]>, overrides: Record<string, unknown> = {}): Promise<RouteResponse> {
    const res = await post('/api/v1/patrol/routes', fx.commanderA1, routeBody(offsets, overrides));
    expect(res.status).toBe(201);
    return (await res.json()) as RouteResponse;
  }

  async function scheduleRun(routeId: string, overrides: Record<string, unknown> = {}): Promise<RunResponse> {
    const res = await post('/api/v1/patrol/runs', fx.dispatcherA1, {
      patrol_route_id: routeId,
      assigned_operative_user_id: fx.opAlpha,
      incident_id: null,
      scheduled_start_at: new Date().toISOString(),
      idempotency_key: `run-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
      ...overrides,
    });
    expect(res.status).toBe(201);
    return (await res.json()) as RunResponse;
  }

  async function startRun(runId: string, userId = fx.opAlpha): Promise<RunResponse> {
    const res = await post(`/api/v1/patrol/runs/${runId}/start`, userId, { idempotency_key: `start-${randomUUID()}`, trace_id: `trace-${randomUUID()}` });
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

  const verify = (runId: string, runCheckpointId: string, userId: string, body: Record<string, unknown> = {}) =>
    post(`/api/v1/patrol/runs/${runId}/checkpoints/${runCheckpointId}/verify`, userId, verifyBody(body));

  beforeAll(async () => {
    for (const [key, value] of Object.entries(STACK_ENV)) process.env[key] = value;
    // C13-01: production's sweep cadence is hard-wired and cannot be switched
    // off by configuration. A spec silences only the REPEATING timer, through
    // the DI seam, so the sweeps in flight are exactly the ones it drives.
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(PATROL_SWEEP_SCHEDULER)
      .useClass(NoopPatrolSweepScheduler)
      .compile();
    app = moduleRef.createNestApplication({ logger: false });
    await app.listen(0, '127.0.0.1');
    const address = app.getHttpServer().address();
    base = `http://127.0.0.1:${typeof address === 'object' && address ? address.port : 0}`;
    prisma = app.get(PrismaService);
    sweeper = app.get(PatrolMissedSweeper);
    await seed(prisma);
  }, 60_000);

  afterAll(async () => {
    if (app) {
      await cleanup(prisma);
      await app.close();
    }
  }, 30_000);

  // --- Routes and versions (C9-04) ----------------------------------------

  it('a commander creates a route; version 1 checkpoints carry the timing standard in sequence order', async () => {
    const route = await createRoute([[0, 60_000, 120_000], [0, 120_000, 240_000]]);
    expect(route.route_version).toBe(1);
    expect(route.checkpoints.map((c) => c.sequence_number)).toEqual([1, 2]);
    expect(await prisma.fieldAuditLog.count({ where: { organisationId: fx.orgA, kind: 'PATROL_ROUTE_CREATED', payload: { path: ['patrol_route_id'], equals: route.id } } })).toBe(1);
  });

  it('C9-09 matrix: dispatcher cannot manage routes, operator and operatives cannot read them; dispatcher can read', async () => {
    expect((await post('/api/v1/patrol/routes', fx.dispatcherA1, routeBody([[0, 1000, 2000]]))).status).toBe(403);
    expect((await get('/api/v1/patrol/routes', fx.operatorA1)).status).toBe(403);
    expect((await get('/api/v1/patrol/routes', fx.opAlpha)).status).toBe(403);
    expect((await get('/api/v1/patrol/routes', fx.dispatcherA1)).status).toBe(200);
  });

  it('route creation replay returns the established route, and a route needs at least one checkpoint', async () => {
    const body = routeBody([[0, 1000, 2000]]);
    const first = (await (await post('/api/v1/patrol/routes', fx.commanderA1, body)).json()) as RouteResponse;
    const replayRes = await post('/api/v1/patrol/routes', fx.commanderA1, body);
    expect(replayRes.status).toBe(201);
    expect(((await replayRes.json()) as RouteResponse).id).toBe(first.id);
    expect(await prisma.patrolRoute.count({ where: { organisationId: fx.orgA, name: 'Perimeter walk', idempotencyKey: body.idempotency_key as string } })).toBe(1);

    expect((await post('/api/v1/patrol/routes', fx.commanderA1, routeBody([]))).status).toBe(400);
  });

  it('a route cannot be created against a cross-site scope, a fictional site, or another tenant, and unknown zones are refused', async () => {
    expect((await post('/api/v1/patrol/routes', fx.commanderA1, routeBody([[0, 1000, 2000]], { site_id: fx.siteA2 }))).status).toBe(403);
    expect((await post('/api/v1/patrol/routes', fx.commanderA1, routeBody([[0, 1000, 2000]], { site_id: `${tag}_ghost` }))).status).toBe(403);
    expect((await post('/api/v1/patrol/routes', fx.commanderA1, routeBody([[0, 1000, 2000]], { site_id: fx.siteB1 }))).status).toBe(403);

    const withGhostZone = routeBody([[0, 1000, 2000]]);
    (withGhostZone.checkpoints as Array<Record<string, unknown>>)[0].zone_id = `${tag}_ghost_zone`;
    expect((await post('/api/v1/patrol/routes', fx.commanderA1, withGhostZone)).status).toBe(400);

    const withRealZone = routeBody([[0, 1000, 2000]]);
    (withRealZone.checkpoints as Array<Record<string, unknown>>)[0].zone_id = fx.zoneA1;
    expect((await post('/api/v1/patrol/routes', fx.commanderA1, withRealZone)).status).toBe(201);
  });

  it('C9-02: offsets out of order are refused with a 400, not persisted', async () => {
    const res = await post('/api/v1/patrol/routes', fx.commanderA1, routeBody([[5000, 1000, 2000]]));
    expect(res.status).toBe(400);
  });

  // --- Version pinning and immutability (C9-04) ----------------------------

  it('a run pins the version current at schedule time; publishing a new version never rewrites it', async () => {
    const route = await createRoute([[0, 60_000, 120_000], [0, 120_000, 240_000]]);
    const run = await scheduleRun(route.id);
    expect(run.route_version).toBe(1);

    const publishRes = await post(`/api/v1/patrol/routes/${route.id}/versions`, fx.commanderA1, {
      checkpoints: [1, 2, 3].map((n) => ({
        name: `V2 checkpoint ${n}`, zone_id: null, location: null,
        window_open_offset_ms: 0, late_after_offset_ms: 60_000, missed_after_offset_ms: 120_000,
      })),
      idempotency_key: `publish-${randomUUID()}`,
      trace_id: `trace-${randomUUID()}`,
    });
    expect(publishRes.status).toBe(201);
    expect(((await publishRes.json()) as RouteResponse).route_version).toBe(2);

    // Version 1 rows are untouched, and the already-scheduled run still pins v1:
    // starting it materialises TWO checkpoints from v1, not three from v2.
    expect(await prisma.patrolCheckpoint.count({ where: { patrolRouteId: route.id, routeVersion: 1 } })).toBe(2);
    const started = await startRun(run.id);
    expect(started.route_version).toBe(1);
    expect(started.checkpoints).toHaveLength(2);
  });

  // --- Materialisation and timing (C9-02) -----------------------------------

  it('start is the assigned operative alone; everyone else gets the 404 a nonexistent run would produce', async () => {
    const route = await createRoute([[0, 60_000, 120_000]]);
    const run = await scheduleRun(route.id);
    expect((await post(`/api/v1/patrol/runs/${run.id}/start`, fx.opBravo, { idempotency_key: 'x', trace_id: 't' })).status).toBe(404);
    expect((await get(`/api/v1/patrol/runs/${run.id}`, fx.opBravo)).status).toBe(404);
    expect((await get(`/api/v1/patrol/runs/${run.id}`, fx.dispatcherB1)).status).toBe(404);
    expect((await get(`/api/v1/patrol/runs/${run.id}`, fx.commanderA1)).status).toBe(200);
  });

  it('materialisation converts version offsets into absolute instants from the server-owned start', async () => {
    const route = await createRoute([[5_000, 60_000, 120_000]]);
    const run = await scheduleRun(route.id);
    const started = await startRun(run.id);
    expect(started.status).toBe('IN_PROGRESS');
    expect(started.started_at).not.toBeNull();
    const startedAt = new Date(started.started_at as string).getTime();
    const checkpoint = started.checkpoints[0];
    expect(new Date(checkpoint.window_opens_at).getTime() - startedAt).toBe(5_000);
    expect(new Date(checkpoint.late_after).getTime() - startedAt).toBe(60_000);
    expect(new Date(checkpoint.missed_after).getTime() - startedAt).toBe(120_000);
    expect(checkpoint.state).toBe('PENDING');
    expect(await prisma.fieldOutbox.count({ where: { payload: { path: ['patrol_run_id'], equals: run.id } } })).toBeGreaterThanOrEqual(2);
  });

  it('C9-02: arriving before the window opens is TOO_EARLY, refused without mutation', async () => {
    const route = await createRoute([[60_000, 120_000, 240_000]]);
    const run = await scheduleRun(route.id);
    const started = await startRun(run.id);
    const res = await verify(run.id, started.checkpoints[0].id, fx.opAlpha);
    expect(res.status).toBe(409);
    const row = await prisma.patrolRunCheckpoint.findUniqueOrThrow({ where: { id: started.checkpoints[0].id } });
    expect(row.state).toBe('PENDING');
    expect(await prisma.patrolCheckpointVerification.count({ where: { patrolRunId: run.id } })).toBe(0);
  });

  it('an in-window verification resolves VERIFIED with the database receipt time, and a skewed device clock changes nothing', async () => {
    const route = await createRoute([[0, 60_000, 120_000]]);
    const run = await scheduleRun(route.id);
    const started = await startRun(run.id);
    // source_at five minutes in the future: telemetry, not a veto (C9-01).
    const res = await verify(run.id, started.checkpoints[0].id, fx.opAlpha, { source_at: new Date(Date.now() + 300_000).toISOString() });
    expect(res.status).toBe(201);
    const view = (await res.json()) as VerifyResponse;
    expect(view.verification.timing_outcome).toBe('VERIFIED');
    expect(view.run_checkpoint.state).toBe('VERIFIED');
    // Single checkpoint, resolved -> system-owned completion (C9-08/C9-09).
    expect(view.run_status).toBe('COMPLETED');
    const runRow = await prisma.patrolRun.findUniqueOrThrow({ where: { id: run.id } });
    expect(runRow.status).toBe('COMPLETED');
    expect(runRow.endedAt).not.toBeNull();
    expect(await prisma.fieldAuditLog.count({ where: { kind: 'PATROL_RUN_COMPLETED', payload: { path: ['patrol_run_id'], equals: run.id } } })).toBe(1);
  });

  it('past the on-time window but before the deadline resolves LATE, and the contract forbids calling it VERIFIED', async () => {
    const route = await createRoute([[0, 0, 600_000]]);
    const run = await scheduleRun(route.id);
    const started = await startRun(run.id);
    const res = await verify(run.id, started.checkpoints[0].id, fx.opAlpha);
    expect(res.status).toBe(201);
    const view = (await res.json()) as VerifyResponse;
    expect(view.verification.timing_outcome).toBe('LATE');
    expect(view.run_checkpoint.state).toBe('LATE');
  });

  // --- Ordering (directive s.6) --------------------------------------------

  it('checkpoint N cannot be verified while a lower sequence is PENDING, and verifying in order completes the run', async () => {
    const route = await createRoute([[0, 60_000, 120_000], [0, 120_000, 240_000]]);
    const run = await scheduleRun(route.id);
    const started = await startRun(run.id);
    const [first, second] = started.checkpoints;

    const outOfOrder = await verify(run.id, second.id, fx.opAlpha);
    expect(outOfOrder.status).toBe(409);

    expect((await verify(run.id, first.id, fx.opAlpha)).status).toBe(201);
    const last = await verify(run.id, second.id, fx.opAlpha);
    expect(last.status).toBe(201);
    expect(((await last.json()) as VerifyResponse).run_status).toBe('COMPLETED');
  });

  // --- Replay and race (C9-06) ----------------------------------------------

  it('C9-06: a replayed verification returns the established record; concurrent same-key requests produce exactly one row', async () => {
    const route = await createRoute([[0, 60_000, 120_000]]);
    const run = await scheduleRun(route.id);
    const started = await startRun(run.id);
    const body = verifyBody();

    const [a, b] = await Promise.all([
      verify(run.id, started.checkpoints[0].id, fx.opAlpha, body),
      verify(run.id, started.checkpoints[0].id, fx.opAlpha, body),
    ]);
    expect(a.status).toBe(201);
    expect(b.status).toBe(201);
    const viewA = (await a.json()) as VerifyResponse;
    const viewB = (await b.json()) as VerifyResponse;
    expect(viewA.verification.id).toBe(viewB.verification.id);
    expect(await prisma.patrolCheckpointVerification.count({ where: { patrolRunId: run.id } })).toBe(1);
    expect(await prisma.fieldAuditLog.count({ where: { kind: 'PATROL_CHECKPOINT_VERIFIED', payload: { path: ['patrol_run_id'], equals: run.id } } })).toBe(1);

    // A LATER replay of the same key still returns the established record.
    const replay = await verify(run.id, started.checkpoints[0].id, fx.opAlpha, body);
    expect(replay.status).toBe(201);
    expect(((await replay.json()) as VerifyResponse).verification.id).toBe(viewA.verification.id);

    // A DIFFERENT key against the resolved checkpoint is a conflict, not a second record.
    expect((await verify(run.id, started.checkpoints[0].id, fx.opAlpha)).status).toBe(409);
    expect(await prisma.patrolCheckpointVerification.count({ where: { patrolRunId: run.id } })).toBe(1);
  });

  // --- MISSED is the sweep's judgement alone (C9-02/C9-06) ------------------

  it('past the deadline a verification is refused, the sweep stamps MISSED exactly once, and the run completes', async () => {
    const route = await createRoute([[0, 0, 0]]);
    const run = await scheduleRun(route.id);
    const started = await startRun(run.id);

    // The deadline has passed. The verify path may never stamp MISSED: it
    // refuses (EXPIRED — or the sweep already won the race, also a conflict).
    const expired = await verify(run.id, started.checkpoints[0].id, fx.opAlpha);
    expect(expired.status).toBe(409);
    expect(await prisma.patrolCheckpointVerification.count({ where: { patrolRunId: run.id } })).toBe(0);

    // Two concurrent sweeps: exactly one MISSED transition and one audit row.
    await Promise.all([sweeper.sweep(), sweeper.sweep()]);
    await sweeper.sweep();
    const row = await prisma.patrolRunCheckpoint.findUniqueOrThrow({ where: { id: started.checkpoints[0].id } });
    expect(row.state).toBe('MISSED');
    expect(row.resolvedAt).toBeNull();
    expect(row.verificationId).toBeNull();
    expect(await prisma.fieldAuditLog.count({ where: { kind: 'PATROL_CHECKPOINT_MISSED', payload: { path: ['patrol_run_checkpoint_id'], equals: row.id } } })).toBe(1);

    // C9-08: VERIFIED/LATE/MISSED all resolved -> the run completes.
    const runRow = await prisma.patrolRun.findUniqueOrThrow({ where: { id: run.id } });
    expect(runRow.status).toBe('COMPLETED');

    // And a verification after MISSED remains refused.
    expect((await verify(run.id, started.checkpoints[0].id, fx.opAlpha)).status).toBe(409);
  });

  // --- Cancel and abandon (C9-03/C9-09) -------------------------------------

  it('cancel is command authority on a run that never started', async () => {
    const route = await createRoute([[0, 60_000, 120_000]]);
    const run = await scheduleRun(route.id);
    expect((await post(`/api/v1/patrol/runs/${run.id}/cancel`, fx.opAlpha, { idempotency_key: 'x', trace_id: 't' })).status).toBe(403);
    const res = await post(`/api/v1/patrol/runs/${run.id}/cancel`, fx.dispatcherA1, { idempotency_key: `cancel-${randomUUID()}`, trace_id: 't' });
    expect(res.status).toBe(201);
    const view = (await res.json()) as RunResponse;
    expect(view.status).toBe('CANCELLED');
    expect(view.started_at).toBeNull();
    expect(view.ended_at).not.toBeNull();

    const startedRoute = await createRoute([[0, 60_000, 120_000]]);
    const startedRun = await scheduleRun(startedRoute.id);
    await startRun(startedRun.id);
    expect((await post(`/api/v1/patrol/runs/${startedRun.id}/cancel`, fx.dispatcherA1, { idempotency_key: `cancel-${randomUUID()}`, trace_id: 't' })).status).toBe(409);
  });

  it('C9-03: abandonment cannot launder an overdue checkpoint — overdue becomes MISSED, only the future one is CANCELLED', async () => {
    const route = await createRoute([[0, 0, 0], [0, 300_000, 600_000]]);
    const run = await scheduleRun(route.id);
    const started = await startRun(run.id);

    const res = await post(`/api/v1/patrol/runs/${run.id}/abandon`, fx.opAlpha, { idempotency_key: `abandon-${randomUUID()}`, trace_id: 't' });
    expect(res.status).toBe(201);
    const view = (await res.json()) as RunResponse;
    expect(view.status).toBe('ABANDONED');
    expect(view.checkpoints.find((c) => c.sequence_number === 1)?.state).toBe('MISSED');
    expect(view.checkpoints.find((c) => c.sequence_number === 2)?.state).toBe('CANCELLED');
    expect(await prisma.fieldAuditLog.count({ where: { kind: 'PATROL_CHECKPOINT_MISSED', payload: { path: ['patrol_run_checkpoint_id'], equals: started.checkpoints[0].id } } })).toBe(1);
  });

  it('C9-09: command abandonment requires a reason and records it; a non-assignee operative cannot abandon', async () => {
    const route = await createRoute([[0, 300_000, 600_000]]);
    const run = await scheduleRun(route.id);
    await startRun(run.id);

    expect((await post(`/api/v1/patrol/runs/${run.id}/abandon`, fx.opBravo, { idempotency_key: 'x', trace_id: 't' })).status).toBe(404);
    expect((await post(`/api/v1/patrol/runs/${run.id}/abandon-command`, fx.dispatcherA1, { idempotency_key: 'x', trace_id: 't' })).status).toBe(400);

    const res = await post(`/api/v1/patrol/runs/${run.id}/abandon-command`, fx.dispatcherA1, {
      idempotency_key: `abandon-${randomUUID()}`, trace_id: 't', reason: 'Operative pulled to SEV1 response',
    });
    expect(res.status).toBe(201);
    expect(((await res.json()) as RunResponse).abandon_reason).toBe('Operative pulled to SEV1 response');
  });

  // --- Incident-linked patrols (C9-05) --------------------------------------

  it('C9-05: scheduling an incident-linked patrol requires assignment eligibility; execution requires it to be live', async () => {
    const route = await createRoute([[0, 60_000, 120_000]]);

    // opBravo has no assignment on the incident: not schedulable.
    const ineligible = await post('/api/v1/patrol/runs', fx.dispatcherA1, {
      patrol_route_id: route.id, assigned_operative_user_id: fx.opBravo, incident_id: fx.incidentA1,
      scheduled_start_at: new Date().toISOString(), idempotency_key: `run-${randomUUID()}`, trace_id: 't',
    });
    expect(ineligible.status).toBe(400);

    // A cross-site incident is indistinguishable from a fictional one.
    const wrongIncident = await post('/api/v1/patrol/runs', fx.dispatcherA1, {
      patrol_route_id: route.id, assigned_operative_user_id: fx.opAlpha, incident_id: randomUUID(),
      scheduled_start_at: new Date().toISOString(), idempotency_key: `run-${randomUUID()}`, trace_id: 't',
    });
    expect(wrongIncident.status).toBe(400);

    const run = await scheduleRun(route.id, { incident_id: fx.incidentA1 });
    expect(await prisma.incidentTimelineEntry.count({ where: { incidentId: fx.incidentA1, kind: 'PATROL_RUN_SCHEDULED' } })).toBe(1);
    const started = await startRun(run.id);
    expect(await prisma.incidentTimelineEntry.count({ where: { incidentId: fx.incidentA1, kind: 'PATROL_RUN_STARTED' } })).toBe(1);

    // The assignment goes terminal mid-run: verification is refused (C9-05).
    await prisma.fieldAssignment.updateMany({ where: { organisationId: fx.orgA, incidentId: fx.incidentA1, assigneeUserId: fx.opAlpha }, data: { status: 'COMPLETED' } });
    expect((await verify(run.id, started.checkpoints[0].id, fx.opAlpha)).status).toBe(409);

    await prisma.fieldAssignment.updateMany({ where: { organisationId: fx.orgA, incidentId: fx.incidentA1, assigneeUserId: fx.opAlpha }, data: { status: 'ACCEPTED' } });
    expect((await verify(run.id, started.checkpoints[0].id, fx.opAlpha)).status).toBe(201);
    expect(await prisma.incidentTimelineEntry.count({ where: { incidentId: fx.incidentA1, kind: 'PATROL_CHECKPOINT_VERIFIED' } })).toBe(1);
    expect(await prisma.incidentTimelineEntry.count({ where: { incidentId: fx.incidentA1, kind: 'PATROL_RUN_COMPLETED' } })).toBe(1);
  });

  // --- Read scoping (C9-05) -------------------------------------------------

  it('an operative lists only their own runs; command lists the site; a foreign tenant sees nothing', async () => {
    const route = await createRoute([[0, 60_000, 120_000]]);
    await scheduleRun(route.id);

    const ownRes = await get('/api/v1/patrol/runs', fx.opAlpha);
    expect(ownRes.status).toBe(200);
    const own = (await ownRes.json()) as Array<{ assigned_operative_user_id: string }>;
    expect(own.length).toBeGreaterThan(0);
    expect(own.every((run) => run.assigned_operative_user_id === fx.opAlpha)).toBe(true);

    const bravoRes = await get('/api/v1/patrol/runs', fx.opBravo);
    expect(((await bravoRes.json()) as unknown[]).length).toBe(0);

    const commandRes = await get('/api/v1/patrol/runs', fx.dispatcherA1);
    expect(((await commandRes.json()) as unknown[]).length).toBeGreaterThan(0);

    const foreignRes = await get('/api/v1/patrol/runs', fx.dispatcherB1);
    expect(((await foreignRes.json()) as unknown[]).length).toBe(0);

    expect((await get('/api/v1/patrol/runs', fx.operatorA1)).status).toBe(403);
  });

  it('a wrong-run checkpoint id is refused: the pair must belong together', async () => {
    const routeA = await createRoute([[0, 60_000, 120_000]]);
    const routeB = await createRoute([[0, 60_000, 120_000]]);
    const runA = await scheduleRun(routeA.id);
    const runB = await scheduleRun(routeB.id);
    const startedA = await startRun(runA.id);
    await startRun(runB.id);

    // A checkpoint from run A presented against run B: 404, no mutation.
    const res = await verify(runB.id, startedA.checkpoints[0].id, fx.opAlpha);
    expect(res.status).toBe(404);
    expect(await prisma.patrolCheckpointVerification.count({ where: { patrolRunId: { in: [runA.id, runB.id] } } })).toBe(0);
  });
});
