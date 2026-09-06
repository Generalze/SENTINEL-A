import { randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { AppModule } from '../../app.module';
import { PrismaService } from '../../prisma/prisma.service';
import { PatrolMissedSweeper } from './patrol-missed.sweeper';
import { PATROL_SWEEP_SCHEDULER } from './patrol-sweep.scheduler';
import { OUTBOX_PUBLISH_SCHEDULER } from '../../common/scheduling/outbox-publish.scheduler';
import { NoopPatrolSweepScheduler } from './patrol-sweep.scheduler.test-support';
import { NoopOutboxPublishScheduler } from '../../common/scheduling/outbox-publish.scheduler.test-support';
import { PatrolRepository } from './patrol.repository';

/**
 * TI-01 — A NOOP SCHEDULER MUST ACTUALLY MEAN NOOP.
 *
 * THE DEFECT THIS SUITE EXISTS FOR.
 *
 * `PatrolMissedSweeper.onApplicationBootstrap` used to call `this.sweep()`
 * DIRECTLY and only afterwards hand the recurring task to the injected
 * scheduler. Overriding that scheduler with a Noop therefore suppressed the
 * repeat and not the first sweep — so every live suite that booted `AppModule`
 * ran one sweep no matter what it had asked for.
 *
 * That sweep is GLOBAL. `sweepMissedOnce` matches on state, deadline and run
 * status with no organisation filter, which is correct for production — one
 * deployment serves every tenant — and fatal in a test database shared by
 * sixteen concurrently booting suites. Any suite holding a run that was
 * IN_PROGRESS with a past-deadline PENDING checkpoint could have that
 * checkpoint stamped MISSED by an unrelated suite's boot, completing the run
 * underneath it.
 *
 * That is precisely the state `m2-field-loop` holds when it asserts
 * `run_status === 'IN_PROGRESS'`, and it is why that assertion failed once and
 * passed on a re-run: the failure needed another suite to boot inside a window
 * of a few hundred milliseconds.
 *
 * WHAT IS ASSERTED HERE, AND WHY IN THIS ORDER.
 *
 *   1. a Noop-scheduled boot sweeps ZERO times          (the defect itself)
 *   2. a victim run SURVIVES concurrent boots           (the observed symptom)
 *   3. an explicit sweep still works                    (that we fixed it
 *                                                        rather than disabled
 *                                                        patrol sweeping)
 *
 * Three is not optional. A "fix" that stopped the sweeper from ever running
 * would satisfy the first two and destroy the feature.
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

const tag = `ti01_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;

const fx = {
  org: `${tag}_org`,
  site: `${tag}_site`,
  operative: `${tag}_operative`,
};

/** How many unrelated applications boot while the victim run is vulnerable. */
const CONCURRENT_BOOTS = 6;

describe('TI-01 patrol sweeper isolation (live stack)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let restoreEnv: Array<[string, string | undefined]> = [];

  /** Builds an application with the sweeper's scheduler stubbed, exactly as every live suite does. */
  async function bootWithNoopScheduler(): Promise<INestApplication> {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(PATROL_SWEEP_SCHEDULER)
      .useClass(NoopPatrolSweepScheduler)
      // TI-02: and the three outbox publishers, which used to drain every
      // tenant's pending rows at boot through no seam at all. One token
      // reaches all three, so a suite need not know how many there are.
      .overrideProvider(OUTBOX_PUBLISH_SCHEDULER)
      .useClass(NoopOutboxPublishScheduler)
      .compile();
    const instance = moduleRef.createNestApplication();
    await instance.init();
    return instance;
  }

  beforeAll(async () => {
    restoreEnv = Object.entries(STACK_ENV).map(([key]) => [key, process.env[key]]);
    for (const [key, value] of Object.entries(STACK_ENV)) process.env[key] = value;
    app = await bootWithNoopScheduler();
    prisma = app.get(PrismaService);
    await seed(prisma);
  }, 120_000);

  afterAll(async () => {
    if (prisma !== undefined) await cleanup(prisma);
    if (app !== undefined) await app.close();
    for (const [key, value] of restoreEnv) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }, 60_000);

  async function seed(db: PrismaService): Promise<void> {
    await db.organisation.create({ data: { id: fx.org, name: 'TI-01 Org' } });
    await db.site.create({ data: { id: fx.site, organisationId: fx.org, name: 'TI-01 Site' } });
    await db.user.create({
      data: {
        id: fx.operative,
        organisationId: fx.org,
        email: `${fx.operative}@example.invalid`,
        displayName: fx.operative,
        clearance: 5,
        roles: { create: [{ role: 'field.operative', siteId: fx.site }] },
      },
    });
  }

  async function cleanup(db: PrismaService): Promise<void> {
    await db.patrolRunCheckpoint.deleteMany({ where: { organisationId: fx.org } });
    await db.patrolRun.deleteMany({ where: { organisationId: fx.org } });
    await db.patrolCheckpoint.deleteMany({ where: { organisationId: fx.org } });
    await db.patrolRouteVersion.deleteMany({ where: { organisationId: fx.org } });
    await db.patrolRoute.deleteMany({ where: { organisationId: fx.org } });
    await db.fieldAuditLog.deleteMany({ where: { organisationId: fx.org } });
    await db.userRole.deleteMany({ where: { user: { organisationId: fx.org } } });
    await db.user.deleteMany({ where: { organisationId: fx.org } });
    await db.site.deleteMany({ where: { organisationId: fx.org } });
    await db.organisation.deleteMany({ where: { id: fx.org } });
  }

  let seq = 0;

  /**
   * A run in EXACTLY the state that made `m2-field-loop` a victim:
   * IN_PROGRESS, holding a PENDING checkpoint whose deadline has already
   * passed. This is a legitimate, reachable state -- m2 reaches it on purpose,
   * because its next assertion requires the VERIFY path to refuse a
   * past-deadline checkpoint with 409.
   */
  async function seedVulnerableRun(): Promise<{ runId: string; checkpointId: string }> {
    const routeId = randomUUID();
    const checkpointId = randomUUID();
    const runId = randomUUID();
    const runCheckpointId = randomUUID();
    const now = Date.now();
    seq += 1;

    await prisma.patrolRoute.create({
      data: {
        id: routeId,
        organisationId: fx.org,
        siteId: fx.site,
        name: `${tag}-route-${seq}`,
        currentVersion: 1,
        createdByUserId: fx.operative,
        idempotencyKey: `${tag}-route-${seq}`,
        traceId: `${tag}-trace-${seq}`,
      },
    });
    await prisma.patrolRouteVersion.create({
      data: {
        patrolRouteId: routeId,
        version: 1,
        organisationId: fx.org,
        siteId: fx.site,
        publishedByUserId: fx.operative,
        idempotencyKey: `${tag}-version-${seq}`,
        traceId: `${tag}-trace-${seq}`,
      },
    });
    await prisma.patrolCheckpoint.create({
      data: {
        id: checkpointId,
        patrolRouteId: routeId,
        routeVersion: 1,
        organisationId: fx.org,
        siteId: fx.site,
        sequenceNumber: 1,
        name: 'checkpoint-1',
        windowOpenOffsetMs: 0,
        lateAfterOffsetMs: 1_000,
        missedAfterOffsetMs: 2_000,
        traceId: `${tag}-trace-${seq}`,
      },
    });
    await prisma.patrolRun.create({
      data: {
        id: runId,
        organisationId: fx.org,
        siteId: fx.site,
        patrolRouteId: routeId,
        routeVersion: 1,
        assignedOperativeUserId: fx.operative,
        status: 'IN_PROGRESS',
        scheduledStartAt: new Date(now - 60_000),
        createdByUserId: fx.operative,
        idempotencyKey: `${tag}-run-${seq}`,
        traceId: `${tag}-trace-${seq}`,
      },
    });
    await prisma.patrolRunCheckpoint.create({
      data: {
        id: runCheckpointId,
        patrolRunId: runId,
        patrolCheckpointId: checkpointId,
        organisationId: fx.org,
        siteId: fx.site,
        patrolRouteId: routeId,
        routeVersion: 1,
        sequenceNumber: 1,
        windowOpensAt: new Date(now - 60_000),
        lateAfter: new Date(now - 40_000),
        // THE DEADLINE IS IN THE PAST. This is what makes the row eligible for
        // a sweep, and it is a state the domain reaches legitimately.
        missedAfter: new Date(now - 30_000),
        state: 'PENDING',
        traceId: `${tag}-trace-${seq}`,
      },
    });
    return { runId, checkpointId: runCheckpointId };
  }

  async function stateOf(runId: string, checkpointId: string): Promise<{ run: string; checkpoint: string }> {
    const run = await prisma.patrolRun.findUniqueOrThrow({ where: { id: runId }, select: { status: true } });
    const checkpoint = await prisma.patrolRunCheckpoint.findUniqueOrThrow({
      where: { id: checkpointId },
      select: { state: true },
    });
    return { run: run.status, checkpoint: checkpoint.state };
  }

  // -------------------------------------------------------------------------
  // TI01-08 — the defect itself
  // -------------------------------------------------------------------------

  it('a Noop-scheduled application performs ZERO sweeps during bootstrap', async () => {
    // Spied on the PROTOTYPE, before the application is built, so the count
    // covers the instance Nest constructs rather than one this test made.
    const spy = vi.spyOn(PatrolRepository.prototype, 'sweepMissedOnce');
    spy.mockClear();

    const other = await bootWithNoopScheduler();
    try {
      expect(spy).toHaveBeenCalledTimes(0);
    } finally {
      await other.close();
      spy.mockRestore();
    }
  }, 120_000);

  // -------------------------------------------------------------------------
  // TI01-09 — the observed symptom, reproduced deliberately
  // -------------------------------------------------------------------------

  it('a vulnerable run survives concurrent unrelated application boots', async () => {
    const { runId, checkpointId } = await seedVulnerableRun();
    expect(await stateOf(runId, checkpointId)).toEqual({ run: 'IN_PROGRESS', checkpoint: 'PENDING' });

    // Unrelated suites booting while the victim is vulnerable. Before TI-01
    // each of these performed a global sweep and any one of them would stamp
    // this checkpoint MISSED.
    const others = await Promise.all(Array.from({ length: CONCURRENT_BOOTS }, () => bootWithNoopScheduler()));
    try {
      expect(await stateOf(runId, checkpointId)).toEqual({ run: 'IN_PROGRESS', checkpoint: 'PENDING' });
    } finally {
      await Promise.all(others.map((instance) => instance.close()));
    }
  }, 180_000);

  // -------------------------------------------------------------------------
  // TI01-10 — proof we fixed the seam rather than disabling the feature
  // -------------------------------------------------------------------------

  it('an explicitly invoked sweep still marks an eligible checkpoint MISSED', async () => {
    const { runId, checkpointId } = await seedVulnerableRun();
    expect(await stateOf(runId, checkpointId)).toEqual({ run: 'IN_PROGRESS', checkpoint: 'PENDING' });

    // The OWNED seam: the sweeper invoked on purpose, by the party that wants
    // the transition, exactly as a patrol suite should invoke it.
    const swept = await app.get(PatrolMissedSweeper).sweep();
    expect(swept).toBeGreaterThanOrEqual(1);

    const after = await stateOf(runId, checkpointId);
    expect(after.checkpoint).toBe('MISSED');
    // The run's own lifecycle rules still apply -- the single checkpoint is
    // resolved, so the run is no longer in progress. TI-01 changed who starts
    // the sweep, never what a sweep does.
    expect(after.run).not.toBe('IN_PROGRESS');
  }, 120_000);

  it('a checkpoint whose deadline has NOT passed is left alone by an explicit sweep', async () => {
    const routeId = randomUUID();
    const checkpointId = randomUUID();
    const runId = randomUUID();
    const runCheckpointId = randomUUID();
    const now = Date.now();
    seq += 1;

    await prisma.patrolRoute.create({
      data: {
        id: routeId, organisationId: fx.org, siteId: fx.site, name: `${tag}-route-${seq}`, currentVersion: 1,
        createdByUserId: fx.operative, idempotencyKey: `${tag}-route-${seq}`, traceId: `${tag}-trace-${seq}`,
      },
    });
    await prisma.patrolRouteVersion.create({
      data: {
        patrolRouteId: routeId, version: 1, organisationId: fx.org, siteId: fx.site,
        publishedByUserId: fx.operative, idempotencyKey: `${tag}-version-${seq}`, traceId: `${tag}-trace-${seq}`,
      },
    });
    await prisma.patrolCheckpoint.create({
      data: {
        id: checkpointId, patrolRouteId: routeId, routeVersion: 1, organisationId: fx.org, siteId: fx.site,
        sequenceNumber: 1, name: 'checkpoint-1', windowOpenOffsetMs: 0, lateAfterOffsetMs: 1_000,
        missedAfterOffsetMs: 2_000, traceId: `${tag}-trace-${seq}`,
      },
    });
    await prisma.patrolRun.create({
      data: {
        id: runId, organisationId: fx.org, siteId: fx.site, patrolRouteId: routeId, routeVersion: 1,
        assignedOperativeUserId: fx.operative, status: 'IN_PROGRESS', scheduledStartAt: new Date(now),
        createdByUserId: fx.operative, idempotencyKey: `${tag}-run-${seq}`, traceId: `${tag}-trace-${seq}`,
      },
    });
    await prisma.patrolRunCheckpoint.create({
      data: {
        id: runCheckpointId, patrolRunId: runId, patrolCheckpointId: checkpointId, organisationId: fx.org,
        siteId: fx.site, patrolRouteId: routeId, routeVersion: 1, sequenceNumber: 1,
        windowOpensAt: new Date(now),
        lateAfter: new Date(now + 600_000),
        // Deadline comfortably in the FUTURE.
        missedAfter: new Date(now + 900_000),
        state: 'PENDING',
        traceId: `${tag}-trace-${seq}`,
      },
    });

    await app.get(PatrolMissedSweeper).sweep();
    expect(await stateOf(runId, runCheckpointId)).toEqual({ run: 'IN_PROGRESS', checkpoint: 'PENDING' });
  }, 120_000);
});
