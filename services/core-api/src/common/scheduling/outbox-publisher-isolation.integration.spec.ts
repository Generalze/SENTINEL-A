import { randomUUID } from 'node:crypto';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { AppModule } from '../../app.module';
import { FieldMessagingOutboxPublisher } from '../../modules/field-messaging/field-messaging-outbox.publisher';
import { FieldOutboxPublisher } from '../../modules/field/field-outbox.publisher';
import { IncidentsOutboxPublisher } from '../../modules/incidents/incidents-outbox.publisher';
import { IncidentsRepository } from '../../modules/incidents/incidents.repository';
import { PATROL_SWEEP_SCHEDULER } from '../../modules/patrol/patrol-sweep.scheduler';
import { NoopPatrolSweepScheduler } from '../../modules/patrol/patrol-sweep.scheduler.test-support';
import { PrismaService } from '../../prisma/prisma.service';
import { OUTBOX_PUBLISH_SCHEDULER } from './outbox-publish.scheduler';
import { NoopOutboxPublishScheduler } from './outbox-publish.scheduler.test-support';

/**
 * TI-02 — A NOOP OUTBOX SCHEDULER MUST ACTUALLY MEAN NOOP.
 *
 * THE DEFECT THIS SUITE EXISTS FOR
 * --------------------------------
 * `FieldOutboxPublisher`, `FieldMessagingOutboxPublisher` and
 * `IncidentsOutboxPublisher` each ran `await this.sweep()` directly in
 * `onApplicationBootstrap` and then installed their own `setInterval`. Neither
 * half went through an injection token — there was no token — so booting
 * `AppModule` in a test drained three outbox tables no matter what the suite
 * had asked for.
 *
 * Those drains are GLOBAL. `pendingOutbox` and the two `findMany({ where: {
 * publishedAt: null } })` calls match on publication state alone, with no
 * organisation filter, which is correct for production — one deployment serves
 * every tenant — and fatal in a test database shared by sixteen concurrently
 * booting suites: an unrelated boot claims another suite's pending rows, marks
 * them published, and the suite that was about to drive its own sweep and
 * assert on the result finds nothing left to publish.
 *
 * This is the same defect TI-01 corrected in `PatrolMissedSweeper`, in three
 * more places, and it is asserted here the same way.
 *
 * WHAT IS ASSERTED HERE, AND WHY IN THIS ORDER
 * --------------------------------------------
 *   1. a Noop-scheduled boot drains ZERO times, all three publishers
 *      (the defect itself)
 *   2. a pending row belonging to someone else SURVIVES unrelated boots
 *      (the symptom)
 *   3. an explicitly invoked sweep still publishes and marks published
 *      (that we fixed the seam rather than disabling outbox publishing)
 *
 * Three is not optional. A "fix" that stopped the publishers from ever running
 * would satisfy the first two and silently destroy realtime delivery.
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

const tag = `ti02_${Date.now()}_${Math.trunc(Math.random() * 100000)}`;

const fx = {
  org: `${tag}_org`,
  site: `${tag}_site`,
  recipient: `${tag}_recipient`,
};

/** How many unrelated applications boot while a pending row is exposed. */
const CONCURRENT_BOOTS = 6;

describe('TI-02 outbox publisher isolation (live stack)', () => {
  let app: INestApplication;
  let prisma: PrismaService;
  let restoreEnv: Array<[string, string | undefined]> = [];

  /**
   * Builds an application with BOTH background seams stubbed, exactly as every
   * live suite now does. The patrol scheduler is TI-01's; the outbox scheduler
   * is TI-02's, and one override reaches all three publishers because there is
   * one token.
   */
  async function bootWithNoopPublishers(): Promise<INestApplication> {
    const moduleRef = await Test.createTestingModule({ imports: [AppModule] })
      .overrideProvider(PATROL_SWEEP_SCHEDULER)
      .useClass(NoopPatrolSweepScheduler)
      .overrideProvider(OUTBOX_PUBLISH_SCHEDULER)
      .useClass(NoopOutboxPublishScheduler)
      .compile();
    const instance = moduleRef.createNestApplication({ logger: false });
    await instance.init();
    return instance;
  }

  beforeAll(async () => {
    restoreEnv = Object.entries(STACK_ENV).map(([key]) => [key, process.env[key]]);
    for (const [key, value] of Object.entries(STACK_ENV)) process.env[key] = value;
    app = await bootWithNoopPublishers();
    prisma = app.get(PrismaService);
    await cleanup(prisma);
  }, 120_000);

  afterAll(async () => {
    if (prisma !== undefined) await cleanup(prisma);
    if (app !== undefined) await app.close();
    for (const [key, value] of restoreEnv) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }, 60_000);

  async function cleanup(db: PrismaService): Promise<void> {
    await db.fieldOutbox.deleteMany({ where: { organisationId: fx.org } });
    await db.incidentFieldMessageOutbox.deleteMany({ where: { organisationId: fx.org } });
    await db.incidentUpdateOutbox.deleteMany({ where: { organisationId: fx.org } });
  }

  /**
   * One unpublished row in each of the three outboxes, scoped to this suite's
   * own organisation. None of these tables carries a foreign key, so the rows
   * stand alone: what is under test is the publish cadence, not the domain
   * writes that normally create them.
   *
   * Each row's `publishedAt` is read back FROM THE INSERT and asserted null
   * here rather than by a separate query. A separate query would be a race: a
   * sibling suite's own deliberate sweep is global and may legitimately publish
   * these rows a moment after they appear. What the insert returns is not
   * subject to that.
   */
  async function seedPendingRows(): Promise<{ field: string; message: string; incident: string }> {
    const field = await prisma.fieldOutbox.create({
      data: {
        organisationId: fx.org,
        siteId: fx.site,
        payload: { kind: 'FIELD_ASSIGNMENT_CREATED', assignment_id: randomUUID() },
      },
      select: { id: true, publishedAt: true },
    });
    const message = await prisma.incidentFieldMessageOutbox.create({
      data: {
        organisationId: fx.org,
        siteId: fx.site,
        recipientUserId: fx.recipient,
        payload: { incident_id: randomUUID(), message_id: randomUUID(), recipient_user_id: fx.recipient },
      },
      select: { id: true, publishedAt: true },
    });
    const incident = await prisma.incidentUpdateOutbox.create({
      data: {
        incidentId: randomUUID(),
        organisationId: fx.org,
        payload: { id: randomUUID(), kind: 'INCIDENT_UPDATED' },
      },
      select: { id: true, publishedAt: true },
    });
    // The starting state of all three, established at the moment of insert.
    expect([field.publishedAt, message.publishedAt, incident.publishedAt]).toEqual([null, null, null]);
    return { field: field.id, message: message.id, incident: incident.id };
  }

  async function publishedState(ids: { field: string; message: string; incident: string }): Promise<{
    field: Date | null;
    message: Date | null;
    incident: Date | null;
  }> {
    const [field, message, incident] = await Promise.all([
      prisma.fieldOutbox.findUniqueOrThrow({ where: { id: ids.field }, select: { publishedAt: true } }),
      prisma.incidentFieldMessageOutbox.findUniqueOrThrow({ where: { id: ids.message }, select: { publishedAt: true } }),
      prisma.incidentUpdateOutbox.findUniqueOrThrow({ where: { id: ids.incident }, select: { publishedAt: true } }),
    ]);
    return { field: field.publishedAt, message: message.publishedAt, incident: incident.publishedAt };
  }

  // -------------------------------------------------------------------------
  // TI02-01 — the defect itself
  // -------------------------------------------------------------------------

  it('a Noop-scheduled application performs ZERO outbox drains during bootstrap', async () => {
    // Spied on the PROTOTYPES, before the application is built, so the counts
    // cover the instances Nest constructs rather than any this test made.
    // `IncidentsRepository.prototype.pendingOutbox` is the repository method
    // TI-01 would have watched; the two Field publishers reach Prisma model
    // delegates, which are per-client properties and not prototype methods, so
    // their own `sweep` is the equivalent single entry point.
    const spies = [
      vi.spyOn(IncidentsRepository.prototype, 'pendingOutbox'),
      vi.spyOn(FieldOutboxPublisher.prototype, 'sweep'),
      vi.spyOn(FieldMessagingOutboxPublisher.prototype, 'sweep'),
      vi.spyOn(IncidentsOutboxPublisher.prototype, 'sweep'),
    ];
    for (const spy of spies) spy.mockClear();

    const other = await bootWithNoopPublishers();
    try {
      for (const spy of spies) expect(spy).toHaveBeenCalledTimes(0);
    } finally {
      await other.close();
      for (const spy of spies) spy.mockRestore();
    }
  }, 120_000);

  // -------------------------------------------------------------------------
  // TI02-02 — the symptom, reproduced deliberately
  // -------------------------------------------------------------------------

  it('six applications booting at once still perform ZERO outbox drains between them', async () => {
    // The symptom at the scale that produced it: before TI-02, sixteen suites
    // booting against one database meant sixteen global drains landing at
    // unpredictable moments in each other's assertions. Six simultaneous boots
    // reproduce that shape; the count that has to stay zero is the total across
    // all of them.
    //
    // WHY THIS COUNTS CALLS RATHER THAN INSPECTING ROWS.
    //
    // The obvious version of this test seeds pending rows and asserts they are
    // still unpublished after the boots. It is not sound, and it failed for a
    // reason worth writing down: an outbox drain is GLOBAL by design, and the
    // sibling suites in a parallel run invoke their own drains DELIBERATELY —
    // `m2-field-loop` sweeps the Field outbox in a loop for up to 25 seconds,
    // `field-messaging.realtime` sweeps its own. Those sweeps are legitimate
    // and they publish this suite's rows too. Asserting on shared row state
    // therefore measures the whole run's timing, not the bootstrap behaviour
    // TI-02 owns.
    //
    // So the assertion is made where the correction actually lives: no boot
    // reaches a drain at all. That is stricter than the row check, not looser
    // — a single drain fails it, whether or not it happened to find a row.
    const spies = [
      vi.spyOn(IncidentsRepository.prototype, 'pendingOutbox'),
      vi.spyOn(FieldOutboxPublisher.prototype, 'sweep'),
      vi.spyOn(FieldMessagingOutboxPublisher.prototype, 'sweep'),
      vi.spyOn(IncidentsOutboxPublisher.prototype, 'sweep'),
    ];
    for (const spy of spies) spy.mockClear();

    const others = await Promise.all(Array.from({ length: CONCURRENT_BOOTS }, () => bootWithNoopPublishers()));
    try {
      for (const spy of spies) expect(spy).toHaveBeenCalledTimes(0);
    } finally {
      await Promise.all(others.map((instance) => instance.close()));
      for (const spy of spies) spy.mockRestore();
    }
  }, 180_000);

  // -------------------------------------------------------------------------
  // TI02-03 — proof we fixed the seam rather than disabling publishing
  // -------------------------------------------------------------------------

  it('an explicitly invoked sweep still publishes each pending row and marks it published', async () => {
    // Seeded unpublished (asserted at the insert), then drained on purpose.
    const ids = await seedPendingRows();

    // The OWNED seam: each publisher invoked deliberately, by the party that
    // wants the drain, exactly as a suite that needs its rows published should
    // invoke it. These sweeps reach the real NATS connection on the live stack
    // and the real `updateMany`/`markOutboxPublished` write.
    //
    // The assertion is on the ROWS rather than on the returned counts. A count
    // would be a race in a parallel run for the reason recorded above — outbox
    // drains are global, sibling suites invoke their own, and one of them may
    // have published these rows a moment earlier, which would make a correct
    // publisher return 0 here. What must be true either way, and what would be
    // false if TI-02 had disabled publishing rather than moved its trigger, is
    // that a row that entered unpublished leaves published.
    await app.get(FieldOutboxPublisher).sweep();
    await app.get(FieldMessagingOutboxPublisher).sweep();
    await app.get(IncidentsOutboxPublisher).sweep();

    const after = await publishedState(ids);
    expect(after.field).not.toBeNull();
    expect(after.message).not.toBeNull();
    expect(after.incident).not.toBeNull();
  }, 120_000);

  it('a row already published is not published twice', async () => {
    // The other half of "we did not disable it": the drain is still idempotent
    // on its own rows, so a second explicit sweep finds nothing of ours to do.
    // TI-02 changed who starts a sweep, never what a sweep does.
    const ids = await seedPendingRows();
    await app.get(FieldOutboxPublisher).sweep();
    const first = await publishedState(ids);
    expect(first.field).not.toBeNull();

    await app.get(FieldOutboxPublisher).sweep();
    const second = await publishedState(ids);
    expect(second.field?.getTime()).toBe(first.field?.getTime());
  }, 120_000);
});
