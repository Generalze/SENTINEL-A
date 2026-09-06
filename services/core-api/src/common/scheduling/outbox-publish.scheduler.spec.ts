import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadConfig } from '../../config/env.schema';
import type { NatsProvider } from '../../infra/nats.provider';
import { FieldMessagingOutboxPublisher } from '../../modules/field-messaging/field-messaging-outbox.publisher';
import { FieldOutboxPublisher } from '../../modules/field/field-outbox.publisher';
import { IncidentsOutboxPublisher } from '../../modules/incidents/incidents-outbox.publisher';
import type { IncidentsRepository } from '../../modules/incidents/incidents.repository';
import type { PrismaService } from '../../prisma/prisma.service';
import {
  IntervalOutboxPublishScheduler,
  OUTBOX_PUBLISH_INTERVAL_MS,
  type OutboxPublishScheduler,
} from './outbox-publish.scheduler';
import { NoopOutboxPublishScheduler, RecordingOutboxPublishScheduler } from './outbox-publish.scheduler.test-support';

/**
 * TI-02 — the permanent guard that all three outbox publishers drain on ONE
 * controllable cadence, and that the cadence has no off switch in production.
 *
 * THE DEFECT THIS SPEC EXISTS FOR
 * -------------------------------
 * `FieldOutboxPublisher`, `FieldMessagingOutboxPublisher` and
 * `IncidentsOutboxPublisher` each ran `await this.sweep()` inline in
 * `onApplicationBootstrap` and then created their own `setInterval`. There was
 * no injection token in any of them, so nothing could decline either half. The
 * drain query carries no organisation filter — correct in production, where
 * one deployment serves every tenant — so in a database shared by sixteen
 * concurrently booting suites every unrelated boot claimed and marked
 * published other suites' pending rows, on its own schedule.
 *
 * WHY ALL THREE ARE ASSERTED IN ONE FILE
 * --------------------------------------
 * Because they are one policy, and a policy asserted in three separate places
 * is a policy that will hold in two of them. The table below is the point: add
 * a fourth outbox publisher and it belongs in it, and the day it does not
 * behave like the other three this file says so.
 *
 * These are pure unit assertions: no live stack, no database.
 */

const validEnv = {
  DATABASE_URL: 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
  NATS_URL: 'nats://localhost:4222',
  REDIS_URL: 'redis://localhost:6379',
  S3_ENDPOINT: 'http://localhost:9000',
  S3_ACCESS_KEY: 'sentinel',
  S3_SECRET_KEY: 'sentinel123',
  S3_BUCKET: 'sentinel-dev',
};

interface Bootable {
  onApplicationBootstrap(): Promise<void>;
  onModuleDestroy(): void;
}

interface Harness {
  publisher: Bootable;
  /** The `take`/`limit` of every drain pass that actually reached the data store. */
  sweeps: number[];
}

/** What the stubbed data store does when a drain pass reaches it. */
type StoreBehaviour = 'empty' | 'unreachable';

/** NATS is configured but never reached: every fixture here returns zero rows. */
function natsStub(): NatsProvider {
  return { isConfigured: () => true, getConnection: vi.fn() } as unknown as NatsProvider;
}

/**
 * Records the pass and then behaves as asked. `unreachable` is the database
 * that is briefly down at boot — the case that must not abort application
 * start-up and must not kill the cadence.
 */
function record(sweeps: number[], behaviour: StoreBehaviour): (limit: number) => Promise<never[]> {
  return (limit: number) => {
    sweeps.push(limit);
    return behaviour === 'empty' ? Promise.resolve([]) : Promise.reject(new Error('database unreachable'));
  };
}

/**
 * Each entry builds the REAL publisher with the given scheduler and counts the
 * drain passes that reach its data store. That counter is the observable that
 * matters: it is exactly what an unrelated suite's boot used to move.
 */
const publishers: ReadonlyArray<{
  name: string;
  ctor: { readonly length: number };
  build: (scheduler: OutboxPublishScheduler, behaviour?: StoreBehaviour) => Harness;
}> = [
  {
    name: 'FieldOutboxPublisher',
    ctor: FieldOutboxPublisher,
    build: (scheduler, behaviour = 'empty') => {
      const sweeps: number[] = [];
      const take = record(sweeps, behaviour);
      const prisma = {
        fieldOutbox: { findMany: (args: { take: number }) => take(args.take) },
      } as unknown as PrismaService;
      return { publisher: new FieldOutboxPublisher(prisma, natsStub(), scheduler), sweeps };
    },
  },
  {
    name: 'FieldMessagingOutboxPublisher',
    ctor: FieldMessagingOutboxPublisher,
    build: (scheduler, behaviour = 'empty') => {
      const sweeps: number[] = [];
      const take = record(sweeps, behaviour);
      const prisma = {
        incidentFieldMessageOutbox: { findMany: (args: { take: number }) => take(args.take) },
      } as unknown as PrismaService;
      return { publisher: new FieldMessagingOutboxPublisher(prisma, natsStub(), scheduler), sweeps };
    },
  },
  {
    name: 'IncidentsOutboxPublisher',
    ctor: IncidentsOutboxPublisher,
    build: (scheduler, behaviour = 'empty') => {
      const sweeps: number[] = [];
      const take = record(sweeps, behaviour);
      const repository = { pendingOutbox: (limit: number) => take(limit) } as unknown as IncidentsRepository;
      return { publisher: new IncidentsOutboxPublisher(repository, natsStub(), scheduler), sweeps };
    },
  },
];

describe('TI-02: the outbox publish cadence is a seam, and is not configurable', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  // --- 1. no environment key can reach the cadence -------------------------

  it('the validated env schema produces no OUTBOX_PUBLISH_INTERVAL_MS key at all', () => {
    const config = loadConfig(validEnv);

    expect(Object.keys(config)).not.toContain('OUTBOX_PUBLISH_INTERVAL_MS');
    expect('OUTBOX_PUBLISH_INTERVAL_MS' in config).toBe(false);
  });

  it('setting OUTBOX_PUBLISH_INTERVAL_MS in the environment is inert — it never reaches config', () => {
    // The dangerous case, stated literally: an operator writes a kill-switch
    // value into a production environment file. It must be discarded by the
    // schema rather than honoured, or outbox delivery quietly stops.
    const config = loadConfig({ ...validEnv, OUTBOX_PUBLISH_INTERVAL_MS: '0' });

    expect('OUTBOX_PUBLISH_INTERVAL_MS' in config).toBe(false);
    expect(Object.values(config)).not.toContain(0);
  });

  it('the drain cadence is the hard-wired constant the three publishers already used', () => {
    // 5s was written inline in all three. It moved here unchanged; if it ever
    // stops being that number, that is a production change and not a refactor.
    expect(OUTBOX_PUBLISH_INTERVAL_MS).toBe(5_000);
  });

  // --- 2. one policy, proved separately for each publisher ------------------

  for (const { name, ctor, build } of publishers) {
    describe(name, () => {
      it('asks for a boot sweep and schedules the hard-wired interval', async () => {
        const scheduler = new RecordingOutboxPublishScheduler();
        const { publisher, sweeps } = build(scheduler);

        await publisher.onApplicationBootstrap();

        // Exactly one cadence, at exactly the constant — captured from the real
        // argument the publisher passed, not from a value this test supplied.
        expect(scheduler.starts).toEqual([OUTBOX_PUBLISH_INTERVAL_MS]);
        expect(scheduler.starts[0]).toBe(5_000);

        // The publisher ASKS for the boot sweep and no longer performs one
        // itself. That distinction is the entire correction, so it is asserted
        // directly: the request is recorded, this double declines to honour it,
        // and therefore no drain has happened yet.
        expect(scheduler.immediateRequests).toEqual([true]);
        expect(sweeps).toEqual([]);

        // What was handed over is the REAL drain, not a stub: firing it works.
        await scheduler.fire();
        expect(sweeps).toEqual([100]);
      });

      it('with the REAL scheduler, sweeps immediately at boot and then repeats', async () => {
        // The half that matters for production: TI-02 moved who owns the boot
        // sweep, never whether it happens. A restarted server still publishes
        // rows committed while it was down without waiting for the first tick.
        vi.useFakeTimers();
        const { publisher, sweeps } = build(new IntervalOutboxPublishScheduler());

        await publisher.onApplicationBootstrap();
        // Immediately — before any timer has advanced at all.
        expect(sweeps).toEqual([100]);

        await vi.advanceTimersByTimeAsync(OUTBOX_PUBLISH_INTERVAL_MS * 2);
        expect(sweeps.length).toBe(3);

        publisher.onModuleDestroy();
        await vi.advanceTimersByTimeAsync(OUTBOX_PUBLISH_INTERVAL_MS * 5);
        expect(sweeps.length).toBe(3);
      });

      it('with a Noop scheduler, performs NO boot sweep and NO recurrence', async () => {
        // The regression for the defect itself. Before TI-02 the first count
        // below was 1 no matter what was injected, because the publisher swept
        // before consulting anything injectable — and there was nothing to
        // inject.
        vi.useFakeTimers();
        const { publisher, sweeps } = build(new NoopOutboxPublishScheduler());

        await publisher.onApplicationBootstrap();
        expect(sweeps).toEqual([]);

        await vi.advanceTimersByTimeAsync(OUTBOX_PUBLISH_INTERVAL_MS * 10);
        expect(sweeps).toEqual([]);
      });

      it('a boot sweep that fails is contained, and the cadence survives it', async () => {
        // A database briefly unreachable at boot must not abort application
        // start-up and must not kill the repeat. The publisher wraps its own
        // drain before handing it over; the awaited boot execution now happens
        // inside the seam, so this proves the wrapping survived the move.
        vi.useFakeTimers();
        const { publisher, sweeps } = build(new IntervalOutboxPublishScheduler(), 'unreachable');

        await expect(publisher.onApplicationBootstrap()).resolves.toBeUndefined();
        expect(sweeps).toEqual([100]);

        await vi.advanceTimersByTimeAsync(OUTBOX_PUBLISH_INTERVAL_MS);
        expect(sweeps.length).toBe(2);
        publisher.onModuleDestroy();
      });

      it('shutdown stops the cadence through the seam', async () => {
        const scheduler = new RecordingOutboxPublishScheduler();
        const { publisher } = build(scheduler);

        await publisher.onApplicationBootstrap();
        publisher.onModuleDestroy();

        expect(scheduler.stopCount).toBe(1);
      });

      it('takes no configuration dependency it could read an interval from', () => {
        // Three constructor parameters: two collaborators and the scheduler
        // token. A fourth would mean something new can influence the cadence.
        expect(ctor.length).toBe(3);
      });
    });
  }

  // --- 3. the production scheduler genuinely repeats ------------------------

  it('IntervalOutboxPublishScheduler fires on the interval and stops on stop()', async () => {
    vi.useFakeTimers();
    const scheduler = new IntervalOutboxPublishScheduler();
    let fired = 0;

    // `runImmediately: false` isolates the CADENCE from the boot sweep, so the
    // count below is the timer's work alone.
    await scheduler.start(
      async () => {
        fired += 1;
      },
      OUTBOX_PUBLISH_INTERVAL_MS,
      { runImmediately: false },
    );
    expect(fired).toBe(0);

    await vi.advanceTimersByTimeAsync(OUTBOX_PUBLISH_INTERVAL_MS * 3);
    expect(fired).toBe(3);

    scheduler.stop();
    await vi.advanceTimersByTimeAsync(OUTBOX_PUBLISH_INTERVAL_MS * 5);
    expect(fired).toBe(3);

    // Idempotent: a second stop (e.g. a repeated shutdown hook) is harmless.
    expect(() => {
      scheduler.stop();
    }).not.toThrow();
  });

  it('IntervalOutboxPublishScheduler awaits the immediate run BEFORE installing the timer', async () => {
    // Order, not just occurrence. The publishers used to await their own sweep
    // and only then create the timer; if the seam installed the timer first,
    // a slow boot drain could overlap its own first tick. `sweeping` guards
    // against harm, but the order is the behaviour being preserved, so it is
    // asserted rather than assumed.
    vi.useFakeTimers();
    const scheduler = new IntervalOutboxPublishScheduler();
    const order: string[] = [];
    let release: () => void = () => {};
    const boot = new Promise<void>((resolve) => {
      release = resolve;
    });
    let first = true;

    const started = scheduler.start(
      async () => {
        if (first) {
          first = false;
          order.push('boot-start');
          await boot;
          order.push('boot-end');
          return;
        }
        order.push('tick');
      },
      OUTBOX_PUBLISH_INTERVAL_MS,
      { runImmediately: true },
    );

    // The boot drain is in flight and has not finished; advancing well past the
    // interval must produce no tick, because no timer exists yet.
    await vi.advanceTimersByTimeAsync(OUTBOX_PUBLISH_INTERVAL_MS * 3);
    expect(order).toEqual(['boot-start']);

    release();
    await started;
    expect(order).toEqual(['boot-start', 'boot-end']);

    await vi.advanceTimersByTimeAsync(OUTBOX_PUBLISH_INTERVAL_MS);
    expect(order).toEqual(['boot-start', 'boot-end', 'tick']);
    scheduler.stop();
  });
});
