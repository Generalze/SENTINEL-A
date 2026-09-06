import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadConfig } from '../../config/env.schema';
import { PATROL_SWEEP_INTERVAL_MS, PatrolMissedSweeper } from './patrol-missed.sweeper';
import { IntervalPatrolSweepScheduler } from './patrol-sweep.scheduler';
import { NoopPatrolSweepScheduler, RecordingPatrolSweepScheduler } from './patrol-sweep.scheduler.test-support';
import type { PatrolRepository } from './patrol.repository';

/**
 * C13-01 — the permanent guard that the patrol missed-sweep has NO off switch.
 *
 * WP-19 s.3 makes MISSED the server's own verdict: a checkpoint is missed by
 * the clock, and no client may argue it away. A configurable sweep interval
 * quietly handed that guarantee to whoever writes the environment file — a `0`
 * in a production config, and missed checkpoints simply stop being detected,
 * silently, with every test still green. This spec fails the moment such a key
 * comes back, or the moment the interval stops being the hard-wired constant.
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

/** A repository stub that only counts sweeps — the sweep SQL is WP-19's own tests' business. */
function repositoryStub(): { repository: PatrolRepository; calls: number[] } {
  const calls: number[] = [];
  const repository = {
    sweepMissedOnce: (limit: number) => {
      calls.push(limit);
      return Promise.resolve(0);
    },
  } as unknown as PatrolRepository;
  return { repository, calls };
}

describe('C13-01: the patrol sweep cadence is not configurable', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  // --- 1. no environment key can reach the sweep ---------------------------

  it('the validated env schema produces no PATROL_SWEEP_INTERVAL_MS key at all', () => {
    const config = loadConfig(validEnv);

    expect(Object.keys(config)).not.toContain('PATROL_SWEEP_INTERVAL_MS');
    expect('PATROL_SWEEP_INTERVAL_MS' in config).toBe(false);
  });

  it('setting PATROL_SWEEP_INTERVAL_MS in the environment is inert — it never reaches config', () => {
    // The dangerous case, stated literally: an operator writes the old
    // kill-switch value into a production environment file. It must be
    // discarded by the schema rather than honoured.
    const config = loadConfig({ ...validEnv, PATROL_SWEEP_INTERVAL_MS: '0' });

    expect('PATROL_SWEEP_INTERVAL_MS' in config).toBe(false);
    expect(Object.values(config)).not.toContain(0);
  });

  // --- 2. the interval is the hard-wired constant --------------------------

  it('the sweeper schedules the cadence with the hard-wired 5000ms constant', async () => {
    expect(PATROL_SWEEP_INTERVAL_MS).toBe(5_000);

    const { repository, calls } = repositoryStub();
    const scheduler = new RecordingPatrolSweepScheduler();
    const sweeper = new PatrolMissedSweeper(repository, scheduler);

    await sweeper.onApplicationBootstrap();

    // Exactly one cadence, at exactly the constant — captured from the real
    // argument the sweeper passed, not from a value the test supplied.
    expect(scheduler.starts).toEqual([5_000]);
    expect(scheduler.starts[0]).toBe(PATROL_SWEEP_INTERVAL_MS);

    // TI-01: the sweeper ASKS for a boot sweep and no longer performs one
    // itself. That distinction is the entire correction, so it is asserted
    // directly: the request is recorded, and this double declines to honour it,
    // and therefore NO sweep has happened yet.
    expect(scheduler.immediateRequests).toEqual([true]);
    expect(calls).toEqual([]);

    // The task it handed over is the real sweep, not a stub: firing it works.
    await scheduler.fire();
    expect(calls).toEqual([100]);
  });

  it('TI-01: a Noop scheduler produces NO sweep at bootstrap', async () => {
    // The regression for the defect itself, at unit level. Before TI-01 the
    // sweeper called `sweep()` directly, so this count was 1 no matter which
    // scheduler was installed — and because `sweepMissedOnce` has no
    // organisation filter, that one sweep crossed every tenant in a shared
    // test database.
    const { repository, calls } = repositoryStub();
    const sweeper = new PatrolMissedSweeper(repository, new NoopPatrolSweepScheduler());

    await sweeper.onApplicationBootstrap();

    expect(calls).toEqual([]);
  });

  it('TI-01: the REAL scheduler still sweeps immediately at boot, then repeats', async () => {
    // The other half, and the one that matters for production: TI-01 moved who
    // owns the boot sweep, never whether it happens. A restarted server must
    // still catch up on checkpoints whose deadlines passed while it was down,
    // without waiting for the first five-second tick.
    vi.useFakeTimers();
    try {
      const { repository, calls } = repositoryStub();
      const sweeper = new PatrolMissedSweeper(repository, new IntervalPatrolSweepScheduler());

      await sweeper.onApplicationBootstrap();
      // Immediately — before any timer has advanced at all.
      expect(calls).toEqual([100]);

      await vi.advanceTimersByTimeAsync(PATROL_SWEEP_INTERVAL_MS * 2);
      expect(calls.length).toBe(3);
    } finally {
      vi.useRealTimers();
    }
  });

  it('the sweeper takes no configuration dependency it could read an interval from', () => {
    // Two constructor parameters: the repository and the scheduler token. A
    // third would mean something new can influence the cadence.
    expect(PatrolMissedSweeper.length).toBe(2);
  });

  it('the scheduled callback runs the sweep, so the cadence is real work and not a stub', async () => {
    const { repository, calls } = repositoryStub();
    const scheduler = new RecordingPatrolSweepScheduler();
    const sweeper = new PatrolMissedSweeper(repository, scheduler);

    await sweeper.onApplicationBootstrap();
    // TI-01: this double records the request for an immediate sweep and
    // declines to honour it, so nothing has run yet. The assertion that
    // matters is the next one: what was handed over is the REAL sweep.
    expect(calls).toHaveLength(0);

    await scheduler.fire();
    expect(calls).toHaveLength(1);
  });

  it('shutdown stops the cadence', async () => {
    const { repository } = repositoryStub();
    const scheduler = new RecordingPatrolSweepScheduler();
    const sweeper = new PatrolMissedSweeper(repository, scheduler);

    await sweeper.onApplicationBootstrap();
    sweeper.onModuleDestroy();

    expect(scheduler.stopCount).toBe(1);
  });

  // --- 3. the production scheduler genuinely repeats -----------------------

  it('IntervalPatrolSweepScheduler fires on the interval and stops on stop()', async () => {
    vi.useFakeTimers();
    const scheduler = new IntervalPatrolSweepScheduler();
    let fired = 0;

    // `runImmediately: false` isolates the CADENCE from the boot sweep, so the
    // count below is the timer's work alone.
    await scheduler.start(async () => {
      fired += 1;
    }, PATROL_SWEEP_INTERVAL_MS, { runImmediately: false });
    expect(fired).toBe(0);

    await vi.advanceTimersByTimeAsync(PATROL_SWEEP_INTERVAL_MS * 3);
    expect(fired).toBe(3);

    scheduler.stop();
    await vi.advanceTimersByTimeAsync(PATROL_SWEEP_INTERVAL_MS * 5);
    expect(fired).toBe(3);

    // Idempotent: a second stop (e.g. a repeated shutdown hook) is harmless.
    expect(() => {
      scheduler.stop();
    }).not.toThrow();
  });
});
