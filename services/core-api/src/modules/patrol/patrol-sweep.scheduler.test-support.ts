import type { PatrolSweepScheduler, PatrolSweepStartOptions } from './patrol-sweep.scheduler';

/**
 * C13-01 test doubles for the patrol sweep cadence.
 *
 * These exist ONLY so a spec can stop the repeating timer from racing it. They
 * are never provided by `PatrolModule`; a spec substitutes one explicitly via
 * `Test.createTestingModule(...).overrideProvider(PATROL_SWEEP_SCHEDULER)`,
 * which is test-harness wiring with no runtime or configuration counterpart.
 * There is deliberately no env var, config field or HTTP route that reaches
 * them — see the header of `patrol-sweep.scheduler.ts` for why.
 */

/**
 * A scheduler that never fires ANYTHING.
 *
 * TI-01: this used to suppress only the repeating timer, because the boot sweep
 * was performed by `PatrolMissedSweeper` before this class was ever consulted.
 * A suite that installed this double still emitted one GLOBAL sweep across
 * every tenant in the shared test database, which is how an unrelated suite's
 * boot could stamp another suite's patrol checkpoint MISSED. `start` now owns
 * the immediate execution as well, so declining to do anything here means
 * exactly what it says.
 */
export class NoopPatrolSweepScheduler implements PatrolSweepScheduler {
  async start(): Promise<void> {
    /* deliberately nothing — including the immediate sweep. That is the point. */
  }

  stop(): void {
    /* nothing to stop */
  }
}

/**
 * A scheduler that never fires but records what it was asked to schedule, so a
 * test can assert the interval is the hard-wired constant rather than anything
 * an operator supplied.
 */
export class RecordingPatrolSweepScheduler implements PatrolSweepScheduler {
  readonly starts: number[] = [];
  /** TI-01: what each `start` asked for, so a test can prove production asks for the boot sweep. */
  readonly immediateRequests: boolean[] = [];
  stopCount = 0;
  private run: (() => Promise<void>) | undefined;

  async start(run: () => Promise<void>, intervalMs: number, options: PatrolSweepStartOptions): Promise<void> {
    this.run = run;
    this.starts.push(intervalMs);
    this.immediateRequests.push(options.runImmediately);
    // Deliberately does NOT honour `runImmediately`. This double records
    // intent; a test that wants the sweep to happen calls `fire()`.
  }

  stop(): void {
    this.stopCount += 1;
    this.run = undefined;
  }

  /** Fires the scheduled callback once, on the test's own terms. */
  async fire(): Promise<void> {
    await this.run?.();
  }
}
