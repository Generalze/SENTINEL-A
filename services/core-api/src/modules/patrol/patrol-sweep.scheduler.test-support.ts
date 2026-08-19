import type { PatrolSweepScheduler } from './patrol-sweep.scheduler';

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
 * A scheduler that never fires. The boot sweep still runs (it is not the
 * scheduler's business), so a spec sees a deterministic single sweep at boot
 * and thereafter only the sweeps it drives itself.
 */
export class NoopPatrolSweepScheduler implements PatrolSweepScheduler {
  start(): void {
    /* deliberately nothing: the whole purpose of this double */
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
  stopCount = 0;
  private run: (() => void) | undefined;

  start(run: () => void, intervalMs: number): void {
    this.run = run;
    this.starts.push(intervalMs);
  }

  stop(): void {
    this.stopCount += 1;
    this.run = undefined;
  }

  /** Fires the scheduled callback once, on the test's own terms. */
  fire(): void {
    this.run?.();
  }
}
