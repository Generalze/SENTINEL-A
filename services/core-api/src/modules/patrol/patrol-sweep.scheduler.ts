import { Injectable } from '@nestjs/common';

/**
 * WP-19/C13-01 — the patrol missed-sweep cadence is a DEPENDENCY SEAM, and
 * deliberately NOT configuration.
 *
 * WHY THIS IS NOT AN ENV VAR
 * --------------------------
 * MISSED is the server's own judgement (WP-19, directive s.3). A checkpoint is
 * missed by the clock alone: no client asserts it, no client can argue it away,
 * and the whole point of the WP-19 design is that this one verdict cannot be
 * talked out of. A configuration key that switches the sweep off — even one
 * that merely *defaults* to on — hands every deployment a silent kill-switch
 * over a safety-critical verdict. A single mistyped or copy-pasted `0` in a
 * production environment file, and missed patrol checkpoints simply stop being
 * detected, with nothing failing loudly to say so. There is no operational need
 * that justifies that risk: the cadence has never been a tuning knob, only a
 * test-determinism problem wearing a tuning knob's clothes.
 *
 * So the interval is hard-wired (see `PATROL_SWEEP_INTERVAL_MS` in
 * `patrol-missed.sweeper.ts`) and the only thing that varies is HOW the
 * recurring callback is scheduled. In production that is always
 * `IntervalPatrolSweepScheduler`, wired in `patrol.module.ts`. Nothing an
 * operator can set, send, or POST reaches this decision.
 *
 * WHY A SEAM EXISTS AT ALL
 * ------------------------
 * The integration suites drive `sweep()` explicitly, so that what they assert
 * is what they caused. An ambient timer firing on its own schedule made those
 * suites depend on lucky timing — a sweep landing between a test's action and
 * its assertion changed the counts it was about to check. That is a scheduler
 * problem, not a patrol-semantics problem, and it is fixed at the scheduler:
 * a test substitutes a scheduler that never fires (`NoopPatrolSweepScheduler`
 * in `patrol-sweep.scheduler.test-support.ts`) via Nest's `overrideProvider`,
 * which is compile-time test wiring and has no runtime representation at all.
 *
 * Note what the seam does NOT cover: the boot sweep in
 * `onApplicationBootstrap` runs unconditionally, under every scheduler. A
 * restarted server catches up on missed checkpoints immediately, and no test
 * double can skip that — the seam suppresses only the *repeating* timer.
 */

/** DI token for the sweep scheduler. Injected by `PatrolMissedSweeper`. */
export const PATROL_SWEEP_SCHEDULER = Symbol('PATROL_SWEEP_SCHEDULER');

export interface PatrolSweepScheduler {
  /**
   * Begins invoking `run` every `intervalMs` milliseconds. Called once, from
   * `onApplicationBootstrap`, after the boot sweep has already completed.
   */
  start(run: () => void, intervalMs: number): void;
  /** Stops the cadence. Idempotent — safe to call without a prior `start`. */
  stop(): void;
}

/**
 * The production scheduler, and the only one wired into `PatrolModule`.
 *
 * `unref()` keeps the timer from holding the process open on its own: the
 * sweep is work the server does *while* it is alive, never a reason to stay
 * alive. Shutdown is still explicit via `stop()` from `onModuleDestroy`.
 */
@Injectable()
export class IntervalPatrolSweepScheduler implements PatrolSweepScheduler {
  private timer: ReturnType<typeof globalThis.setInterval> | undefined;

  start(run: () => void, intervalMs: number): void {
    this.stop();
    this.timer = globalThis.setInterval(run, intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) {
      globalThis.clearInterval(this.timer);
      this.timer = undefined;
    }
  }
}
