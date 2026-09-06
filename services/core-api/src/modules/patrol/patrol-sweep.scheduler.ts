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
 * TI-01 — THE SEAM NOW COVERS THE BOOT SWEEP TOO, AND HAS TO.
 *
 * This comment used to end by recording that the boot sweep in
 * `onApplicationBootstrap` ran unconditionally under every scheduler, and that
 * no test double could skip it. That was accurate, it was deliberate, and it
 * was the defect: `PatrolMissedSweeper` called `sweep()` directly and only
 * afterwards handed the recurring task to this scheduler, so a Noop suppressed
 * the repeat and not the first sweep.
 *
 * The reasoning behind the old design was that a boot sweep is a single,
 * bounded, deterministic event — a suite would see exactly one and could
 * account for it. What that missed is that `sweepMissedOnce` carries NO
 * organisation filter. It is global by design, because one deployment serves
 * every tenant. In a test database shared by sixteen concurrently booting
 * suites, "one deterministic sweep per boot" is sixteen unpredictable global
 * mutations of everyone else's rows, and a suite holding an IN_PROGRESS run
 * with a past-deadline PENDING checkpoint could have it stamped MISSED by a
 * suite that has nothing to do with patrols.
 *
 * So `start` now owns BOTH executions. Production asks for the immediate sweep
 * explicitly and gets exactly the behaviour it always had — catch up at boot,
 * then every five seconds. A Noop scheduler now genuinely means no sweeps at
 * all, which is what every suite that installed one was already asking for.
 */

/** DI token for the sweep scheduler. Injected by `PatrolMissedSweeper`. */
export const PATROL_SWEEP_SCHEDULER = Symbol('PATROL_SWEEP_SCHEDULER');

/**
 * How the sweep task is executed. The interval is NOT a parameter a caller
 * chooses freely — `PatrolMissedSweeper` passes the hard-wired constant — and
 * `runImmediately` is REQUIRED rather than optional so that every call site has
 * to state, in the diff, whether it wants a sweep at boot.
 */
export interface PatrolSweepStartOptions {
  /**
   * Whether to execute the task once before scheduling the repeat.
   *
   * Production passes `true`: a restarted server must catch up on checkpoints
   * whose deadlines passed while it was down, without waiting five seconds. A
   * test double ignores the request entirely, which is the whole point.
   */
  readonly runImmediately: boolean;
}

export interface PatrolSweepScheduler {
  /**
   * Starts the sweep task. AWAITS the immediate execution when one is
   * requested, so an application's bootstrap does not complete until the
   * catch-up sweep has, exactly as it did when the sweeper ran that sweep
   * itself.
   */
  start(run: () => Promise<void>, intervalMs: number, options: PatrolSweepStartOptions): Promise<void>;
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

  async start(run: () => Promise<void>, intervalMs: number, options: PatrolSweepStartOptions): Promise<void> {
    this.stop();
    // BEFORE the timer is installed, and awaited. A server that has been down
    // has missed checkpoints to judge, and it judges them as part of coming up
    // rather than five seconds into serving traffic.
    if (options.runImmediately) await run();
    this.timer = globalThis.setInterval(() => {
      void run();
    }, intervalMs);
    this.timer.unref?.();
  }

  stop(): void {
    if (this.timer) {
      globalThis.clearInterval(this.timer);
      this.timer = undefined;
    }
  }
}
