import { Injectable } from '@nestjs/common';

/**
 * TI-02 — the outbox publish cadence is a DEPENDENCY SEAM, and deliberately
 * NOT configuration.
 *
 * WHAT THIS IS FOR
 * ----------------
 * Three services drain a transactional outbox onto NATS on a timer:
 * `FieldOutboxPublisher` (WP-17), `FieldMessagingOutboxPublisher` (WP-18) and
 * `IncidentsOutboxPublisher`. All three were written independently and all
 * three arrived at the same shape, character for character:
 *
 *     async onApplicationBootstrap() {
 *       await this.sweep();                       // catch up on what we missed
 *       this.timer = setInterval(() => ..., 5000) // then keep draining
 *     }
 *
 * The recovery sweep at boot is right. A process that has been down has rows
 * that were committed but never published, and their subscribers are waiting
 * on a signal that will otherwise not arrive until the first tick. What was
 * wrong is that the whole cadence — boot sweep AND repeat — was written inline,
 * with no injection token at all, so nothing outside the class could decline
 * either half of it.
 *
 * WHY THAT MATTERS BEYOND TIDINESS
 * --------------------------------
 * `pendingOutbox` / `findMany({ where: { publishedAt: null } })` carry NO
 * organisation filter. That is correct for production, where one deployment
 * serves every tenant and every unpublished row is genuinely its business. In
 * a test database shared by sixteen concurrently booting suites it means each
 * unrelated boot claims and marks published every other suite's pending rows,
 * on its own schedule, in the middle of their assertions. This is the same
 * defect TI-01 corrected in `PatrolMissedSweeper`, in three more places.
 *
 * ONE SEAM, NOT THREE
 * -------------------
 * There is exactly one definition of this mechanism because there is exactly
 * one mechanism. Three structurally identical scheduler interfaces — one per
 * module — would be three things to keep in step, and this repository's
 * dearest lesson is that two definitions of one thing drift apart: the day
 * someone fixes an ordering bug in the Field scheduler is the day Incidents
 * quietly stops matching it. A suite that wants silence should also not have
 * to know how many publishers exist, or discover a new one by watching a test
 * go red. One token, overridden once, covers all three.
 *
 * The token is bound PER MODULE rather than exported from a shared module, so
 * each publisher owns its own scheduler INSTANCE and its own timer handle.
 * A single shared instance would have the three publishers overwrite each
 * other's `timer` field and only the last one would ever actually repeat.
 *
 * WHY PATROL KEEPS ITS OWN TOKEN
 * ------------------------------
 * `PATROL_SWEEP_SCHEDULER` (see `modules/patrol/patrol-sweep.scheduler.ts`)
 * is deliberately left alone. Its shape is the same because TI-02 copied it,
 * but it governs a different decision: whether the server reaches the MISSED
 * verdict at all, which WP-19 s.3 makes a safety-critical judgement that no
 * operator and no test author should be able to silence by accident while
 * reaching for something else. Collapsing the two tokens would mean a suite
 * that wanted quiet outbox publishing silently also switched off patrol's
 * verdict, or the reverse — one override, two unrelated consequences. Two
 * POLICIES, deliberately separate; one SHAPE, deliberately identical.
 *
 * WHAT IS NOT HERE
 * ----------------
 * No environment variable, no config key, no HTTP route reaches this. The
 * interval is the hard-wired constant below and the only binding of the token
 * outside test wiring is `IntervalOutboxPublishScheduler`. A test substitutes
 * a double through `Test.createTestingModule(...).overrideProvider(...)`,
 * which is compile-time harness wiring with no runtime representation at all.
 */

/**
 * The drain cadence, hard-wired.
 *
 * This is the value all three publishers already used, written inline as
 * `5_000` in each of them. It moves here unchanged: one constant, so the three
 * cannot disagree about it, and so a test can assert the interval a publisher
 * asks for is this and not something it invented.
 */
export const OUTBOX_PUBLISH_INTERVAL_MS = 5_000;

/** DI token for the outbox publish scheduler. Bound by each publishing module. */
export const OUTBOX_PUBLISH_SCHEDULER = Symbol('OUTBOX_PUBLISH_SCHEDULER');

/**
 * How the drain task is executed. The interval is NOT a parameter a caller
 * chooses freely — each publisher passes {@link OUTBOX_PUBLISH_INTERVAL_MS} —
 * and `runImmediately` is REQUIRED rather than optional so that every call
 * site has to state, in the diff, whether it wants a sweep at boot.
 */
export interface OutboxPublishStartOptions {
  /**
   * Whether to execute the task once before scheduling the repeat.
   *
   * Production passes `true`: a restarted server owes its subscribers the
   * signals for rows that were committed while it was down, and it owes them
   * at boot rather than five seconds into serving traffic. A test double
   * ignores the request entirely, which is the whole point.
   */
  readonly runImmediately: boolean;
}

export interface OutboxPublishScheduler {
  /**
   * Starts the drain task. AWAITS the immediate execution when one is
   * requested, so an application's bootstrap does not complete until the
   * recovery sweep has, exactly as it did when each publisher ran that sweep
   * itself.
   */
  start(run: () => Promise<void>, intervalMs: number, options: OutboxPublishStartOptions): Promise<void>;
  /** Stops the cadence. Idempotent — safe to call without a prior `start`. */
  stop(): void;
}

/**
 * The production scheduler, and the only one bound in a real module.
 *
 * `unref()` keeps the timer from holding the process open on its own: draining
 * the outbox is work the server does *while* it is alive, never a reason to
 * stay alive. Shutdown is still explicit via `stop()` from `onModuleDestroy`.
 */
@Injectable()
export class IntervalOutboxPublishScheduler implements OutboxPublishScheduler {
  private timer: ReturnType<typeof globalThis.setInterval> | undefined;

  async start(run: () => Promise<void>, intervalMs: number, options: OutboxPublishStartOptions): Promise<void> {
    this.stop();
    // BEFORE the timer is installed, and awaited — the order the three
    // publishers already had, preserved exactly.
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
