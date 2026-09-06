import type { OutboxPublishScheduler, OutboxPublishStartOptions } from './outbox-publish.scheduler';

/**
 * TI-02 test doubles for the outbox publish cadence.
 *
 * These exist ONLY so a spec can stop three ambient, cross-tenant drain loops
 * from racing it. They are never bound by a real module; a spec substitutes one
 * explicitly via `Test.createTestingModule(...).overrideProvider(
 * OUTBOX_PUBLISH_SCHEDULER)`, which is test-harness wiring with no runtime or
 * configuration counterpart. There is deliberately no env var, config field or
 * HTTP route that reaches them — see the header of
 * `outbox-publish.scheduler.ts` for why.
 */

/**
 * A scheduler that never fires ANYTHING — not the boot sweep, not the repeat.
 *
 * Before TI-02 there was nothing to install here: all three publishers ran
 * `await this.sweep()` inline in `onApplicationBootstrap` and then created
 * their own timer, so every live suite that booted `AppModule` drained the
 * shared outbox tables of every other suite's pending rows. Declining to do
 * anything here now means exactly what it says.
 */
export class NoopOutboxPublishScheduler implements OutboxPublishScheduler {
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
 * a publisher invented, and that production asks for the boot sweep.
 */
export class RecordingOutboxPublishScheduler implements OutboxPublishScheduler {
  readonly starts: number[] = [];
  /** What each `start` asked for, so a test can prove production wants the boot sweep. */
  readonly immediateRequests: boolean[] = [];
  stopCount = 0;
  private run: (() => Promise<void>) | undefined;

  async start(run: () => Promise<void>, intervalMs: number, options: OutboxPublishStartOptions): Promise<void> {
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
