import { Inject, Injectable, Logger, type OnApplicationBootstrap, type OnModuleDestroy } from '@nestjs/common';
import { PATROL_SWEEP_SCHEDULER, type PatrolSweepScheduler } from './patrol-sweep.scheduler';
import { PatrolRepository } from './patrol.repository';

/**
 * C13-01: the sweep cadence, HARD-WIRED.
 *
 * This is a constant and not a configuration key on purpose. MISSED is a
 * server-owned verdict, so no environment file may decide how often — or
 * whether — the server reaches it. See `patrol-sweep.scheduler.ts` for the
 * full argument and for the test-only seam that replaces the *scheduler*
 * without ever touching this number.
 */
export const PATROL_SWEEP_INTERVAL_MS = 5_000;

/**
 * WP-19 missed sweep (directive s.3): MISSED is the server's judgement alone.
 * This is deliberately a database-only job — it needs no NATS and no socket,
 * because a checkpoint is missed by the clock, not by anything a client did.
 *
 * Each candidate is re-judged under the run lock with a fresh database clock
 * inside its own transaction (C9-06), so racing a live verification is safe:
 * whichever holds the row first decides, and the loser sees the row's new
 * state rather than double-stamping it.
 */
@Injectable()
export class PatrolMissedSweeper implements OnApplicationBootstrap, OnModuleDestroy {
  private readonly logger = new Logger(PatrolMissedSweeper.name);
  private sweeping = false;

  constructor(
    @Inject(PatrolRepository) private readonly repository: PatrolRepository,
    @Inject(PATROL_SWEEP_SCHEDULER) private readonly scheduler: PatrolSweepScheduler,
  ) {}

  /**
   * The boot sweep is UNCONDITIONAL — a server that has just come back up owes
   * an immediate verdict on everything whose deadline passed while it was
   * down, and no injected scheduler can decline that. Only the repeating
   * cadence goes through the seam, which is exactly the part a test needs
   * silenced so its explicit `sweep()` calls are the only ones in flight.
   */
  async onApplicationBootstrap(): Promise<void> {
    await this.sweep();
    this.scheduler.start(() => {
      void this.sweep().catch((error: unknown) => {
        this.logger.error(`Patrol missed sweep failed: ${error instanceof Error ? error.message : String(error)}`);
      });
    }, PATROL_SWEEP_INTERVAL_MS);
  }

  onModuleDestroy(): void {
    this.scheduler.stop();
  }

  async sweep(limit = 100): Promise<number> {
    if (this.sweeping) return 0;
    this.sweeping = true;
    try {
      const transitioned = await this.repository.sweepMissedOnce(limit);
      if (transitioned > 0) this.logger.log(`marked ${transitioned} patrol checkpoint(s) MISSED`);
      return transitioned;
    } finally {
      this.sweeping = false;
    }
  }
}
