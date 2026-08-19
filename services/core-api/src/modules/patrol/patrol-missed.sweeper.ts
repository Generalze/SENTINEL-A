import { Inject, Injectable, Logger, type OnApplicationBootstrap, type OnModuleDestroy } from '@nestjs/common';
import { AppConfigService } from '../../config/config.service';
import { PatrolRepository } from './patrol.repository';

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
  private timer: ReturnType<typeof globalThis.setInterval> | undefined;
  private sweeping = false;

  constructor(
    @Inject(PatrolRepository) private readonly repository: PatrolRepository,
    @Inject(AppConfigService) private readonly config: AppConfigService,
  ) {}

  /**
   * W22-02: the background cadence is CONFIGURED, not hard-wired.
   *
   * A zero interval disables the timer and the boot sweep together, which is
   * the whole point: a suite that drives `sweep()` explicitly must not also be
   * raced by a timer it did not ask for. Correctness never depended on the
   * cadence — MISSED is decided per checkpoint under the run lock against the
   * database clock — so removing the ambient scheduler from tests removes a
   * source of false failures without touching a single patrol rule.
   */
  async onApplicationBootstrap(): Promise<void> {
    const intervalMs = this.config.values.PATROL_SWEEP_INTERVAL_MS;
    if (intervalMs === 0) {
      this.logger.log('patrol missed sweep cadence disabled (PATROL_SWEEP_INTERVAL_MS=0); sweep() must be invoked explicitly');
      return;
    }
    await this.sweep();
    this.timer = globalThis.setInterval(() => {
      void this.sweep().catch((error: unknown) => {
        this.logger.error(`Patrol missed sweep failed: ${error instanceof Error ? error.message : String(error)}`);
      });
    }, intervalMs);
    this.timer.unref?.();
  }

  onModuleDestroy(): void {
    if (this.timer) {
      globalThis.clearInterval(this.timer);
      this.timer = undefined;
    }
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
