import { Inject, Injectable, Logger, type OnApplicationBootstrap, type OnModuleDestroy } from '@nestjs/common';
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

  constructor(@Inject(PatrolRepository) private readonly repository: PatrolRepository) {}

  async onApplicationBootstrap(): Promise<void> {
    await this.sweep();
    this.timer = globalThis.setInterval(() => {
      void this.sweep().catch((error: unknown) => {
        this.logger.error(`Patrol missed sweep failed: ${error instanceof Error ? error.message : String(error)}`);
      });
    }, 5_000);
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
