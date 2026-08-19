import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { PatrolMissedSweeper } from './patrol-missed.sweeper';
import { IntervalPatrolSweepScheduler, PATROL_SWEEP_SCHEDULER } from './patrol-sweep.scheduler';
import { PatrolController } from './patrol.controller';
import { PatrolRepository } from './patrol.repository';
import { PatrolService } from './patrol.service';

/**
 * WP-19 patrol foundation.
 *
 * No realtime import: patrol's content-free signals ride the WP-17 Field
 * outbox (`FieldOutbox` -> `sentinel.field.updated.{org}.{site}`), which the
 * Field module already publishes and the realtime bridge already delivers.
 * This module owns definitions, executions, timing truth and the missed sweep.
 */
@Module({
  imports: [PrismaModule],
  controllers: [PatrolController],
  providers: [
    PatrolRepository,
    PatrolService,
    PatrolMissedSweeper,
    /**
     * C13-01: production always gets the real interval scheduler. This is the
     * ONLY binding of the token outside test wiring — there is no env var and
     * no config field that can swap or silence it. A spec overrides the token
     * through `Test.createTestingModule(...).overrideProvider(...)`.
     */
    { provide: PATROL_SWEEP_SCHEDULER, useClass: IntervalPatrolSweepScheduler },
  ],
  exports: [PatrolService],
})
export class PatrolModule {}
