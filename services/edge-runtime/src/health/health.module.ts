import { Module } from '@nestjs/common';
import { EdgeQueueModule } from '../modules/queue/edge-queue.module';
import { EdgeHealthController } from './health.controller';
import { EdgeHealthService, EDGE_READINESS_PROBES } from './health.service';
import { EdgeQueueCapacityProbe } from './queue-capacity.probe';
import { EdgeQueueStorageProbe } from './queue-storage.probe';

/**
 * The probe list is assembled here from the individually injectable probes, so
 * a lane adding a dependency adds one provider and one array entry, and the
 * health service never learns what any dependency IS.
 */
@Module({
  imports: [EdgeQueueModule],
  controllers: [EdgeHealthController],
  providers: [
    EdgeQueueStorageProbe,
    EdgeQueueCapacityProbe,
    {
      provide: EDGE_READINESS_PROBES,
      inject: [EdgeQueueStorageProbe, EdgeQueueCapacityProbe],
      useFactory: (queueStorage: EdgeQueueStorageProbe, queueCapacity: EdgeQueueCapacityProbe) => [queueStorage, queueCapacity],
    },
    EdgeHealthService,
  ],
})
export class EdgeHealthModule {}
