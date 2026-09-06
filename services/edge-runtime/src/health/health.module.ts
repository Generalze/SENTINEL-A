import { Module } from '@nestjs/common';
import { EdgeHealthController } from './health.controller';
import { EdgeHealthService, EDGE_READINESS_PROBES } from './health.service';
import { EdgeQueueStorageProbe } from './queue-storage.probe';

/**
 * The probe list is assembled here from the individually injectable probes, so
 * a lane adding a dependency adds one provider and one array entry, and the
 * health service never learns what any dependency IS.
 */
@Module({
  controllers: [EdgeHealthController],
  providers: [
    EdgeQueueStorageProbe,
    {
      provide: EDGE_READINESS_PROBES,
      inject: [EdgeQueueStorageProbe],
      useFactory: (queueStorage: EdgeQueueStorageProbe) => [queueStorage],
    },
    EdgeHealthService,
  ],
})
export class EdgeHealthModule {}
