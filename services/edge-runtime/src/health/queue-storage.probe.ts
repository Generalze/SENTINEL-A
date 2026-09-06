import { constants as fsConstants } from 'node:fs';
import { access } from 'node:fs/promises';
import { Inject, Injectable } from '@nestjs/common';
import { EdgeConfigService } from '../config/config.service';
import type { DependencyStatus, EdgeReadinessProbe } from './health.types';

/**
 * THE ONE DEPENDENCY WHOSE FAILURE MUST TAKE EDGE OUT OF SERVICE.
 *
 * If the durable queue directory is not writable, Edge cannot keep an operation
 * safe across a restart — and accepting one anyway means telling a Field device
 * its work is stored when it is in memory on a box that may be power-cycled by
 * a cleaner. A refusal at the door is recoverable; a silently lost duress
 * signal is not.
 *
 * The check is `W_OK` on the directory rather than a write-and-delete, because
 * a probe must not mutate the very store it is reporting on: a probe that
 * writes is a probe that can fill a disk, and one that deletes is one bad path
 * expansion away from deleting a queue.
 */
@Injectable()
export class EdgeQueueStorageProbe implements EdgeReadinessProbe {
  readonly name = 'queue_storage';

  constructor(@Inject(EdgeConfigService) private readonly config: EdgeConfigService) {}

  async check(): Promise<DependencyStatus> {
    await access(this.config.values.EDGE_QUEUE_PATH, fsConstants.W_OK);
    return 'up';
  }
}
