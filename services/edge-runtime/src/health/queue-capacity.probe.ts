import { Inject, Injectable } from '@nestjs/common';
import { EDGE_OPERATION_STORE } from '../modules/queue/edge-queue.module';
import type { SqliteEdgeOperationStore } from '../modules/queue/edge-queue.store';
import type { DependencyStatus, EdgeReadinessProbe } from './health.types';

/**
 * THE SECOND CONDITION UNDER WHICH ACCEPTING AN OPERATION IS WORSE THAN
 * REFUSING IT.
 *
 * `EdgeQueueStorageProbe` reports the directory being unwritable. This one
 * reports the queue being FULL, which is the same fact arriving by a different
 * route: in both cases Edge cannot durably hold the next operation, and
 * accepting one anyway means telling a Field device its work is stored when it
 * is not.
 *
 * WHY `down` AND NOT SOMETHING SOFTER. `DependencyStatus` has three members and
 * none of them means "nearly full"; adding one would widen a shape three other
 * probes share. The degraded band is surfaced where it belongs instead —
 * `EdgeQueueMetrics.queued_count` against `capacity`, which an operator's
 * dashboard reads continuously — and this probe flips only at the point where
 * the store is actually refusing. The health service's own comment sets the
 * bar: readiness is about Edge being unable to do its own job locally, and a
 * full queue is precisely that.
 *
 * WHAT THIS MUST NEVER BECOME. It must not report `down` because central is
 * unreachable, because the queue is deep, or because trusted time is absent.
 * Every one of those is a condition Edge exists to work THROUGH, and a probe
 * that failed on them would take the box out of service at the exact moment the
 * site depends on it.
 */
@Injectable()
export class EdgeQueueCapacityProbe implements EdgeReadinessProbe {
  readonly name = 'queue_capacity';

  constructor(@Inject(EDGE_OPERATION_STORE) private readonly store: SqliteEdgeOperationStore) {}

  async check(): Promise<DependencyStatus> {
    return this.store.capacityState() === 'REFUSING_AT_CAPACITY' ? 'down' : 'up';
  }
}
