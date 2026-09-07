import { Inject, Injectable, Optional } from '@nestjs/common';
import type { DependencyStatus, EdgeReadinessProbe, ReadinessResult } from './health.types';
import { computeReadinessStatus, guardedProbe } from './readiness.util';

/** Multi-provider token. A lane that adds a dependency registers its probe here. */
export const EDGE_READINESS_PROBES = Symbol('EDGE_READINESS_PROBES');

/**
 * WP-29B — READINESS FOR A BOX THAT IS SUPPOSED TO WORK WHILE THE WAN IS DOWN.
 *
 * The discipline is core-api's, deliberately: every probe runs behind a hard
 * deadline, every failure becomes an honest `down`, and nothing here can throw.
 *
 * WHAT EDGE DOES *NOT* PUT IN THIS ANSWER, AND WHY
 * -----------------------------------------------
 * Central being unreachable is NOT a readiness failure. It is Edge's ENTIRE
 * REASON TO EXIST. An Edge that reported `degraded` the moment the WAN dropped
 * would be taken out of service by whatever is watching it at exactly the
 * moment the site depends on it, and the outage would look like an Edge fault
 * rather than a link fault. Central reachability belongs in
 * `EdgeQueueMetrics.consecutive_unknown_transport_results`, which is a gauge an
 * operator reads, not a gate that stops the queue.
 *
 * Absence of trusted time is likewise not a readiness failure. An Edge with no
 * valid anchor still queues, still orders, still forwards; what it cannot do is
 * witness, and central fails those operations closed at
 * NO_TRUSTWORTHY_TIME_WITNESS all by itself. Reporting `degraded` would stop
 * the queueing too, which converts a refusal into data loss. It is surfaced as
 * `EdgeQueueMetrics.trusted_time_available` instead.
 *
 * What IS a readiness failure is Edge being unable to do its own job locally —
 * above all, being unable to write to its durable queue. That is the one
 * condition under which accepting an operation is worse than refusing it, since
 * accepting means telling a Field device its work is safe when it is not.
 */
@Injectable()
export class EdgeHealthService {
  private readonly probes: readonly EdgeReadinessProbe[];

  constructor(@Optional() @Inject(EDGE_READINESS_PROBES) probes: readonly EdgeReadinessProbe[] | null) {
    this.probes = probes ?? [];
  }

  async checkReadiness(): Promise<ReadinessResult> {
    const results = await Promise.all(
      this.probes.map(async (probe): Promise<readonly [string, DependencyStatus]> => [probe.name, await guardedProbe(() => probe.check())]),
    );
    const dependencies: Record<string, DependencyStatus> = {};
    for (const [name, status] of results) dependencies[name] = status;
    return { status: computeReadinessStatus(dependencies), dependencies };
  }
}
