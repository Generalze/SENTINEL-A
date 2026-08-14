/**
 * Persistence for the fusion domain.
 *
 * Two invariants this layer exists to protect:
 *
 * 1. IDEMPOTENCY (directive deliverable #4). The `(organisation_id,
 *    event_id)` UNIQUE constraint on `fusion_applied_events` is the single
 *    source of truth for "already applied". The insert of that row happens
 *    INSIDE the same transaction as the hypothesis update, so an event can
 *    never be counted twice, nor counted once and recorded zero times, even
 *    if the process dies between the two writes.
 *
 * 2. NO LOST UPDATES. The hypothesis row carries a `version` column and every
 *    update is `UPDATE ... WHERE id = ? AND version = ?`. A zero row count
 *    means a concurrent delivery updated the same window first; the caller
 *    re-reads and re-applies rather than overwriting with stale state. A
 *    plain read-modify-write would silently drop signals under concurrent
 *    redelivery, which for a threat assessment means losing evidence.
 *
 * The transition log is insert-only: no method here updates or deletes a
 * `fusion_hypothesis_transitions` row, and none exists elsewhere in the
 * module.
 */

import { Inject, Injectable } from '@nestjs/common';
import {
  Prisma,
  type FusionAppliedEvent,
  type Hypothesis as HypothesisRow,
  type HypothesisTransition as HypothesisTransitionRow,
} from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import type { CorrelationKey } from './core/correlation';
import type { IgnoreReason } from './core/eventRules';
import type { ProcessedSignal, Signal } from './core/threatState';
import { UNIQUE_CONSTRAINT_VIOLATION } from './fusion.constants';
import { decodeCursor, encodeCursor } from './fusion.mapper';
import type { HypothesisListFilter } from './fusion.types';

/** True for a Prisma unique-constraint violation from the statement it wraps. */
export function isUniqueViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === UNIQUE_CONSTRAINT_VIOLATION;
}

/**
 * Fields written on every state application.
 *
 * `signals` / `ignoredSignals` are the core's own domain objects, not Prisma
 * JSON types: converting to `Prisma.InputJsonValue` happens here, at the
 * persistence boundary, so the service layer never has to know how the
 * history is stored.
 */
export interface HypothesisStateUpdate {
  state: number;
  detectionConfidence: number;
  threatProbability: number;
  potentialImpact: string;
  operationalSeverity: string;
  sourceDiversity: number;
  supportingEventIds: string[];
  contradictingEventIds: string[];
  confidenceExplanation: string;
  ruleVersions: string[];
  signals: readonly ProcessedSignal[];
  ignoredSignals: readonly Signal[];
  supportingImpactFamilies: string[];
  incidentCandidateLatched: boolean;
  incidentCandidateDeEscalated: boolean;
  incidentCandidateEmissions: number;
}

/**
 * The signal history is plain JSON-safe data (strings, numbers, booleans)
 * produced by this module, so the cast is a type-system formality rather than
 * a claim about untrusted input. Optional fields are why the structural
 * assignment does not hold on its own: `boolean | undefined` is not a member
 * of `Prisma.InputJsonValue`, and omitted-vs-null round-trips identically
 * through Postgres `jsonb` for our purposes.
 */
function toJson(value: readonly unknown[]): Prisma.InputJsonValue {
  return value as unknown as Prisma.InputJsonValue;
}

export interface TransitionInsert {
  fromState: number;
  toState: number;
  eventId: string;
  reason: string;
  ruleVersions: string[];
  occurredAt: Date;
}

export interface AppliedEventInsert {
  organisationId: string;
  eventId: string;
  hypothesisId: string | null;
  correlationKey: string;
  eventType: string;
  signalKind: string | null;
  ignoreReason: IgnoreReason | null;
  ruleVersion: string;
}

/** Result of an attempted application. `conflict` means "retry against fresh state". */
export type ApplyOutcome =
  | { status: 'applied'; row: HypothesisRow }
  | { status: 'duplicate' }
  | { status: 'conflict' };

@Injectable()
export class FusionRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  async findByCorrelationKey(correlationKey: string): Promise<HypothesisRow | null> {
    return this.prisma.hypothesis.findUnique({ where: { correlationKey } });
  }

  async findById(id: string): Promise<HypothesisRow | null> {
    return this.prisma.hypothesis.findUnique({ where: { id } });
  }

  async findAppliedEvent(organisationId: string, eventId: string): Promise<FusionAppliedEvent | null> {
    return this.prisma.fusionAppliedEvent.findUnique({
      where: { organisationId_eventId: { organisationId, eventId } },
    });
  }

  async listTransitions(hypothesisId: string): Promise<HypothesisTransitionRow[]> {
    return this.prisma.hypothesisTransition.findMany({
      where: { hypothesisId },
      orderBy: { sequence: 'asc' },
    });
  }

  /**
   * Records an event that produced no signal (unknown type, or a rule whose
   * metadata guard was not met). `hypothesisId` stays NULL so unmapped
   * traffic never manufactures empty hypotheses, while the event is still
   * durably recorded — "ignored, but recorded".
   *
   * Returns false when the event had already been recorded (redelivery).
   */
  async recordIgnoredEvent(insert: AppliedEventInsert): Promise<boolean> {
    try {
      await this.prisma.fusionAppliedEvent.create({ data: insert });
      return true;
    } catch (error) {
      if (isUniqueViolation(error)) {
        return false;
      }
      throw error;
    }
  }

  /**
   * Load-or-create the hypothesis for a correlation window.
   *
   * The create is racy by nature — two deliveries for the same new window can
   * arrive at once — so the UNIQUE constraint on `correlation_key` is the
   * arbiter: the loser catches P2002 and re-reads the winner's row. Returning
   * a freshly-read row (never a locally-fabricated one) is what keeps the
   * `version` guard meaningful afterwards.
   */
  async loadOrCreateForWindow(params: {
    correlation: CorrelationKey;
    type: string;
    potentialImpact: string;
    operationalSeverity: string;
    confidenceExplanation: string;
    ruleVersions: string[];
  }): Promise<HypothesisRow> {
    const existing = await this.findByCorrelationKey(params.correlation.key);
    if (existing) {
      return existing;
    }

    try {
      return await this.prisma.hypothesis.create({
        data: {
          type: params.type,
          organisationId: params.correlation.organisationId,
          siteId: params.correlation.siteId,
          zoneId: params.correlation.zoneId,
          zoneKey: params.correlation.zoneKey,
          correlationKey: params.correlation.key,
          windowStart: params.correlation.windowStart,
          windowEnd: params.correlation.windowEnd,
          state: 0,
          detectionConfidence: 0,
          threatProbability: 0,
          potentialImpact: params.potentialImpact,
          operationalSeverity: params.operationalSeverity,
          sourceDiversity: 0,
          supportingEventIds: [],
          contradictingEventIds: [],
          confidenceExplanation: params.confidenceExplanation,
          ruleVersions: params.ruleVersions,
          signals: [],
          ignoredSignals: [],
          supportingImpactFamilies: [],
        },
      });
    } catch (error) {
      if (!isUniqueViolation(error)) {
        throw error;
      }
      const winner = await this.findByCorrelationKey(params.correlation.key);
      if (!winner) {
        // A unique violation with no row behind it means the constraint that
        // fired was not the correlation-key one; surface it rather than loop.
        throw error;
      }
      return winner;
    }
  }

  /**
   * Applies one event atomically: record it as applied, update the hypothesis
   * under its optimistic-concurrency guard, and append any transitions the
   * core produced. All three succeed or none do.
   */
  async applyEvent(params: {
    hypothesisId: string;
    expectedVersion: number;
    firstTransitionSequence: number;
    organisationId: string;
    update: HypothesisStateUpdate;
    transitions: readonly TransitionInsert[];
    appliedEvent: AppliedEventInsert;
  }): Promise<ApplyOutcome> {
    return this.prisma.$transaction(async (tx) => {
      // Insert-first: the UNIQUE constraint on (organisation_id, event_id)
      // rejects a redelivery here, before any state has been touched, and the
      // whole transaction rolls back.
      try {
        await tx.fusionAppliedEvent.create({ data: params.appliedEvent });
      } catch (error) {
        if (isUniqueViolation(error)) {
          return { status: 'duplicate' } as const;
        }
        throw error;
      }

      const updated = await tx.hypothesis.updateMany({
        where: { id: params.hypothesisId, version: params.expectedVersion },
        data: {
          state: params.update.state,
          detectionConfidence: params.update.detectionConfidence,
          threatProbability: params.update.threatProbability,
          potentialImpact: params.update.potentialImpact,
          operationalSeverity: params.update.operationalSeverity,
          sourceDiversity: params.update.sourceDiversity,
          supportingEventIds: params.update.supportingEventIds,
          contradictingEventIds: params.update.contradictingEventIds,
          confidenceExplanation: params.update.confidenceExplanation,
          ruleVersions: params.update.ruleVersions,
          signals: toJson(params.update.signals),
          ignoredSignals: toJson(params.update.ignoredSignals),
          supportingImpactFamilies: params.update.supportingImpactFamilies,
          incidentCandidateLatched: params.update.incidentCandidateLatched,
          incidentCandidateDeEscalated: params.update.incidentCandidateDeEscalated,
          incidentCandidateEmissions: params.update.incidentCandidateEmissions,
          transitionCount: params.firstTransitionSequence + params.transitions.length,
          version: { increment: 1 },
        },
      });

      if (updated.count === 0) {
        // Someone else won the race. Throwing rolls the applied-event insert
        // back, so the caller may safely re-apply the same event.
        throw new ConcurrentUpdateError();
      }

      if (params.transitions.length > 0) {
        await tx.hypothesisTransition.createMany({
          data: params.transitions.map((transition, index) => ({
            hypothesisId: params.hypothesisId,
            organisationId: params.organisationId,
            sequence: params.firstTransitionSequence + index,
            fromState: transition.fromState,
            toState: transition.toState,
            eventId: transition.eventId,
            reason: transition.reason,
            ruleVersions: transition.ruleVersions,
            occurredAt: transition.occurredAt,
          })),
        });
      }

      const row = await tx.hypothesis.findUniqueOrThrow({ where: { id: params.hypothesisId } });
      return { status: 'applied', row } as const;
    }).catch((error: unknown) => {
      if (error instanceof ConcurrentUpdateError) {
        return { status: 'conflict' } as const;
      }
      throw error;
    });
  }

  async list(filter: HypothesisListFilter): Promise<{ items: HypothesisRow[]; nextCursor: string | null }> {
    const where: Prisma.HypothesisWhereInput = {
      organisationId: filter.organisationId,
      ...(filter.siteId ? { siteId: filter.siteId } : {}),
      ...(filter.zoneKey ? { zoneKey: filter.zoneKey } : {}),
      ...(filter.minState !== undefined ? { state: { gte: filter.minState } } : {}),
      ...(filter.updatedFrom || filter.updatedTo
        ? {
            updatedAt: {
              ...(filter.updatedFrom ? { gte: filter.updatedFrom } : {}),
              ...(filter.updatedTo ? { lte: filter.updatedTo } : {}),
            },
          }
        : {}),
    };

    if (filter.cursor) {
      const cursor = decodeCursor(filter.cursor);
      const cursorDate = new Date(cursor.updatedAt);
      where.OR = [{ updatedAt: { lt: cursorDate } }, { updatedAt: cursorDate, id: { lt: cursor.id } }];
    }

    const rows = await this.prisma.hypothesis.findMany({
      where,
      orderBy: [{ updatedAt: 'desc' }, { id: 'desc' }],
      take: filter.limit + 1,
    });

    const hasMore = rows.length > filter.limit;
    const items = hasMore ? rows.slice(0, filter.limit) : rows;
    const last = items[items.length - 1];
    const nextCursor = hasMore && last ? encodeCursor({ updatedAt: last.updatedAt.toISOString(), id: last.id }) : null;

    return { items, nextCursor };
  }
}

/** Internal sentinel used to roll back a transaction that lost the version race. */
class ConcurrentUpdateError extends Error {
  constructor() {
    super('Hypothesis was updated concurrently');
    this.name = 'ConcurrentUpdateError';
  }
}
