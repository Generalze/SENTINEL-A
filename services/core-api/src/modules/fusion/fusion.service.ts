/**
 * Fusion v1 application service (WP-05 deliverables #2-#5).
 *
 * `applyEvent` is the single entry point through which every event reaches a
 * hypothesis, whether it arrived over JetStream or was handed in directly by
 * a test. Keeping one path means the consumer cannot drift from what the
 * tests exercise.
 *
 * PIPELINE (all of it transparent, §65.1)
 * ---------------------------------------
 *   1. Correlate      — deriveCorrelationKey: pure, from the event alone.
 *   2. Map            — mapEventToSignal: EVENT_TYPE_RULES only. No rule ->
 *                       record and stop.
 *   3. Load-or-create — the hypothesis for that correlation window.
 *   4. Assess         — the certified CERT-S core's applySignal. This module
 *                       adds nothing to the state machine; it only feeds it.
 *   5. Persist        — new state, evidence arrays, explanation and any
 *                       transitions, atomically with the idempotency record.
 *   6. Emit           — hypothesis update always; incident-candidate when the
 *                       latch says so.
 *
 * REBUILDING THE CORE'S OBJECT FROM A ROW
 * ---------------------------------------
 * The core recomputes everything from the full signal history, so the row's
 * `signals` / `ignoredSignals` JSON is the authoritative state and the scalar
 * columns are materialised views of it.
 *
 * The rebuilt hypothesis is handed to the core with `transitions: []` on
 * purpose. `applySignal` only ever APPENDS to that array and never reads it,
 * so whatever comes back in `transitions` is exactly the set of transitions
 * this one signal caused — the delta to insert. The full history is never
 * loaded into memory to append one row to it.
 */

import { Inject, Injectable, Logger } from '@nestjs/common';
import type { NormalisedEvent } from '@sentinel/contracts';
import { deriveCorrelationKey, describeCorrelationKey } from './core/correlation';
import type { CorrelationKey } from './core/correlation';
import { derivePotentialImpact, mapEventToSignal } from './core/eventRules';
import { buildConfidenceExplanation } from './core/explanation';
import { applySignal, computeDiverseSupportingCount, createHypothesis, deriveSeverity } from './core/threatState';
import type { PotentialImpact, Signal, ThreatHypothesis, ThreatState } from './core/threatState';
import {
  APPLY_MAX_ATTEMPTS,
  FUSION_RULE_VERSIONS,
  HYPOTHESIS_TYPE,
  INCIDENT_CANDIDATE_STATE_THRESHOLD,
} from './fusion.constants';
import {
  readProcessedSignals,
  readSignals,
  toHypothesisDetailView,
  toHypothesisView,
  toThreatState,
} from './fusion.mapper';
import { FusionPublisherService } from './fusion-publisher.service';
import { FusionRepository } from './fusion.repository';
import type { HypothesisStateUpdate, TransitionInsert } from './fusion.repository';
import type {
  ApplyEventResult,
  HypothesisDetailView,
  HypothesisListFilter,
  HypothesisListResult,
  IncidentCandidateMessage,
} from './fusion.types';

import type { Hypothesis as HypothesisRow } from '@prisma/client';

@Injectable()
export class FusionService {
  private readonly logger = new Logger(FusionService.name);

  /**
   * Per-correlation-key serialisation inside this process.
   *
   * Correctness under concurrency is guaranteed by the database (version
   * guard + unique constraints); this queue is purely an efficiency measure,
   * so that a burst of events for the same window does not spend most of its
   * attempts losing optimistic-concurrency races to itself. Removing it would
   * be slower, never wrong.
   */
  private readonly chains = new Map<string, Promise<void>>();

  constructor(
    @Inject(FusionRepository) private readonly repository: FusionRepository,
    @Inject(FusionPublisherService) private readonly publisher: FusionPublisherService,
  ) {}

  async applyEvent(event: NormalisedEvent): Promise<ApplyEventResult> {
    const correlation = deriveCorrelationKey(event);
    return this.runExclusive(correlation.key, () => this.applyEventInner(event, correlation));
  }

  private async applyEventInner(event: NormalisedEvent, correlation: CorrelationKey): Promise<ApplyEventResult> {
    const mapping = mapEventToSignal(event);

    // --- Unmapped / condition-not-met: recorded, never assessed ---
    if (mapping.outcome === 'ignored') {
      const recorded = await this.repository.recordIgnoredEvent({
        organisationId: event.organisation_id,
        eventId: event.event_id,
        hypothesisId: null,
        correlationKey: correlation.key,
        eventType: event.event_type,
        signalKind: null,
        ignoreReason: mapping.reason,
        ruleVersion: mapping.ruleVersion,
      });
      if (!recorded) {
        return { outcome: 'duplicate', eventId: event.event_id };
      }
      this.logger.debug(
        `event ${event.event_id} (${event.event_type}) produced no signal [${mapping.reason}]; recorded against ${correlation.key}`,
      );
      return { outcome: 'ignored', eventId: event.event_id, reason: mapping.reason, correlationKey: correlation.key };
    }

    // Cheap pre-check. The authoritative guard is the UNIQUE constraint
    // inside the transaction below; this only avoids the work when we already
    // know the answer.
    const alreadyApplied = await this.repository.findAppliedEvent(event.organisation_id, event.event_id);
    if (alreadyApplied) {
      return { outcome: 'duplicate', eventId: event.event_id };
    }

    for (let attempt = 1; attempt <= APPLY_MAX_ATTEMPTS; attempt += 1) {
      const result = await this.attemptApply(event, correlation, mapping.signal, mapping.impactFamily);
      if (result !== 'conflict') {
        return result;
      }
      this.logger.warn(
        `concurrent update on hypothesis for ${correlation.key} while applying ${event.event_id}; retrying (attempt ${attempt}/${APPLY_MAX_ATTEMPTS})`,
      );
    }

    throw new Error(
      `Could not apply event ${event.event_id} to ${correlation.key} after ${APPLY_MAX_ATTEMPTS} attempts (persistent write contention)`,
    );
  }

  private async attemptApply(
    event: NormalisedEvent,
    correlation: CorrelationKey,
    signal: Signal,
    impactFamily: string | null,
  ): Promise<ApplyEventResult | 'conflict'> {
    // A brand-new window has no evidence yet, so it starts at the M1 rule's
    // floor. These seed values are overwritten by the update below on this
    // same event; they exist so the row is never momentarily inconsistent.
    const seedImpact = derivePotentialImpact([]);
    const row = await this.repository.loadOrCreateForWindow({
      correlation,
      type: HYPOTHESIS_TYPE,
      potentialImpact: seedImpact,
      operationalSeverity: deriveSeverity(0, seedImpact),
      confidenceExplanation: buildConfidenceExplanation(
        createHypothesis('', seedImpact),
        describeCorrelationKey(correlation),
        FUSION_RULE_VERSIONS,
      ),
      ruleVersions: [...FUSION_RULE_VERSIONS],
    });

    // --- Potential impact (M1 placeholder rule) ---
    // Computed BEFORE applySignal, because the core derives operational
    // severity from the hypothesis's potential impact. A quarantined source's
    // family is excluded for the same reason the core drops the signal itself
    // (rule 1): evidence from a source we do not trust must not move any
    // output, and potential impact is an output.
    const contributesFamily = impactFamily !== null && signal.sourceTrust !== 'quarantined';
    const supportingImpactFamilies = [
      ...new Set(contributesFamily ? [...row.supportingImpactFamilies, impactFamily] : row.supportingImpactFamilies),
    ].sort();
    const potentialImpact = derivePotentialImpact(supportingImpactFamilies);

    const previous = this.rebuildHypothesis(row, potentialImpact);
    const next = applySignal(previous, signal);

    const supportingEventIds = next.signals.filter((s) => s.kind === 'SUPPORTING').map((s) => s.signalId);
    const contradictingEventIds = next.signals.filter((s) => s.kind === 'CONTRADICTING').map((s) => s.signalId);
    const confidenceExplanation = buildConfidenceExplanation(
      next,
      describeCorrelationKey(correlation),
      FUSION_RULE_VERSIONS,
    );

    const latch = this.decideLatch(row, next.state);

    const update: HypothesisStateUpdate = {
      state: next.state,
      detectionConfidence: next.detectionConfidence,
      threatProbability: next.threatProbability,
      potentialImpact: next.potentialImpact,
      operationalSeverity: next.operationalSeverity,
      sourceDiversity: computeDiverseSupportingCount(next.signals),
      supportingEventIds,
      contradictingEventIds,
      confidenceExplanation,
      ruleVersions: [...FUSION_RULE_VERSIONS],
      signals: next.signals,
      ignoredSignals: next.ignoredSignals,
      supportingImpactFamilies,
      incidentCandidateLatched: latch.latched,
      incidentCandidateDeEscalated: latch.deEscalated,
      incidentCandidateEmissions: latch.emissions,
    };

    const occurredAt = new Date(event.occurred_at);
    const transitions: TransitionInsert[] = next.transitions.map((transition) => ({
      fromState: transition.from,
      toState: transition.to,
      eventId: transition.signalId,
      reason: transition.reason,
      ruleVersions: [...FUSION_RULE_VERSIONS],
      occurredAt,
    }));

    const outcome = await this.repository.applyEvent({
      hypothesisId: row.id,
      expectedVersion: row.version,
      firstTransitionSequence: row.transitionCount,
      organisationId: event.organisation_id,
      update,
      transitions,
      appliedEvent: {
        organisationId: event.organisation_id,
        eventId: event.event_id,
        hypothesisId: row.id,
        correlationKey: correlation.key,
        eventType: event.event_type,
        signalKind: signal.kind,
        ignoreReason: null,
        ruleVersion: FUSION_RULE_VERSIONS[0],
      },
    });

    if (outcome.status === 'conflict') {
      return 'conflict';
    }
    if (outcome.status === 'duplicate') {
      return { outcome: 'duplicate', eventId: event.event_id };
    }

    const view = toHypothesisView(outcome.row);
    const emittedAt = new Date().toISOString();
    const previousState = toThreatState(row.state);

    const candidate: IncidentCandidateMessage | null = latch.emit
      ? {
          schema_version: 1,
          incident_candidate_id: outcome.row.incidentCandidateId,
          hypothesis_id: outcome.row.id,
          organisation_id: view.organisation_id,
          site_id: view.site_id,
          zone_id: view.zone_id,
          threat_state: view.state,
          detection_confidence: view.detection_confidence,
          threat_probability: view.threat_probability,
          potential_impact: view.potential_impact,
          operational_severity: view.operational_severity,
          supporting_event_ids: view.supporting_event_ids,
          contradicting_event_ids: view.contradicting_event_ids,
          confidence_explanation: view.confidence_explanation,
          rule_or_model_versions: view.rule_or_model_versions,
          re_escalation: latch.reEscalation,
          emission_number: latch.emissions,
          triggering_event_id: event.event_id,
          emitted_at: emittedAt,
        }
      : null;

    const updateMessage = {
      schema_version: 1 as const,
      hypothesis: view,
      triggering_event_id: event.event_id,
      previous_state: previousState,
      state_changed: next.state !== previousState,
      emitted_at: emittedAt,
    };

    await this.publisher.publishHypothesisUpdate(updateMessage);
    if (candidate) {
      await this.publisher.publishIncidentCandidate(candidate);
    }

    return {
      outcome: 'applied',
      eventId: event.event_id,
      hypothesisId: outcome.row.id,
      previousState,
      state: view.state,
      stateChanged: updateMessage.state_changed,
      incidentCandidate: candidate,
      update: updateMessage,
    };
  }

  // -------------------------------------------------------------------------
  // Read side (deliverable #6)
  // -------------------------------------------------------------------------

  /**
   * Tenant-scoped list. `filter.organisationId` is mandatory in the type, and
   * the repository puts it into the WHERE clause unconditionally, so there is
   * no shape of query that can read across organisations.
   */
  async list(filter: HypothesisListFilter): Promise<HypothesisListResult> {
    const { items, nextCursor } = await this.repository.list(filter);
    return { items: items.map(toHypothesisView), next_cursor: nextCursor };
  }

  /**
   * Tenant-scoped fetch by id, with the append-only transition log.
   *
   * Returns null both when the hypothesis does not exist and when it belongs
   * to another organisation — the caller turns both into the same 404, so the
   * API never confirms the existence of another tenant's data.
   */
  async getDetail(organisationId: string, id: string): Promise<HypothesisDetailView | null> {
    const row = await this.repository.findById(id);
    if (!row || row.organisationId !== organisationId) {
      return null;
    }
    const transitions = await this.repository.listTransitions(row.id);
    return toHypothesisDetailView(row, transitions);
  }

  /**
   * Reconstructs the core's in-memory hypothesis from a persisted row.
   *
   * `transitions: []` is deliberate — see the module doc: what comes back
   * from `applySignal` is then exactly the delta to append.
   */
  private rebuildHypothesis(row: HypothesisRow, impact: PotentialImpact): ThreatHypothesis {
    const state = toThreatState(row.state);
    return {
      id: row.id,
      state,
      detectionConfidence: row.detectionConfidence,
      threatProbability: row.threatProbability,
      potentialImpact: impact,
      // Recomputed by applySignal from (state, potentialImpact); seeded
      // consistently so the rebuilt object is never internally contradictory.
      operationalSeverity: deriveSeverity(state, impact),
      signals: readProcessedSignals(row.signals),
      ignoredSignals: readSignals(row.ignoredSignals),
      transitions: [],
    };
  }

  /**
   * Incident-candidate latch (directive deliverable #5).
   *
   *   state >= 2 and not latched  -> emit, latch. `re_escalation` is true iff
   *                                  the hypothesis had previously been
   *                                  latched and fell back below the
   *                                  threshold.
   *   state >= 2 and latched      -> no emission (this is the "exactly once"
   *                                  part).
   *   state <  2 and latched      -> release the latch and remember that a
   *                                  de-escalation happened, so the next
   *                                  crossing is marked as a re-escalation.
   *
   * Two columns are required: the latch alone cannot tell a first emission
   * from a re-emission once it has been released.
   */
  private decideLatch(
    row: HypothesisRow,
    state: ThreatState,
  ): { latched: boolean; deEscalated: boolean; emissions: number; emit: boolean; reEscalation: boolean } {
    if (state >= INCIDENT_CANDIDATE_STATE_THRESHOLD) {
      if (row.incidentCandidateLatched) {
        return {
          latched: true,
          deEscalated: row.incidentCandidateDeEscalated,
          emissions: row.incidentCandidateEmissions,
          emit: false,
          reEscalation: false,
        };
      }
      return {
        latched: true,
        deEscalated: false,
        emissions: row.incidentCandidateEmissions + 1,
        emit: true,
        reEscalation: row.incidentCandidateDeEscalated,
      };
    }

    return {
      latched: false,
      deEscalated: row.incidentCandidateDeEscalated || row.incidentCandidateLatched,
      emissions: row.incidentCandidateEmissions,
      emit: false,
      reEscalation: false,
    };
  }

  /** Serialises work per key; see the `chains` field doc for why this is an optimisation only. */
  private runExclusive<T>(key: string, work: () => Promise<T>): Promise<T> {
    const previous = this.chains.get(key) ?? Promise.resolve();
    const run = previous.then(work, work);
    const settled = run.then(
      () => undefined,
      () => undefined,
    );
    this.chains.set(key, settled);
    void settled.then(() => {
      if (this.chains.get(key) === settled) {
        this.chains.delete(key);
      }
    });
    return run;
  }
}
