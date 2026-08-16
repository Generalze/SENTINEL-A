import type { OperationalSeverity, PotentialImpact, ThreatState } from '@sentinel/contracts';
import type { IgnoreReason } from './core/eventRules';

/**
 * The §65.3 hypothesis record as it leaves this module — over HTTP and over
 * NATS alike. ONE type, ONE mapper (fusion.mapper.ts), so the API and the
 * published summary can never disagree, and so the §11.4 guarantee below
 * holds on both surfaces at once.
 *
 * §11.4 STRUCTURAL GUARANTEE
 * --------------------------
 * `supporting_event_ids` and `contradicting_event_ids` are both non-optional.
 * There is no partial/summary variant of this type anywhere in the module, so
 * no consumer — including the Command UI — can be handed one side of the
 * evidence without the other. Contradiction search is first-class doctrine,
 * not a field a caller may omit.
 */
export interface HypothesisView {
  schema_version: 1;

  // --- §65.3 record ---
  hypothesis_id: string;
  incident_candidate_id: string;
  type: string;
  state: ThreatState;
  supporting_event_ids: string[];
  contradicting_event_ids: string[];
  source_diversity: number;

  // --- §11.3 four separated values, never collapsed ---
  detection_confidence: number;
  threat_probability: number;
  potential_impact: PotentialImpact;
  operational_severity: OperationalSeverity;

  confidence_explanation: string;
  created_at: string;
  updated_at: string;
  rule_or_model_versions: string[];

  // --- Correlation context (§65.2), beyond the §65.3 field list ---
  organisation_id: string;
  site_id: string;
  zone_id: string | null;
  /** `zone_id ?? 'site-wide'` — the value used in the correlation key. */
  zone_key: string;
  correlation_window_start: string;
  correlation_window_end: string;

  // --- Incident-candidate latch state (directive deliverable #5) ---
  incident_candidate_emitted: boolean;
  incident_candidate_emissions: number;

  /** Human-readable state name, so a client never has to hard-code the 0..5 mapping. */
  state_name: string;
}

/** A single row of the append-only transition log, as returned by the detail route. */
export interface HypothesisTransitionView {
  sequence: number;
  from_state: ThreatState;
  to_state: ThreatState;
  from_state_name: string;
  to_state_name: string;
  event_id: string;
  reason: string;
  rule_or_model_versions: string[];
  occurred_at: string;
  recorded_at: string;
}

export interface HypothesisDetailView extends HypothesisView {
  transitions: HypothesisTransitionView[];
}

export interface HypothesisListResult {
  items: HypothesisView[];
  next_cursor: string | null;
}

export interface HypothesisListFilter {
  organisationId: string;
  siteId?: string;
  zoneKey?: string;
  /** Inclusive lower bound on threat state, for "show me everything at SUSPICIOUS or above". */
  minState?: number;
  updatedFrom?: Date;
  updatedTo?: Date;
  limit: number;
  cursor?: string;
}

/** Message body published to `sentinel.fusion.incident-candidate.{organisation_id}`. */
export interface IncidentCandidateMessage {
  schema_version: 1;
  incident_candidate_id: string;
  hypothesis_id: string;
  organisation_id: string;
  site_id: string;
  zone_id: string | null;
  threat_state: ThreatState;
  detection_confidence: number;
  threat_probability: number;
  potential_impact: PotentialImpact;
  operational_severity: OperationalSeverity;
  supporting_event_ids: string[];
  contradicting_event_ids: string[];
  confidence_explanation: string;
  rule_or_model_versions: string[];
  /**
   * False on the first emission for this hypothesis; true whenever the
   * hypothesis had previously fallen below the candidate threshold and has
   * now crossed it again. The `incident_candidate_id` is unchanged across
   * re-emissions — WP-07 is expected to treat a re-escalation as an update
   * to the same candidate, not a new one.
   */
  re_escalation: boolean;
  /** 1 for the first emission, 2 for the first re-escalation, and so on. */
  emission_number: number;
  /** The event whose signal caused the crossing. */
  triggering_event_id: string;
  emitted_at: string;
  hypothesis_version: number;
}

/** Message body published to `sentinel.fusion.hypothesis.{organisation_id}` on every update. */
export interface HypothesisUpdateMessage {
  schema_version: 1;
  hypothesis: HypothesisView;
  triggering_event_id: string;
  previous_state: ThreatState;
  state_changed: boolean;
  emitted_at: string;
  hypothesis_version: number;
}

/** Outcome of applying one event, returned by FusionService.applyEvent. */
export type ApplyEventResult =
  | {
      /** The `(organisation_id, event_id)` pair was already applied — no-op. */
      outcome: 'duplicate';
      eventId: string;
    }
  | {
      /** Recorded, but produced no signal (no rule, or rule condition unmet). */
      outcome: 'ignored';
      eventId: string;
      reason: IgnoreReason;
      correlationKey: string;
    }
  | {
      outcome: 'applied';
      eventId: string;
      hypothesisId: string;
      previousState: ThreatState;
      state: ThreatState;
      stateChanged: boolean;
      incidentCandidate: IncidentCandidateMessage | null;
      update: HypothesisUpdateMessage;
    };
