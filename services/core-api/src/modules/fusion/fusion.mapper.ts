/**
 * Row <-> view mapping for the fusion module.
 *
 * This file is the ONLY place a persisted hypothesis becomes an outward-
 * facing object. Both the HTTP controller and the NATS publisher call
 * `toHypothesisView`, which is what makes the §11.4 guarantee structural:
 * there is no code path that can serialise supporting evidence without
 * contradicting evidence, because there is only one serialiser and it always
 * writes both arrays.
 */

import type { Hypothesis as HypothesisRow, HypothesisTransition as HypothesisTransitionRow } from '@prisma/client';
import type { OperationalSeverity, PotentialImpact, ThreatState } from '@sentinel/contracts';
import { THREAT_STATE_NAMES } from '@sentinel/contracts';
import type { ProcessedSignal, Signal } from './core/threatState';
import type { HypothesisDetailView, HypothesisTransitionView, HypothesisView } from './fusion.types';

/**
 * Narrows the `Int`/`String` columns back to their contract union types.
 *
 * The database stores these as plain int/text (see the schema doc on why no
 * Prisma enums are used here), so this is the boundary where the value set is
 * re-asserted. A row outside the value set is a corrupted row and throwing is
 * correct: silently coercing a bad state into `0` would understate a threat.
 */
export function toThreatState(value: number): ThreatState {
  if (!Number.isInteger(value) || value < 0 || value > 5) {
    throw new Error(`Corrupt hypothesis row: threat state ${value} is outside 0..5`);
  }
  return value as ThreatState;
}

const POTENTIAL_IMPACTS: readonly string[] = ['LOW', 'MODERATE', 'HIGH', 'EXTREME'];
const OPERATIONAL_SEVERITIES: readonly string[] = ['SEV1', 'SEV2', 'SEV3', 'SEV4', 'SEV5'];

export function toPotentialImpact(value: string): PotentialImpact {
  if (!POTENTIAL_IMPACTS.includes(value)) {
    throw new Error(`Corrupt hypothesis row: potential impact "${value}" is not a known value`);
  }
  return value as PotentialImpact;
}

export function toOperationalSeverity(value: string): OperationalSeverity {
  if (!OPERATIONAL_SEVERITIES.includes(value)) {
    throw new Error(`Corrupt hypothesis row: operational severity "${value}" is not a known value`);
  }
  return value as OperationalSeverity;
}

/**
 * Reads the persisted signal history back out of the JSON column.
 *
 * The column is written only by this module, from objects the certified core
 * produced, so the shape is trusted; the guard here is against a NULL/
 * non-array column rather than against arbitrary user input.
 */
export function readProcessedSignals(value: unknown): ProcessedSignal[] {
  return Array.isArray(value) ? (value as ProcessedSignal[]) : [];
}

export function readSignals(value: unknown): Signal[] {
  return Array.isArray(value) ? (value as Signal[]) : [];
}

/** §65.3 record + correlation context. Always includes BOTH evidence arrays. */
export function toHypothesisView(row: HypothesisRow): HypothesisView {
  const state = toThreatState(row.state);
  return {
    schema_version: 1,
    hypothesis_id: row.id,
    incident_candidate_id: row.incidentCandidateId,
    type: row.type,
    state,
    supporting_event_ids: [...row.supportingEventIds],
    contradicting_event_ids: [...row.contradictingEventIds],
    source_diversity: row.sourceDiversity,
    detection_confidence: row.detectionConfidence,
    threat_probability: row.threatProbability,
    potential_impact: toPotentialImpact(row.potentialImpact),
    operational_severity: toOperationalSeverity(row.operationalSeverity),
    confidence_explanation: row.confidenceExplanation,
    created_at: row.createdAt.toISOString(),
    updated_at: row.updatedAt.toISOString(),
    rule_or_model_versions: [...row.ruleVersions],
    organisation_id: row.organisationId,
    site_id: row.siteId,
    zone_id: row.zoneId,
    zone_key: row.zoneKey,
    correlation_window_start: row.windowStart.toISOString(),
    correlation_window_end: row.windowEnd.toISOString(),
    incident_candidate_emitted: row.incidentCandidateEmissions > 0,
    incident_candidate_emissions: row.incidentCandidateEmissions,
    state_name: THREAT_STATE_NAMES[state],
  };
}

export function toTransitionView(row: HypothesisTransitionRow): HypothesisTransitionView {
  const from = toThreatState(row.fromState);
  const to = toThreatState(row.toState);
  return {
    sequence: row.sequence,
    from_state: from,
    to_state: to,
    from_state_name: THREAT_STATE_NAMES[from],
    to_state_name: THREAT_STATE_NAMES[to],
    event_id: row.eventId,
    reason: row.reason,
    rule_or_model_versions: [...row.ruleVersions],
    occurred_at: row.occurredAt.toISOString(),
    recorded_at: row.createdAt.toISOString(),
  };
}

export function toHypothesisDetailView(
  row: HypothesisRow,
  transitions: readonly HypothesisTransitionRow[],
): HypothesisDetailView {
  return {
    ...toHypothesisView(row),
    transitions: transitions.map(toTransitionView),
  };
}

// ---------------------------------------------------------------------------
// Cursor pagination
// ---------------------------------------------------------------------------

export interface HypothesisCursor {
  updatedAt: string;
  id: string;
}

/**
 * Opaque, base64url-encoded cursor over the list's total sort order
 * (`updated_at DESC, id DESC`). Deliberately local to this module rather than
 * imported from the events module: the two modules are separate lanes owned
 * by separate work packages, and a shared util would couple their release
 * cycles for ten lines of code.
 */
export function encodeCursor(cursor: HypothesisCursor): string {
  return Buffer.from(JSON.stringify(cursor), 'utf8').toString('base64url');
}

export function decodeCursor(raw: string): HypothesisCursor {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(raw, 'base64url').toString('utf8'));
  } catch {
    throw new Error('Invalid cursor');
  }
  if (
    typeof parsed !== 'object' ||
    parsed === null ||
    typeof (parsed as HypothesisCursor).updatedAt !== 'string' ||
    typeof (parsed as HypothesisCursor).id !== 'string' ||
    Number.isNaN(new Date((parsed as HypothesisCursor).updatedAt).getTime())
  ) {
    throw new Error('Invalid cursor');
  }
  return parsed as HypothesisCursor;
}
