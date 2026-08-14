import { z } from 'zod';

/**
 * Threat-state model (architecture §11.2).
 *
 * 0 NORMAL, 1 OBSERVE, 2 SUSPICIOUS, 3 PROBABLE_THREAT, 4 VERIFIED_THREAT,
 * 5 CRITICAL_LIFE_SAFETY.
 */
export const ThreatStateSchema = z.union([
  z.literal(0),
  z.literal(1),
  z.literal(2),
  z.literal(3),
  z.literal(4),
  z.literal(5),
]);
export type ThreatState = z.infer<typeof ThreatStateSchema>;

export const THREAT_STATE_NAMES: Readonly<Record<ThreatState, string>> = {
  0: 'NORMAL',
  1: 'OBSERVE',
  2: 'SUSPICIOUS',
  3: 'PROBABLE_THREAT',
  4: 'VERIFIED_THREAT',
  5: 'CRITICAL_LIFE_SAFETY',
};

/**
 * Potential impact if the hypothesised threat turns out to be real
 * (architecture §11.3 — one of the four values Sentinel must keep separate).
 */
export const PotentialImpactSchema = z.enum(['LOW', 'MODERATE', 'HIGH', 'EXTREME']);
export type PotentialImpact = z.infer<typeof PotentialImpactSchema>;

/**
 * Operational severity / response priority (architecture §11.3). SEV1 is
 * the most severe / highest priority, SEV5 the least.
 */
export const OperationalSeveritySchema = z.enum(['SEV1', 'SEV2', 'SEV3', 'SEV4', 'SEV5']);
export type OperationalSeverity = z.infer<typeof OperationalSeveritySchema>;

/**
 * ThreatAssessment (architecture §11.3). Sentinel stores at least four
 * distinct values — detection confidence, threat probability, potential
 * impact and operational severity — and must never conflate them into a
 * single score: a highly confident minor anomaly can be low severity, and a
 * moderately confident but potentially extreme threat can demand immediate
 * review.
 *
 * Field list beyond the four separated values (assessment_id,
 * organisation_id, site_id, threat_state, assessed_at, trace_id) is not
 * itemised verbatim anywhere in the architecture doc; it was added here to
 * make ThreatAssessment a coherent, independently identifiable record,
 * mirroring the identifying fields already established on NormalisedEvent
 * (§40). Flagging for lead review in case a narrower or different shape is
 * intended downstream.
 */
export const ThreatAssessmentSchema = z.object({
  schema_version: z.literal(1),
  assessment_id: z.string().min(1),
  organisation_id: z.string().min(1),
  site_id: z.string().min(1),
  threat_state: ThreatStateSchema,
  detection_confidence: z.number().min(0).max(1),
  threat_probability: z.number().min(0).max(1),
  potential_impact: PotentialImpactSchema,
  operational_severity: OperationalSeveritySchema,
  assessed_at: z.string().datetime(),
  trace_id: z.string().min(1),
});
export type ThreatAssessment = z.infer<typeof ThreatAssessmentSchema>;

/**
 * Hypothesis record (architecture §65.3). supporting_event_ids and
 * contradicting_event_ids are always present (default []) so the §11.4
 * contradiction-search doctrine can never be silently dropped by a consumer
 * that only populated one side.
 *
 * Lead ruling (WP-01 review): §65.3's field list is an abbreviation of the
 * §11.3 four-value doctrine, not an exemption from it — the Hypothesis
 * therefore carries detection_confidence alongside the other three
 * separated values, matching ThreatAssessment and the Fusion engine's
 * internal state.
 *
 * The updated_at >= created_at ordering check mirrors the analogous
 * occurred_at/ingested_at rule already established on NormalisedEvent; it
 * is not spelled out in §65.3 but follows the same append-only/temporal
 * doctrine, so it was added as a validation-only refinement.
 */
export const HypothesisSchema = z
  .object({
    schema_version: z.literal(1),
    hypothesis_id: z.string().min(1),
    incident_candidate_id: z.string().min(1),
    type: z.string().min(1),
    state: ThreatStateSchema,
    supporting_event_ids: z.array(z.string()).default([]),
    contradicting_event_ids: z.array(z.string()).default([]),
    source_diversity: z.number().int().nonnegative(),
    detection_confidence: z.number().min(0).max(1),
    threat_probability: z.number().min(0).max(1),
    potential_impact: PotentialImpactSchema,
    operational_severity: OperationalSeveritySchema,
    confidence_explanation: z.string().min(1),
    created_at: z.string().datetime(),
    updated_at: z.string().datetime(),
    rule_or_model_versions: z.array(z.string()).default([]),
  })
  .refine((data) => new Date(data.updated_at) >= new Date(data.created_at), {
    message: 'updated_at must be >= created_at',
    path: ['updated_at'],
  });
export type Hypothesis = z.infer<typeof HypothesisSchema>;
