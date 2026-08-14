import type { Scenario, ScenarioStep } from '../scenario.js';
import { eventTemplate } from './helpers.js';

/**
 * proof-a-intrusion@1 (§80 Proof A, §32.1 coordinated-intrusion signal
 * families).
 *
 * A restricted-zone intrusion witnessed independently by a camera, an
 * access controller and a field operative — the multi-source convergence
 * Fusion is meant to correlate into a single high-confidence hypothesis:
 *
 *   t+0s   CAM-07  person_detected            (camera, trusted, conf .78)
 *   t+4s   ACC-02  access_denied_attempt       (access, trusted, conf .95)
 *   t+9s   CAM-07  loitering_detected          (camera, trusted, conf .74)
 *   t+14s  FLD-3   field.hostile_observation   (field,  trusted, conf .90)
 *
 * The contradiction variant (proofAIntrusionContradictionV1) appends a 5th,
 * honestly-emitted event: a *valid*, schedule-matching access grant. The
 * simulator does not decide what that means — Fusion's rule table resolves
 * the contradiction downstream.
 */
const ZONE = 'vault_corridor';

const baseSteps: ScenarioStep[] = [
  {
    at_offset_ms: 0,
    event: eventTemplate({
      event_id: 'evt_proof-a-intrusion-001',
      source_id: 'CAM-07',
      source_type: 'camera',
      event_type: 'person_detected',
      confidence: 0.78,
      offset_ms: 0,
      zone: ZONE,
      track_ids: ['P-101'],
    }),
  },
  {
    at_offset_ms: 4_000,
    event: eventTemplate({
      event_id: 'evt_proof-a-intrusion-002',
      source_id: 'ACC-02',
      source_type: 'access',
      event_type: 'access_denied_attempt',
      confidence: 0.95,
      offset_ms: 4_000,
      zone: ZONE,
    }),
  },
  {
    at_offset_ms: 9_000,
    event: eventTemplate({
      event_id: 'evt_proof-a-intrusion-003',
      source_id: 'CAM-07',
      source_type: 'camera',
      event_type: 'loitering_detected',
      confidence: 0.74,
      offset_ms: 9_000,
      zone: ZONE,
      track_ids: ['P-101'],
    }),
  },
  {
    at_offset_ms: 14_000,
    event: eventTemplate({
      event_id: 'evt_proof-a-intrusion-004',
      source_id: 'FLD-3',
      source_type: 'field',
      event_type: 'field.hostile_observation',
      confidence: 0.9,
      offset_ms: 14_000,
      zone: ZONE,
      metadata: { human_authorised: true },
    }),
  },
];

export const proofAIntrusionV1: Scenario = {
  name: 'proof-a-intrusion',
  version: 1,
  description:
    'Multi-source coordinated intrusion into the vault corridor: camera person-detected, access denial, ' +
    'camera loitering and a field hostile-observation report converge on a single subject (§32.1, §80 Proof A).',
  steps: baseSteps,
};

const contradictionStep: ScenarioStep = {
  at_offset_ms: 16_000,
  event: eventTemplate({
    event_id: 'evt_proof-a-intrusion-contradiction-005',
    source_id: 'ACC-02',
    source_type: 'access',
    event_type: 'access_granted_valid',
    confidence: 0.97,
    offset_ms: 16_000,
    zone: ZONE,
    metadata: { schedule_match: true },
  }),
};

export const proofAIntrusionContradictionV1: Scenario = {
  name: 'proof-a-intrusion',
  version: 1,
  description:
    `${proofAIntrusionV1.description} Contradiction variant: a later, honestly-emitted valid access grant ` +
    "with a matching schedule is added; the simulator does not resolve the contradiction — that is Fusion's rule table's job.",
  steps: [...baseSteps, contradictionStep],
};
