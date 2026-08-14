import type { Scenario, ScenarioStep } from '../scenario.js';
import { eventTemplate } from './helpers.js';

/**
 * single-source-noise@1.
 *
 * One camera spamming six supporting-tier motion events with no
 * corroborating source ever appearing. Correlation must not escalate on
 * volume from a single source alone — the resulting hypothesis should cap
 * at state 2 downstream.
 */
const ZONE = 'perimeter_west';
const SOURCE_ID = 'CAM-11';
const OFFSETS_MS = [0, 2_500, 5_000, 7_500, 10_000, 12_500];

const steps: ScenarioStep[] = OFFSETS_MS.map((offsetMs, index) => ({
  at_offset_ms: offsetMs,
  event: eventTemplate({
    event_id: `evt_single-source-noise-${String(index + 1).padStart(3, '0')}`,
    source_id: SOURCE_ID,
    source_type: 'camera',
    event_type: 'motion_detected',
    confidence: 0.55,
    offset_ms: offsetMs,
    zone: ZONE,
    track_ids: ['P-902'],
    metadata: { supporting_only: true },
  }),
}));

export const singleSourceNoiseV1: Scenario = {
  name: 'single-source-noise',
  version: 1,
  description:
    'A single camera (CAM-11) emits six supporting-tier motion events over 12.5s with no corroborating source. ' +
    'Downstream correlation must cap the resulting hypothesis at state 2 rather than escalate on single-source volume.',
  steps,
};
