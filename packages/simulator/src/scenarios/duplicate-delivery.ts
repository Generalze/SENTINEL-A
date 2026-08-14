import type { Scenario, ScenarioStep } from '../scenario.js';
import { eventTemplate } from './helpers.js';

/**
 * duplicate-delivery@1.
 *
 * The identical event — same event_id, same occurred_at/ingested_at — is
 * delivered 3 times, simulating an at-least-once transport redelivering the
 * same raw message at different wall-clock moments. Ingestion must dedupe
 * by idempotency key (§64.1): one canonical row, received_count = 3,
 * duplicates linked rather than lost.
 */
const ZONE = 'lobby';
const SEND_OFFSETS_MS = [0, 1_500, 3_000];

// offset_ms is fixed at 0 for all three sends: this is ONE occurrence,
// redelivered three times, not three distinct events.
const duplicateEvent = eventTemplate({
  event_id: 'evt_duplicate-delivery-001',
  source_id: 'ACC-05',
  source_type: 'access',
  event_type: 'access_denied_attempt',
  confidence: 0.88,
  offset_ms: 0,
  zone: ZONE,
});

const steps: ScenarioStep[] = SEND_OFFSETS_MS.map((at_offset_ms) => ({
  at_offset_ms,
  event: duplicateEvent,
}));

export const duplicateDeliveryV1: Scenario = {
  name: 'duplicate-delivery',
  version: 1,
  description:
    'The same access_denied_attempt event (identical event_id and occurred_at) is POSTed 3 times over 3s, ' +
    'simulating redelivery. Ingestion must recognise the duplicates via idempotency key rather than create 3 events.',
  steps,
};
