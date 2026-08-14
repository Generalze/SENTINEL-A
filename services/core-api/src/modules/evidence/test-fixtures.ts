/**
 * Test-only fixture builders. Not a *.spec.ts / *.test.ts file itself, so
 * vitest does not try to run it as a suite (same convention as
 * modules/events/test-fixtures.ts).
 */
import type { IngestInput } from './evidence.types';

let counter = 0;

export function makeIngestInput(overrides: Partial<IngestInput> = {}): IngestInput {
  counter += 1;
  const base: IngestInput = {
    organisation_id: 'org_test',
    source_id: 'camera-1',
    content: Buffer.from(`evidence-content-${Date.now()}-${counter}`, 'utf8'),
    content_type: 'application/octet-stream',
    classification: 'EVIDENCE',
    actor: { kind: 'system' },
  };
  return { ...base, ...overrides };
}
