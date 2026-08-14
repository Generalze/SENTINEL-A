import type { Evidence as EvidenceRow, EvidenceCustodyEvent as CustodyRow } from '@prisma/client';
import { describe, expect, it } from 'vitest';
import { toCustodyEventResponse, toEvidenceMetadataResponse } from './evidence.mapper';

function buildEvidenceRow(overrides: Partial<EvidenceRow> = {}): EvidenceRow {
  return {
    id: 'ev-1',
    organisationId: 'org-1',
    sourceId: 'camera-1',
    objectKey: 'org-1/ev-1',
    contentHash: 'deadbeef',
    sizeBytes: 42,
    contentType: 'application/octet-stream',
    classification: 'EVIDENCE',
    derivedFromEvidenceId: null,
    incidentId: null,
    relatedEventIds: [],
    capturedAt: new Date('2026-01-01T00:00:00.000Z'),
    storedAt: new Date('2026-01-01T00:00:01.000Z'),
    ...overrides,
  } as EvidenceRow;
}

function buildCustodyRow(overrides: Partial<CustodyRow> = {}): CustodyRow {
  return {
    id: 'cust-1',
    evidenceId: 'ev-1',
    at: new Date('2026-01-01T00:05:00.000Z'),
    actorKind: 'system',
    actorId: 'system:evidence-vault',
    action: 'INGESTED',
    detail: {},
    ...overrides,
  } as CustodyRow;
}

describe('toEvidenceMetadataResponse', () => {
  it('maps every column to its snake_case API field, ISO-stringifying dates', () => {
    const row = buildEvidenceRow({ derivedFromEvidenceId: 'ev-0', incidentId: 'inc-1', relatedEventIds: ['evt-1', 'evt-2'] });

    expect(toEvidenceMetadataResponse(row)).toEqual({
      id: 'ev-1',
      organisation_id: 'org-1',
      source_id: 'camera-1',
      object_key: 'org-1/ev-1',
      content_hash: 'deadbeef',
      size_bytes: 42,
      content_type: 'application/octet-stream',
      classification: 'EVIDENCE',
      derived_from_evidence_id: 'ev-0',
      incident_id: 'inc-1',
      related_event_ids: ['evt-1', 'evt-2'],
      captured_at: '2026-01-01T00:00:00.000Z',
      stored_at: '2026-01-01T00:00:01.000Z',
    });
  });

  it('passes through null derived_from_evidence_id / incident_id on an original', () => {
    const row = buildEvidenceRow();
    const mapped = toEvidenceMetadataResponse(row);
    expect(mapped.derived_from_evidence_id).toBeNull();
    expect(mapped.incident_id).toBeNull();
  });
});

describe('toCustodyEventResponse', () => {
  it('maps every column to its snake_case API field', () => {
    const row = buildCustodyRow({ detail: { purpose: 'investigation' } });
    expect(toCustodyEventResponse(row)).toEqual({
      id: 'cust-1',
      evidence_id: 'ev-1',
      at: '2026-01-01T00:05:00.000Z',
      actor_kind: 'system',
      actor_id: 'system:evidence-vault',
      action: 'INGESTED',
      detail: { purpose: 'investigation' },
    });
  });
});
