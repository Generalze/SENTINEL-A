import type { Evidence as EvidenceRow, EvidenceCustodyEvent as CustodyRow } from '@prisma/client';
import type { ZodError } from 'zod';
import type { CustodyEventResponse, EvidenceMetadataResponse } from './evidence.types';
import type { EvidenceClassificationLevel } from './classification';

export function toEvidenceMetadataResponse(row: EvidenceRow): EvidenceMetadataResponse {
  return {
    id: row.id,
    organisation_id: row.organisationId,
    source_id: row.sourceId,
    object_key: row.objectKey,
    content_hash: row.contentHash,
    size_bytes: row.sizeBytes,
    content_type: row.contentType,
    classification: row.classification as EvidenceClassificationLevel,
    derived_from_evidence_id: row.derivedFromEvidenceId,
    incident_id: row.incidentId,
    related_event_ids: row.relatedEventIds,
    captured_at: row.capturedAt.toISOString(),
    stored_at: row.storedAt.toISOString(),
  };
}

export function toCustodyEventResponse(row: CustodyRow): CustodyEventResponse {
  return {
    id: row.id,
    evidence_id: row.evidenceId,
    at: row.at.toISOString(),
    actor_kind: row.actorKind,
    actor_id: row.actorId,
    action: row.action,
    detail: row.detail,
  };
}

/** "path.to.field: message" per issue — matches this repo's existing zod-error formatting convention (events.mapper.ts). */
export function formatValidationIssues(error: ZodError): string[] {
  return error.issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.join('.') : '(root)';
    return `${path}: ${issue.message}`;
  });
}
