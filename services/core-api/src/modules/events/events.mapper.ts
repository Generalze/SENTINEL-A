import type { Event as EventRow, Prisma } from '@prisma/client';
import type { NormalisedEvent } from '@sentinel/contracts';
import type { ZodError } from 'zod';
import type { StoredEventResponse } from './events.types';

/** Fields written on every insert (canonical row or linked duplicate row). */
export type EventRowData = Pick<
  Prisma.EventUncheckedCreateInput,
  | 'eventId'
  | 'schemaVersion'
  | 'organisationId'
  | 'siteId'
  | 'zoneId'
  | 'sourceType'
  | 'sourceId'
  | 'sourceTrust'
  | 'eventType'
  | 'confidence'
  | 'occurredAt'
  | 'ingestedAt'
  | 'location'
  | 'trackIds'
  | 'evidenceRefs'
  | 'metadata'
  | 'traceId'
>;

/** NormalisedEvent (contract shape, snake_case) -> Prisma row data (camelCase). */
export function mapNormalisedEventToRow(event: NormalisedEvent): EventRowData {
  return {
    eventId: event.event_id,
    schemaVersion: event.schema_version,
    organisationId: event.organisation_id,
    siteId: event.site_id,
    zoneId: event.zone_id ?? null,
    sourceType: event.source_type,
    sourceId: event.source_id,
    sourceTrust: event.source_trust,
    eventType: event.event_type,
    confidence: event.confidence,
    occurredAt: new Date(event.occurred_at),
    ingestedAt: new Date(event.ingested_at),
    location: event.location as Prisma.InputJsonValue,
    trackIds: event.track_ids,
    evidenceRefs: event.evidence_refs,
    metadata: event.metadata as Prisma.InputJsonValue,
    traceId: event.trace_id,
  };
}

/**
 * Stored row -> the exact §40 contract shape. Used to rebuild the publish
 * payload (JetStream carries "the full normalised event JSON", not our
 * internal columns) and as the base of the API's stored-event response.
 */
export function mapRowToNormalisedEvent(row: EventRow): NormalisedEvent {
  return {
    event_id: row.eventId,
    // Only schema_version 1 is ever accepted at ingestion (NormalisedEventSchema
    // enforces the literal), so this narrowing is safe.
    schema_version: row.schemaVersion as 1,
    organisation_id: row.organisationId,
    site_id: row.siteId,
    zone_id: row.zoneId,
    source_type: row.sourceType as NormalisedEvent['source_type'],
    source_id: row.sourceId,
    source_trust: row.sourceTrust as NormalisedEvent['source_trust'],
    event_type: row.eventType,
    confidence: row.confidence,
    occurred_at: row.occurredAt.toISOString(),
    ingested_at: row.ingestedAt.toISOString(),
    location: row.location as Record<string, unknown>,
    track_ids: row.trackIds,
    evidence_refs: row.evidenceRefs,
    metadata: row.metadata as Record<string, unknown>,
    trace_id: row.traceId,
  };
}

export function toStoredEventResponse(row: EventRow): StoredEventResponse {
  return {
    ...mapRowToNormalisedEvent(row),
    id: row.id,
    received_count: row.receivedCount,
    published_at: row.publishedAt ? row.publishedAt.toISOString() : null,
  };
}

/** "path.to.field: message" per issue — matches this repo's existing zod-error formatting convention. */
export function formatValidationIssues(error: ZodError): string[] {
  return error.issues.map((issue) => {
    const path = issue.path.length > 0 ? issue.path.join('.') : '(root)';
    return `${path}: ${issue.message}`;
  });
}
