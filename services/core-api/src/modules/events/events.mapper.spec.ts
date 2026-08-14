import { NormalisedEventSchema } from '@sentinel/contracts';
import type { Event as EventRow, Prisma } from '@prisma/client';
import { describe, expect, it } from 'vitest';
import { formatValidationIssues, mapNormalisedEventToRow, mapRowToNormalisedEvent, toStoredEventResponse } from './events.mapper';
import { makeNormalisedEvent } from './test-fixtures';

function buildFakeRow(event: ReturnType<typeof makeNormalisedEvent>, overrides: Partial<EventRow> = {}): EventRow {
  return {
    id: 'row-id-1',
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
    location: event.location as Prisma.JsonValue,
    trackIds: event.track_ids,
    evidenceRefs: event.evidence_refs,
    metadata: event.metadata as Prisma.JsonValue,
    traceId: event.trace_id,
    idempotencyKey: null,
    duplicateOfEventId: null,
    receivedCount: 1,
    publishedAt: null,
    createdAt: new Date(),
    ...overrides,
  };
}

describe('events.mapper', () => {
  it('maps a NormalisedEvent to Prisma row data using camelCase field names', () => {
    const event = makeNormalisedEvent({
      zone_id: 'zone-1',
      location: { lat: 1 },
      track_ids: ['t1'],
      evidence_refs: ['e1'],
    });

    const row = mapNormalisedEventToRow(event);

    expect(row.eventId).toBe(event.event_id);
    expect(row.organisationId).toBe(event.organisation_id);
    expect(row.siteId).toBe(event.site_id);
    expect(row.zoneId).toBe('zone-1');
    expect(row.occurredAt).toBeInstanceOf(Date);
    expect(row.occurredAt.toISOString()).toBe(event.occurred_at);
    expect(row.trackIds).toEqual(['t1']);
    expect(row.evidenceRefs).toEqual(['e1']);
    expect(row.location).toEqual({ lat: 1 });
  });

  it('defaults zoneId to null when zone_id is null', () => {
    const event = makeNormalisedEvent({ zone_id: null });
    const row = mapNormalisedEventToRow(event);
    expect(row.zoneId).toBeNull();
  });

  it('round-trips a stored row back into a payload that still satisfies NormalisedEventSchema', () => {
    const event = makeNormalisedEvent({ metadata: { foo: 'bar' } });
    const row = buildFakeRow(event);

    const mapped = mapRowToNormalisedEvent(row);

    expect(() => NormalisedEventSchema.parse(mapped)).not.toThrow();
    expect(mapped).toMatchObject({
      event_id: event.event_id,
      organisation_id: event.organisation_id,
      site_id: event.site_id,
      metadata: { foo: 'bar' },
    });
  });

  it('toStoredEventResponse layers id/received_count/published_at on top of the contract shape', () => {
    const event = makeNormalisedEvent();
    const publishedAt = new Date('2026-01-01T00:00:00.000Z');
    const row = buildFakeRow(event, { receivedCount: 3, publishedAt });

    const response = toStoredEventResponse(row);

    expect(response.id).toBe(row.id);
    expect(response.received_count).toBe(3);
    expect(response.published_at).toBe(publishedAt.toISOString());
    expect(response.event_id).toBe(event.event_id);
  });

  it('toStoredEventResponse reports published_at as null when unpublished', () => {
    const row = buildFakeRow(makeNormalisedEvent(), { publishedAt: null });
    expect(toStoredEventResponse(row).published_at).toBeNull();
  });

  it('formatValidationIssues renders one "path: message" line per zod issue', () => {
    const result = NormalisedEventSchema.safeParse({});
    if (result.success) {
      throw new Error('expected validation to fail for an empty object');
    }

    const issues = formatValidationIssues(result.error);

    expect(issues.length).toBeGreaterThan(0);
    expect(issues.every((line) => /: /.test(line))).toBe(true);
    expect(issues.some((line) => line.startsWith('trace_id'))).toBe(true);
  });
});
