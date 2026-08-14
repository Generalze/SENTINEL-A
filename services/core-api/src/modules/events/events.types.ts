import type { NormalisedEvent } from '@sentinel/contracts';

/**
 * The stored representation returned to API callers: every §40 contract
 * field plus the ingestion bookkeeping columns callers legitimately need
 * to see (id, delivery count, publish state).
 */
export interface StoredEventResponse extends NormalisedEvent {
  id: string;
  received_count: number;
  published_at: string | null;
}

export type IngestResult =
  | { duplicate: true; original_event_id: string }
  | { duplicate: false; event: StoredEventResponse };

export interface EventsListFilter {
  organisationId: string;
  siteId?: string;
  sourceType?: string;
  occurredFrom?: Date;
  occurredTo?: Date;
  limit: number;
  cursor?: string;
}

export interface EventsListResult {
  items: StoredEventResponse[];
  next_cursor: string | null;
}
