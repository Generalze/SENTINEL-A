import { z } from 'zod';

/**
 * WP-14/M7 input-safety caps. A raw ingest is an untrusted, attacker-reachable
 * surface, so the unbounded jsonb/array fields are bounded at the contract
 * boundary: oversized `metadata`/`location` blobs and over-long
 * `track_ids`/`evidence_refs` arrays are rejected before anything is persisted
 * or published, so a single delivery cannot exhaust memory/storage.
 */
export const MAX_TRACK_IDS = 1024;
export const MAX_EVIDENCE_REFS = 1024;
export const MAX_REF_STRING_LENGTH = 512;
/** Max serialized size of the free-form `metadata` object (64 KiB). */
export const MAX_METADATA_BYTES = 64 * 1024;
/** Max serialized size of the free-form `location` object (16 KiB). */
export const MAX_LOCATION_BYTES = 16 * 1024;

const serializedByteLength = (value: unknown): number => Buffer.byteLength(JSON.stringify(value ?? {}), 'utf8');

/**
 * Normalised Event Contract (architecture §40).
 *
 * All source adapters (video, access, field, sensor, cyber, intelligence,
 * external response) must produce this shape. Events are append-only:
 * corrections or retractions are new records that reference the earlier
 * event rather than rewriting history.
 */
export const NormalisedEventSchema = z.object({
  event_id: z.string().regex(/^evt_/, 'event_id must start with "evt_"'),
  schema_version: z.literal(1),
  organisation_id: z.string().min(1),
  site_id: z.string().min(1),
  zone_id: z.string().nullable().optional(),
  source_type: z.enum(['camera', 'access', 'field', 'sensor', 'cyber', 'intel']),
  source_id: z.string().min(1),
  source_trust: z.enum(['trusted', 'degraded', 'suspicious', 'quarantined']),
  event_type: z.string().min(1),
  confidence: z.number().min(0).max(1),
  occurred_at: z.string().datetime(),
  ingested_at: z.string().datetime(),
  location: z
    .record(z.unknown())
    .default({})
    .refine((value) => serializedByteLength(value) <= MAX_LOCATION_BYTES, {
      message: `location must serialize to at most ${MAX_LOCATION_BYTES} bytes`,
    }),
  track_ids: z.array(z.string().max(MAX_REF_STRING_LENGTH)).max(MAX_TRACK_IDS).default([]),
  evidence_refs: z.array(z.string().max(MAX_REF_STRING_LENGTH)).max(MAX_EVIDENCE_REFS).default([]),
  metadata: z
    .record(z.unknown())
    .default({})
    .refine((value) => serializedByteLength(value) <= MAX_METADATA_BYTES, {
      message: `metadata must serialize to at most ${MAX_METADATA_BYTES} bytes`,
    }),
  trace_id: z.string().min(1),
}).refine(
  (data) => new Date(data.ingested_at) >= new Date(data.occurred_at),
  {
    message: 'ingested_at must be >= occurred_at',
    path: ['ingested_at'],
  }
);

export type NormalisedEvent = z.infer<typeof NormalisedEventSchema>;
