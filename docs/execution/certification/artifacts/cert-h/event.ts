import { z } from 'zod';

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
  location: z.record(z.unknown()).default({}),
  track_ids: z.array(z.string()).default([]),
  evidence_refs: z.array(z.string()).default([]),
  metadata: z.record(z.unknown()).default({}),
  trace_id: z.string().min(1),
}).refine(
  (data) => new Date(data.ingested_at) >= new Date(data.occurred_at),
  {
    message: 'ingested_at must be >= occurred_at',
    path: ['ingested_at'],
  }
);

export type NormalisedEvent = z.infer<typeof NormalisedEventSchema>;
