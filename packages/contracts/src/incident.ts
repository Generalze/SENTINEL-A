import { z } from 'zod';
import { OperationalSeveritySchema, ThreatStateSchema } from './threat.js';

/**
 * Incident severity (architecture §12.2).
 *
 * Lead ruling (WP-01 review): §12.2 incident severity and §11.3 operational
 * severity share one SEV1..SEV5 value set and meaning — SEV1 most severe.
 * A single canonical enum (OperationalSeveritySchema) is the source of
 * truth; SeveritySchema is its incident-domain alias so the two can never
 * drift apart.
 */
export const SeveritySchema = OperationalSeveritySchema;
export type Severity = z.infer<typeof SeveritySchema>;

/** Response mode (architecture §12.3). */
export const ResponseModeSchema = z.enum(['STANDARD', 'DISCREET', 'SILENT']);
export type ResponseMode = z.infer<typeof ResponseModeSchema>;

/**
 * Incident lifecycle status. §12.1 lists "closure" as part of the incident
 * object but does not enumerate a status value set verbatim; open/
 * contained/closed follows the directive's explicit field spec.
 */
export const IncidentStatusSchema = z.enum(['open', 'contained', 'closed']);
export type IncidentStatus = z.infer<typeof IncidentStatusSchema>;

/**
 * Incident object (architecture §12.1). Carries identity/site, incident
 * type and severity, threat state and confidence, response mode, the
 * commander and related events, playbook version, lifecycle status and
 * open/close timestamps.
 *
 * closed_at >= opened_at (when closed_at is present) is a validation-only
 * refinement analogous to the occurred_at/ingested_at ordering rule on
 * NormalisedEvent; it is not spelled out in §12.1 itself.
 */
export const IncidentSchema = z
  .object({
    schema_version: z.literal(1),
    id: z.string().min(1),
    organisation_id: z.string().min(1),
    site_id: z.string().min(1),
    incident_type: z.string().min(1),
    severity: SeveritySchema,
    threat_state: ThreatStateSchema,
    confidence: z.number().min(0).max(1),
    response_mode: ResponseModeSchema,
    commander_user_id: z.string().min(1).nullable(),
    related_event_ids: z.array(z.string()).default([]),
    playbook_version: z.string().min(1).nullable(),
    status: IncidentStatusSchema,
    opened_at: z.string().datetime(),
    closed_at: z.string().datetime().nullable(),
  })
  .refine(
    (data) => data.closed_at === null || new Date(data.closed_at) >= new Date(data.opened_at),
    {
      message: 'closed_at must be >= opened_at when present',
      path: ['closed_at'],
    }
  );
export type Incident = z.infer<typeof IncidentSchema>;
