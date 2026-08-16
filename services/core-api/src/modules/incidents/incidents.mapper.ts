import type { Incident as IncidentRow, IncidentTimelineEntry, ResponseTask } from '@prisma/client';
import type { DeliveryState, IncidentStatus, ResponseMode, Severity, ThreatState } from '@sentinel/contracts';
import type { IncidentDetailView, IncidentTimelineView, ResponseTaskView } from './incidents.types';

const SEVERITIES = new Set<string>(['SEV1', 'SEV2', 'SEV3', 'SEV4', 'SEV5']);
const RESPONSE_MODES = new Set<string>(['STANDARD', 'DISCREET', 'SILENT']);
const INCIDENT_STATUSES = new Set<string>(['open', 'contained', 'closed']);
const DELIVERY_STATES = new Set<string>(['REQUESTED', 'DELIVERED', 'ACKNOWLEDGED', 'EXECUTED', 'FAILED', 'UNKNOWN']);

function requireValue<T extends string>(value: string, values: Set<string>, field: string): T {
  if (!values.has(value)) throw new Error(`Corrupt incident row: ${field} ${value} is invalid`);
  return value as T;
}

export function toIncidentView(row: IncidentRow): IncidentDetailView {
  if (!Number.isInteger(row.threatState) || row.threatState < 0 || row.threatState > 5) {
    throw new Error(`Corrupt incident row: threat_state ${row.threatState} is invalid`);
  }
  return {
    schema_version: 1,
    id: row.id,
    organisation_id: row.organisationId,
    site_id: row.siteId,
    incident_type: row.incidentType,
    severity: requireValue<Severity>(row.severity, SEVERITIES, 'severity'),
    threat_state: row.threatState as ThreatState,
    confidence: row.confidence,
    response_mode: requireValue<ResponseMode>(row.responseMode, RESPONSE_MODES, 'response_mode'),
    commander_user_id: row.commanderUserId,
    related_event_ids: [...row.relatedEventIds],
    playbook_version: row.playbookVersion,
    status: requireValue<IncidentStatus>(row.status, INCIDENT_STATUSES, 'status'),
    opened_at: row.openedAt.toISOString(),
    closed_at: row.closedAt?.toISOString() ?? null,
    closure_reason: row.closureReason,
    supporting_event_ids: [...row.supportingEventIds],
    contradicting_event_ids: [...row.contradictingEventIds],
    timeline: [],
    tasks: [],
  };
}

export function toTimelineView(row: IncidentTimelineEntry): IncidentTimelineView {
  return { id: row.id, at: row.at.toISOString(), kind: row.kind, actor_user_id: row.actorUserId, payload: row.payload };
}

export function toTaskView(row: ResponseTask): ResponseTaskView {
  return {
    id: row.id,
    task_type: row.taskType,
    playbook_version: row.playbookVersion,
    delivery_state: requireValue<DeliveryState>(row.deliveryState, DELIVERY_STATES, 'delivery_state'),
    payload: row.payload,
    created_at: row.createdAt.toISOString(),
    updated_at: row.updatedAt.toISOString(),
    completed_at: row.completedAt?.toISOString() ?? null,
    completion_detail: row.completionDetail,
    acknowledged_at: row.acknowledgedAt?.toISOString() ?? null,
    acknowledged_by_user_id: row.acknowledgedByUserId,
  };
}
