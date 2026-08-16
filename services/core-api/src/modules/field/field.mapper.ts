import type { FieldAssignment, FieldOperativeCurrentState } from '@prisma/client';
import type { FieldAssignmentView, FieldOperativeStateView } from './field.types';

export function mapFieldAssignment(row: FieldAssignment): FieldAssignmentView {
  return {
    id: row.id,
    organisation_id: row.organisationId,
    site_id: row.siteId,
    incident_id: row.incidentId,
    assignee_user_id: row.assigneeUserId,
    assignment_type: row.assignmentType,
    priority: row.priority as FieldAssignmentView['priority'],
    status: row.status as FieldAssignmentView['status'],
    delivery_state: row.deliveryState as FieldAssignmentView['delivery_state'],
    need_to_know_summary: row.needToKnowSummary,
    expires_at: row.expiresAt?.toISOString() ?? null,
    accepted_at: row.acceptedAt?.toISOString() ?? null,
    started_at: row.startedAt?.toISOString() ?? null,
    completed_at: row.completedAt?.toISOString() ?? null,
    cancelled_at: row.cancelledAt?.toISOString() ?? null,
    declined_at: row.declinedAt?.toISOString() ?? null,
    created_by_user_id: row.createdByUserId,
    updated_by_user_id: row.updatedByUserId,
    accepted_by_user_id: row.acceptedByUserId,
    created_at: row.createdAt.toISOString(),
    updated_at: row.updatedAt.toISOString(),
  };
}

export function mapFieldState(row: FieldOperativeCurrentState): FieldOperativeStateView {
  return {
    id: row.id,
    organisation_id: row.organisationId,
    site_id: row.siteId,
    user_id: row.userId,
    device_id: row.deviceId,
    state: row.state as FieldOperativeStateView['state'],
    location: row.location,
    source_at: row.sourceAt.toISOString(),
    received_at: row.receivedAt.toISOString(),
    client_freshness_ms: row.clientFreshnessMs,
    authoritative_freshness_ms: row.authoritativeFreshnessMs,
    trace_id: row.traceId,
    updated_at: row.updatedAt.toISOString(),
  };
}
