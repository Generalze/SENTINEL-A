import type { PatrolCheckpoint, PatrolCheckpointVerification, PatrolRoute, PatrolRun, PatrolRunCheckpoint } from '@prisma/client';
import type { CheckpointTimingOutcome, PatrolRunCheckpointState, PatrolRunStatus } from '@sentinel/contracts';
import type {
  CheckpointVerificationView,
  PatrolCheckpointView,
  PatrolRouteView,
  PatrolRunCheckpointView,
  PatrolRunView,
} from './patrol.types';

export function mapCheckpoint(row: PatrolCheckpoint): PatrolCheckpointView {
  return {
    id: row.id,
    patrol_route_id: row.patrolRouteId,
    route_version: row.routeVersion,
    sequence_number: row.sequenceNumber,
    name: row.name,
    zone_id: row.zoneId,
    location: row.location,
    window_open_offset_ms: row.windowOpenOffsetMs,
    late_after_offset_ms: row.lateAfterOffsetMs,
    missed_after_offset_ms: row.missedAfterOffsetMs,
  };
}

export function mapRoute(route: PatrolRoute, checkpoints: PatrolCheckpoint[]): PatrolRouteView {
  return {
    id: route.id,
    organisation_id: route.organisationId,
    site_id: route.siteId,
    name: route.name,
    route_version: route.currentVersion,
    checkpoints: checkpoints.map(mapCheckpoint),
    created_by_user_id: route.createdByUserId,
    created_at: route.createdAt.toISOString(),
    updated_at: route.updatedAt.toISOString(),
    trace_id: route.traceId,
  };
}

export function mapRunCheckpoint(row: PatrolRunCheckpoint): PatrolRunCheckpointView {
  return {
    id: row.id,
    patrol_run_id: row.patrolRunId,
    patrol_checkpoint_id: row.patrolCheckpointId,
    sequence_number: row.sequenceNumber,
    window_opens_at: row.windowOpensAt.toISOString(),
    late_after: row.lateAfter.toISOString(),
    missed_after: row.missedAfter.toISOString(),
    state: row.state as PatrolRunCheckpointState,
    resolved_at: row.resolvedAt?.toISOString() ?? null,
    checkpoint_verification_id: row.verificationId,
  };
}

export function mapRun(run: PatrolRun, checkpoints: PatrolRunCheckpoint[]): PatrolRunView {
  return {
    id: run.id,
    organisation_id: run.organisationId,
    site_id: run.siteId,
    patrol_route_id: run.patrolRouteId,
    route_version: run.routeVersion,
    assigned_operative_user_id: run.assignedOperativeUserId,
    incident_id: run.incidentId,
    status: run.status as PatrolRunStatus,
    scheduled_start_at: run.scheduledStartAt.toISOString(),
    started_at: run.startedAt?.toISOString() ?? null,
    ended_at: run.endedAt?.toISOString() ?? null,
    abandon_reason: run.abandonReason,
    created_by_user_id: run.createdByUserId,
    created_at: run.createdAt.toISOString(),
    updated_at: run.updatedAt.toISOString(),
    trace_id: run.traceId,
    checkpoints: checkpoints.map(mapRunCheckpoint),
  };
}

export function mapVerification(
  row: PatrolCheckpointVerification,
  timingOutcome: Extract<CheckpointTimingOutcome, 'VERIFIED' | 'LATE'>,
): CheckpointVerificationView {
  return {
    id: row.id,
    patrol_run_id: row.patrolRunId,
    patrol_run_checkpoint_id: row.patrolRunCheckpointId,
    patrol_route_id: row.patrolRouteId,
    patrol_checkpoint_id: row.patrolCheckpointId,
    operative_user_id: row.operativeUserId,
    device_id: row.deviceId,
    verification_method: row.verificationMethod,
    source_at: row.sourceAt.toISOString(),
    recorded_at: row.recordedAt.toISOString(),
    trace_id: row.traceId,
    timing_outcome: timingOutcome,
  };
}
