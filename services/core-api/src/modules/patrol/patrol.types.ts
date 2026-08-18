import type { CheckpointTimingOutcome, PatrolRunCheckpointState, PatrolRunStatus } from '@sentinel/contracts';

export interface PatrolCheckpointView {
  id: string;
  patrol_route_id: string;
  route_version: number;
  sequence_number: number;
  name: string;
  zone_id: string | null;
  location: unknown;
  window_open_offset_ms: number;
  late_after_offset_ms: number;
  missed_after_offset_ms: number;
}

export interface PatrolRouteView {
  id: string;
  organisation_id: string;
  site_id: string;
  name: string;
  route_version: number;
  checkpoints: PatrolCheckpointView[];
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
  trace_id: string;
}

export interface PatrolRunCheckpointView {
  id: string;
  patrol_run_id: string;
  patrol_checkpoint_id: string;
  patrol_route_id: string;
  route_version: number;
  sequence_number: number;
  window_opens_at: string;
  late_after: string;
  missed_after: string;
  state: PatrolRunCheckpointState;
  resolved_at: string | null;
  checkpoint_verification_id: string | null;
}

export interface PatrolRunView {
  id: string;
  organisation_id: string;
  site_id: string;
  patrol_route_id: string;
  route_version: number;
  assigned_operative_user_id: string;
  incident_id: string | null;
  status: PatrolRunStatus;
  scheduled_start_at: string;
  started_at: string | null;
  ended_at: string | null;
  abandon_reason: string | null;
  created_by_user_id: string;
  created_at: string;
  updated_at: string;
  trace_id: string;
  checkpoints: PatrolRunCheckpointView[];
}

export interface CheckpointVerificationView {
  id: string;
  patrol_run_id: string;
  patrol_run_checkpoint_id: string;
  patrol_route_id: string;
  route_version: number;
  patrol_checkpoint_id: string;
  operative_user_id: string;
  device_id: string;
  verification_method: string;
  source_at: string;
  recorded_at: string;
  trace_id: string;
  /** VERIFIED or LATE — the outcome the timing rule assigned to recorded_at. */
  timing_outcome: Extract<CheckpointTimingOutcome, 'VERIFIED' | 'LATE'>;
}

export interface VerifyCheckpointResultView {
  verification: CheckpointVerificationView;
  run_checkpoint: PatrolRunCheckpointView;
  /** The run's status after this verification (COMPLETED when it was the last). */
  run_status: PatrolRunStatus;
}

export interface SiteScope {
  orgWide: boolean;
  siteIds: string[];
}
