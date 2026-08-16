import type { FieldAssignmentStatus, FieldState, OperationalSeverity, DeliveryState } from '@sentinel/contracts';

export interface FieldAssignmentView {
  id: string;
  organisation_id: string;
  site_id: string;
  incident_id: string | null;
  assignee_user_id: string;
  assignment_type: string;
  priority: OperationalSeverity;
  status: FieldAssignmentStatus;
  delivery_state: DeliveryState;
  need_to_know_summary: string;
  expires_at: string | null;
  accepted_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  cancelled_at: string | null;
  declined_at: string | null;
  created_by_user_id: string;
  updated_by_user_id: string;
  accepted_by_user_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface FieldOperativeStateView {
  id: string;
  organisation_id: string;
  site_id: string;
  user_id: string;
  device_id: string;
  state: FieldState;
  location: unknown;
  source_at: string;
  received_at: string;
  client_freshness_ms: number;
  authoritative_freshness_ms: number;
  trace_id: string;
  updated_at: string;
}

export interface SiteScope {
  orgWide: boolean;
  siteIds: string[];
}

export type FieldAssignmentAction = 'accept' | 'decline' | 'start' | 'complete' | 'cancel';
