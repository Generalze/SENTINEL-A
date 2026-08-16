import type { DeliveryState, Incident, IncidentStatus, ResponseMode, Severity, ThreatState } from '@sentinel/contracts';
import type { SiteScope } from '../identity/list-pagination';

export interface IncidentTimelineView {
  id: string;
  at: string;
  kind: string;
  actor_user_id: string | null;
  payload: unknown;
}

export interface ResponseTaskView {
  id: string;
  task_type: string;
  playbook_version: string;
  delivery_state: DeliveryState;
  payload: unknown;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
  completion_detail: unknown;
  acknowledged_at: string | null;
  acknowledged_by_user_id: string | null;
}

export interface IncidentDetailView extends Incident {
  timeline: IncidentTimelineView[];
  tasks: ResponseTaskView[];
  closure_reason: string | null;
  supporting_event_ids: string[];
  contradicting_event_ids: string[];
}

export interface IncidentListFilter {
  organisationId: string;
  status?: IncidentStatus;
  severity?: Severity;
  limit: number;
  siteScope: SiteScope;
}

export interface IncidentTransitionInput {
  status: IncidentStatus;
  closureReason?: string;
  actorUserId: string | null;
}

export interface CreateIncidentInput {
  hypothesisId: string;
  incidentCandidateId: string;
  organisationId: string;
  siteId: string;
  incidentType: string;
  severity: Severity;
  threatState: ThreatState;
  confidence: number;
  responseMode: ResponseMode;
  relatedEventIds: string[];
  supportingEventIds: string[];
  contradictingEventIds: string[];
  hypothesisUpdatedAt: Date;
  hypothesisVersion: number;
}
