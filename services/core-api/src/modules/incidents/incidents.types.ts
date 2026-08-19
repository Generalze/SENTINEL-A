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

/**
 * B11-13/B11-14: the narrow internal seam a recognised Whisper device-action
 * signal enters the incident domain through.
 *
 * WHAT IS ABSENT IS THE POINT. There is no hypothesis id and no candidate id,
 * because a duress recognition is not a Fusion assessment and fabricating one
 * would destroy the guarantee those columns exist to give. There is no
 * severity, threat state, response mode, playbook or incident type either:
 * every one of them is FIXED by the incidents domain for this source, so no
 * caller — and no future caller — can steer a recognition into a different
 * response posture. `confidence` is the only judgement that crosses, and it is
 * the SIGNED figure from the trusted device (C11-04), which can only ever
 * narrow what the runtime permits.
 */
export interface OpenWhisperSilentIncidentInput {
  organisationId: string;
  siteId: string;
  /** The digest of the canonical signed statement; becomes `source_ref`. */
  recognitionFingerprint: string;
  confidence: number;
  traceId: string;
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
