export type Severity = 'SEV1' | 'SEV2' | 'SEV3' | 'SEV4' | 'SEV5';
export type IncidentStatus = 'open' | 'contained' | 'closed';
export type DeliveryState = 'REQUESTED' | 'DELIVERED' | 'ACKNOWLEDGED' | 'EXECUTED' | 'FAILED' | 'UNKNOWN';

export interface TimelineEntry {
  id?: string;
  at: string;
  kind: string;
  actor_user_id?: string | null;
  payload?: Record<string, unknown>;
}

export interface RelatedEvent {
  id: string;
  event_id?: string;
  relation?: 'supporting' | 'contradicting' | 'support' | 'contradiction';
  summary?: string;
  occurred_at?: string;
  source_type?: string;
}

export interface ResponseTask {
  id: string;
  name?: string;
  task_type?: string;
  delivery_state: DeliveryState;
  required_action?: string;
}

export interface Incident {
  id: string;
  organisation_id: string;
  site_id: string;
  incident_type: string;
  severity: Severity;
  threat_state: number | string;
  confidence: number;
  response_mode?: string;
  status: IncidentStatus;
  opened_at: string;
  closed_at?: string | null;
  closure_reason?: string | null;
  timeline?: TimelineEntry[];
  related_event_ids?: string[];
  supporting_event_ids?: string[];
  contradicting_event_ids?: string[];
  related_events?: RelatedEvent[];
  response_tasks?: ResponseTask[];
  tasks?: ResponseTask[];
}

export interface PresenceEntry {
  user_id: string;
  connected_at: string;
  sockets: number;
  online?: boolean;
}

export interface IncidentListResponse {
  incidents: Incident[];
  next_cursor?: string | null;
}

export interface PresenceResponse {
  organisation_id: string;
  presence: PresenceEntry[];
}

export interface RealtimeUpdate {
  id?: string;
  incident_id?: string;
  hypothesis_id?: string;
  [key: string]: unknown;
}
