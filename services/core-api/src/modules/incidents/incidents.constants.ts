export const INCIDENTS_STREAM_NAME = 'SENTINEL_FUSION';
export const INCIDENT_CANDIDATE_SUBJECT = 'sentinel.fusion.incident-candidate.>';
export const INCIDENT_CONSUMER_DURABLE = 'incidents-v1';
export const INCIDENT_CONSUMER_ACK_WAIT_MS = 30_000;
export const INCIDENT_CONSUMER_MAX_DELIVER = 5;

export const PLAYBOOK_PROOF_A_V1 = 'PB-PROOF-A@1';
export const TASK_PRESERVE_EVIDENCE = 'preserve-evidence';
export const TASK_NOTIFY_COMMANDER = 'notify-commander';
export const TASK_DISPATCH_FIELD = 'dispatch-field';
export const ACTION_INCIDENT_VIEW = 'incident.view';
export const ACTION_FIELD_ACKNOWLEDGE = 'field.acknowledge';

export const SILENT_DISPATCH_ACTION = 'response.dispatch.silent';
export const STANDARD_DISPATCH_ACTION = 'response.dispatch.standard';
export const RESPONSE_SYSTEM_ACTOR = 'system:incident-response';

export function incidentUpdatedSubject(organisationId: string): string {
  return `sentinel.incidents.updated.${organisationId}`;
}
