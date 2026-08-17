import { assertSafeSubjectToken } from '../../common/messaging/subject-token';

export const INCIDENTS_STREAM_NAME = 'SENTINEL_FUSION';
export const INCIDENT_CANDIDATE_SUBJECT = 'sentinel.fusion.incident-candidate.>';
export const INCIDENT_CONSUMER_DURABLE = 'incidents-v1';
export const INCIDENT_CONSUMER_ACK_WAIT_MS = 30_000;
export const INCIDENT_CONSUMER_MAX_DELIVER = 5;
export const HYPOTHESIS_UPDATE_CONSUMER_DURABLE = 'incidents-hypothesis-v1';
export const HYPOTHESIS_UPDATE_SUBJECT = 'sentinel.fusion.hypothesis.>';

export const PLAYBOOK_PROOF_A_V1 = 'PB-PROOF-A@1';
export const TASK_PRESERVE_EVIDENCE = 'preserve-evidence';
export const TASK_NOTIFY_COMMANDER = 'notify-commander';
export const TASK_DISPATCH_FIELD = 'dispatch-field';
export const ACTION_INCIDENT_VIEW = 'incident.view';
export const ACTION_FIELD_ACKNOWLEDGE = 'field.acknowledge';

export const SILENT_DISPATCH_ACTION = 'response.dispatch.silent';
export const STANDARD_DISPATCH_ACTION = 'response.dispatch.standard';
export const RESPONSE_SYSTEM_ACTOR = 'system:incident-response';

/**
 * WP-17/C7-06: the realtime bridge reads the organisation out of this subject
 * to pick the room it broadcasts into, so the token must not be able to shift
 * the subject's arity. Both publish sites treat a throw here as a failed
 * publish — the database stays authoritative either way.
 */
export function incidentUpdatedSubject(organisationId: string): string {
  assertSafeSubjectToken(organisationId, 'organisation_id');
  return `sentinel.incidents.updated.${organisationId}`;
}
