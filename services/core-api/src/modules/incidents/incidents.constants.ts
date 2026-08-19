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
 * B11-13: the GENERIC incident source seam, stated as data.
 *
 * `source_kind` + `source_ref` answer "what opened this incident" for every
 * source there will ever be. These two literals are the Whisper source's
 * entry, and they live HERE rather than in the whisper module for the same
 * reason `'FUSION_HYPOTHESIS'` is fixed inside `createFromCandidate`: the
 * source identity of an incident is the incidents domain's own vocabulary, so
 * nothing upstream can claim a different origin for the incident it opens. The
 * literal matches the WP-21B migration exactly.
 *
 * The reference is the RECOGNITION FINGERPRINT — the digest of the canonical
 * signed statement — which makes `incidents_source_identity_key` a durable
 * one-incident-per-recognition boundary in the database itself.
 */
export const INCIDENT_SOURCE_KIND_WHISPER_RECOGNITION = 'WHISPER_RECOGNITION';

/**
 * B11-14: what a recognised device-action signal opens.
 *
 * SEV2 puts it inside CRITICAL_PLAYBOOK_SEVERITIES, so it runs the SAME
 * PB-PROOF-A machinery every critical Fusion incident runs — which is the
 * point of W21-10's single allowlisted protocol: recognition INITIATES the
 * already-proven silent path, it does not define a new one. SILENT is not a
 * choice either; the modality exists because signalling audibly is what the
 * operative cannot safely do.
 */
export const WHISPER_INCIDENT_TYPE = 'whisper.device-action';
export const WHISPER_INCIDENT_SEVERITY = 'SEV2';
export const WHISPER_INCIDENT_THREAT_STATE = 2;

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
