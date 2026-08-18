import { assertSafeSubjectToken } from '../../common/messaging/subject-token';

export const ACTION_FIELD_ASSIGNMENT_MANAGE = 'field.assignment.manage';
export const ACTION_FIELD_ASSIGNMENT_ACT = 'field.assignment.act';
export const ACTION_FIELD_STATE_WRITE = 'field.state.write';
export const ACTION_FIELD_STATE_READ = 'field.state.read';

export const FIELD_EVENT_SUBJECT_PREFIX = 'sentinel.field.updated';

/**
 * WP-17/D2: Field events are site-scoped on the wire, not just organisation-
 * scoped — the realtime bridge routes on the site token, so a subject that
 * carried only the organisation would force an org-wide fanout (WP-17/F1).
 * Both tokens are asserted safe (WP-17/F3) because an id containing `.`, `*`
 * or `>` would re-shape the subject and change who receives the event.
 */
export function fieldUpdatedSubject(organisationId: string, siteId: string): string {
  assertSafeSubjectToken(organisationId, 'organisation_id');
  assertSafeSubjectToken(siteId, 'site_id');
  return `${FIELD_EVENT_SUBJECT_PREFIX}.${organisationId}.${siteId}`;
}
