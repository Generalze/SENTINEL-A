export const ACTION_FIELD_ASSIGNMENT_MANAGE = 'field.assignment.manage';
export const ACTION_FIELD_ASSIGNMENT_ACT = 'field.assignment.act';
export const ACTION_FIELD_STATE_WRITE = 'field.state.write';
export const ACTION_FIELD_STATE_READ = 'field.state.read';

export const FIELD_EVENT_SUBJECT_PREFIX = 'sentinel.field.updated';

export function fieldUpdatedSubject(organisationId: string): string {
  return `${FIELD_EVENT_SUBJECT_PREFIX}.${organisationId}`;
}
