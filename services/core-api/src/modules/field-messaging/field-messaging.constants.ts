import { assertSafeSubjectToken } from '../../common/messaging/subject-token';

/**
 * WP-18 actions. `incident.view` is deliberately absent: it is held by six
 * roles (site.commander, operator, dispatcher, field.operative, investigator,
 * admin), so it is never sufficient to read message content.
 */
export const ACTION_MESSAGE_SEND = 'field.message.send';
export const ACTION_MESSAGE_READ = 'field.message.read';
export const ACTION_MESSAGE_ACKNOWLEDGE = 'field.message.acknowledge';
export const ACTION_MESSAGE_OVERSIGHT_READ = 'incident.field-message.oversight.read';

export const MESSAGE_EVENT_SUBJECT_PREFIX = 'sentinel.field.message.updated';

/**
 * WP-18/D5: delivery is per entitled recipient, never a site-wide room.
 * WP-17/C7-08 established the rule this follows from — a shared room whose
 * audience is wider than the entitled set may not carry object identifiers;
 * a per-user channel may, because its audience IS the entitled set.
 *
 * Every dynamic token is asserted safe using the WP-17 validator, and the
 * subject arity is fixed at six segments so a consumer can read organisation
 * and recipient by index without a malformed id shifting them.
 */
export function messageUpdatedSubject(organisationId: string, recipientUserId: string): string {
  assertSafeSubjectToken(organisationId, 'organisation_id');
  assertSafeSubjectToken(recipientUserId, 'recipient_user_id');
  return `${MESSAGE_EVENT_SUBJECT_PREFIX}.${organisationId}.${recipientUserId}`;
}

/** Timeline/audit kinds appended to the incident's own timeline. */
export const TIMELINE_MESSAGE_SENT = 'INCIDENT_FIELD_MESSAGE_SENT';
export const TIMELINE_MESSAGE_ACKNOWLEDGED = 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGED';

/**
 * WP-18 delivery walk (section 76).
 *
 * A recipient acknowledging a message is itself proof the message reached them,
 * but section 76 has no REQUESTED -> ACKNOWLEDGED edge: the legal route is
 * REQUESTED -> DELIVERED -> ACKNOWLEDGED. Rather than add an edge or stand up a
 * second state machine — both forbidden by the directive — this WALKS the
 * existing graph and validates every hop with the shared `canTransition`.
 *
 * Returns the ordered states to apply, or null when acknowledgement is not
 * reachable from `from` (e.g. EXECUTED, or FAILED without a retry first), in
 * which case the caller must refuse without mutating anything.
 */
export function acknowledgementPath(from: string, canTransition: (a: string, b: string) => boolean): readonly string[] | null {
  if (from === 'ACKNOWLEDGED') return [];
  const candidates: readonly (readonly string[])[] = [['ACKNOWLEDGED'], ['DELIVERED', 'ACKNOWLEDGED']];
  for (const path of candidates) {
    let current = from;
    let legal = true;
    for (const next of path) {
      if (!canTransition(current, next)) {
        legal = false;
        break;
      }
      current = next;
    }
    if (legal) return path;
  }
  return null;
}
