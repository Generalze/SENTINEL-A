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
 * WP-18/C8-01: acknowledgement does NOT infer delivery.
 *
 * Section 76 keeps three pieces of evidence distinct: REQUESTED is Sentinel
 * deciding an action should be attempted, DELIVERED is the destination
 * TRANSPORT accepting it, and ACKNOWLEDGED is an authorised human or device
 * confirming receipt. An earlier draft walked REQUESTED -> DELIVERED ->
 * ACKNOWLEDGED inside the human acknowledgement and stamped delivered_at from
 * the acknowledgement clock. That collapsed two different pieces of evidence
 * into one operation and is rejected.
 *
 * REQUESTED -> DELIVERED is system-owned and needs positive transport evidence
 * (an acknowledgement from one of the recipient's own authenticated sockets).
 * Publishing to NATS does not qualify: that proves the internal bus accepted
 * an event, not that the recipient's transport did.
 *
 * The public acknowledgement route is therefore strict — only DELIVERED may
 * advance to ACKNOWLEDGED.
 */
export const ACKNOWLEDGE_REQUIRES_STATE = 'DELIVERED';
