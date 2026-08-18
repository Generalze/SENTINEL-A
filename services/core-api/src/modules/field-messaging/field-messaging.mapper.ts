import type { IncidentFieldMessage, IncidentFieldMessageRecipient } from '@prisma/client';
import type { IncidentFieldMessageRecipientView, IncidentFieldMessageView } from './field-messaging.types';

type MessageWithRecipients = IncidentFieldMessage & { recipients: IncidentFieldMessageRecipient[] };

export function mapRecipient(row: IncidentFieldMessageRecipient): IncidentFieldMessageRecipientView {
  return {
    recipient_user_id: row.recipientUserId,
    delivery_state: row.deliveryState as IncidentFieldMessageRecipientView['delivery_state'],
    delivered_at: row.deliveredAt?.toISOString() ?? null,
    acknowledged_at: row.acknowledgedAt?.toISOString() ?? null,
  };
}

export function mapMessage(row: MessageWithRecipients): IncidentFieldMessageView {
  return {
    id: row.id,
    organisation_id: row.organisationId,
    site_id: row.siteId,
    incident_id: row.incidentId,
    sender_user_id: row.senderUserId,
    body: row.body,
    media_refs: row.mediaRefs,
    retention_class: row.retentionClass,
    sent_at: row.sentAt.toISOString(),
    expires_at: row.expiresAt?.toISOString() ?? null,
    trace_id: row.traceId,
    recipients: [...row.recipients].sort((a, b) => a.recipientUserId.localeCompare(b.recipientUserId)).map(mapRecipient),
  };
}
