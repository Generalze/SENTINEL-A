import type { DeliveryState } from '@sentinel/contracts';

/** What a sender or named recipient may see. Content included — this is the REST truth surface. */
export interface IncidentFieldMessageView {
  id: string;
  organisation_id: string;
  site_id: string;
  incident_id: string;
  sender_user_id: string;
  body: string | null;
  media_refs: string[];
  retention_class: string;
  sent_at: string;
  expires_at: string | null;
  trace_id: string;
  recipients: IncidentFieldMessageRecipientView[];
}

export interface IncidentFieldMessageRecipientView {
  recipient_user_id: string;
  delivery_state: DeliveryState;
  delivered_at: string | null;
  acknowledged_at: string | null;
}

/**
 * WP-18 ruling: an oversight reader is NOT a recipient. This view exists so the
 * oversight route cannot accidentally return, or cause the creation of, any
 * recipient-side state. It carries the same content but is produced by a
 * separate path with its own guard.
 */
export type IncidentFieldMessageOversightView = IncidentFieldMessageView;

export interface SiteScope {
  orgWide: boolean;
  siteIds: string[];
}
