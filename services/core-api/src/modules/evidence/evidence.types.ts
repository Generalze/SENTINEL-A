import type { EvidenceClassificationLevel } from './classification';

/** Who/what triggered a custody-relevant action. Maps directly onto EvidenceCustodyEvent's (actor_kind, actor_id) columns. */
export type CustodyActor = { kind: 'system' } | { kind: 'user'; id: string };

export interface IngestInput {
  organisation_id: string;
  source_id: string;
  content: Buffer;
  content_type: string;
  classification: EvidenceClassificationLevel;
  related_event_ids?: string[];
  incident_id?: string;
  /** When the underlying material was captured; defaults to now() if omitted. */
  captured_at?: Date;
  actor: CustodyActor;
}

export interface DeriveInput {
  evidence_id: string;
  organisation_id: string;
  transform_label: string;
  content: Buffer;
  content_type: string;
  /** Defaults to the original's classification when omitted. */
  classification?: EvidenceClassificationLevel;
  actor: CustodyActor;
}

export interface PreserveEventSnapshotInput {
  organisation_id: string;
  incident_id: string;
  event_ids: string[];
  actor: CustodyActor;
}

export interface EvidenceMetadataResponse {
  id: string;
  organisation_id: string;
  source_id: string;
  object_key: string;
  content_hash: string;
  size_bytes: number;
  content_type: string;
  classification: EvidenceClassificationLevel;
  derived_from_evidence_id: string | null;
  incident_id: string | null;
  related_event_ids: string[];
  captured_at: string;
  stored_at: string;
}

export interface CustodyEventResponse {
  id: string;
  evidence_id: string;
  at: string;
  actor_kind: 'system' | 'user';
  actor_id: string;
  action: string;
  detail: unknown;
}

export interface VerifyResult {
  evidence_id: string;
  verified: boolean;
  expected_hash: string;
  actual_hash: string;
  checked_at: string;
}

export interface EvidenceListFilter {
  organisationId: string;
  incidentId?: string;
  limit: number;
}
