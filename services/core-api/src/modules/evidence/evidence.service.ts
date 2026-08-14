import { randomUUID } from 'node:crypto';
import { ForbiddenException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import type { Event as EventRow } from '@prisma/client';
import { SYSTEM_ACTOR_ID } from './evidence.constants';
import { EvidenceObjectStoreProvider } from './evidence-object-store.provider';
import { canonicalJson, sha256Hex } from './evidence.hash';
import { toEvidenceMetadataResponse } from './evidence.mapper';
import { EvidenceRepository } from './evidence.repository';
import type {
  CustodyActor,
  DeriveInput,
  EvidenceListFilter,
  EvidenceMetadataResponse,
  IngestInput,
  PreserveEventSnapshotInput,
  VerifyResult,
} from './evidence.types';

function actorId(actor: CustodyActor): string {
  return actor.kind === 'user' ? actor.id : SYSTEM_ACTOR_ID;
}

/** Plain-object shape an Event row is serialised to inside a snapshot's canonical JSON. Field names/shape mirror the §40 NormalisedEvent contract plus the row's own id, without importing anything from modules/events (see evidence.repository.ts's doc comment on findEventsByIds). */
function toSnapshotEvent(row: EventRow): Record<string, unknown> {
  return {
    id: row.id,
    event_id: row.eventId,
    schema_version: row.schemaVersion,
    organisation_id: row.organisationId,
    site_id: row.siteId,
    zone_id: row.zoneId,
    source_type: row.sourceType,
    source_id: row.sourceId,
    source_trust: row.sourceTrust,
    event_type: row.eventType,
    confidence: row.confidence,
    occurred_at: row.occurredAt.toISOString(),
    ingested_at: row.ingestedAt.toISOString(),
    location: row.location,
    track_ids: row.trackIds,
    evidence_refs: row.evidenceRefs,
    metadata: row.metadata,
    trace_id: row.traceId,
  };
}

/**
 * Orchestrates the evidence vault (WP-09 deliverables 2, 4, 5, 6, plus the
 * read side of 7). Holds no direct Prisma access — persistence goes
 * through EvidenceRepository, whose class doc is the source of truth for
 * the append-only invariant; object bytes go through
 * EvidenceObjectStoreProvider, which has no update/replace method for an
 * existing key.
 */
@Injectable()
export class EvidenceService {
  constructor(
    @Inject(EvidenceRepository) private readonly repository: EvidenceRepository,
    @Inject(EvidenceObjectStoreProvider) private readonly objectStore: EvidenceObjectStoreProvider,
  ) {}

  /**
   * Deliverable 2 (§72.2 write path): hash -> PUT -> Evidence row ->
   * INGESTED custody event, in that order. The object key is derived from
   * a freshly generated evidence id *before* anything is written, so two
   * calls with byte-identical content always land at two different keys
   * and produce two different Evidence rows (AC2: ingest never overwrites,
   * and a repeat ingest of the same bytes is a new evidence id, not a
   * dedup/no-op).
   */
  async ingest(input: IngestInput): Promise<EvidenceMetadataResponse> {
    const evidenceId = randomUUID();
    const objectKey = this.objectStore.objectKeyFor(input.organisation_id, evidenceId);
    const contentHash = sha256Hex(input.content);

    await this.objectStore.putObject(objectKey, input.content, input.content_type);

    const row = await this.repository.createEvidence({
      id: evidenceId,
      organisationId: input.organisation_id,
      sourceId: input.source_id,
      objectKey,
      contentHash,
      sizeBytes: input.content.byteLength,
      contentType: input.content_type,
      classification: input.classification,
      incidentId: input.incident_id ?? null,
      relatedEventIds: input.related_event_ids ?? [],
      capturedAt: input.captured_at ?? new Date(),
    });

    await this.repository.createCustodyEvent({
      evidenceId: row.id,
      actorKind: input.actor.kind,
      actorId: actorId(input.actor),
      action: 'INGESTED',
      detail: { source_id: input.source_id, content_type: input.content_type, size_bytes: row.sizeBytes },
    });

    return toEvidenceMetadataResponse(row);
  }

  /**
   * Deliverable 4: a new Evidence row linked via derived_from_evidence_id,
   * with its own hash and its own object key (never the original's — keys
   * are id-derived, and ids are freshly generated, so this can't collide).
   * Writes DERIVED custody on both the new row and the original.
   */
  async derive(input: DeriveInput): Promise<EvidenceMetadataResponse> {
    const original = await this.repository.findById(input.evidence_id, input.organisation_id);
    if (!original) {
      throw new NotFoundException(`Evidence ${input.evidence_id} not found`);
    }

    const derivedId = randomUUID();
    const objectKey = this.objectStore.objectKeyFor(input.organisation_id, derivedId);
    const contentHash = sha256Hex(input.content);

    await this.objectStore.putObject(objectKey, input.content, input.content_type);

    const derivedRow = await this.repository.createEvidence({
      id: derivedId,
      organisationId: input.organisation_id,
      sourceId: original.sourceId,
      objectKey,
      contentHash,
      sizeBytes: input.content.byteLength,
      contentType: input.content_type,
      classification: input.classification ?? original.classification,
      derivedFromEvidenceId: original.id,
      incidentId: original.incidentId,
      relatedEventIds: original.relatedEventIds,
      capturedAt: new Date(),
    });

    await this.repository.createCustodyEvent({
      evidenceId: derivedRow.id,
      actorKind: input.actor.kind,
      actorId: actorId(input.actor),
      action: 'DERIVED',
      detail: { transform_label: input.transform_label, derived_from_evidence_id: original.id },
    });
    await this.repository.createCustodyEvent({
      evidenceId: original.id,
      actorKind: input.actor.kind,
      actorId: actorId(input.actor),
      action: 'DERIVED',
      detail: { transform_label: input.transform_label, derived_evidence_id: derivedRow.id },
    });

    return toEvidenceMetadataResponse(derivedRow);
  }

  /**
   * Deliverable 5: re-download the object, re-hash it, compare against the
   * hash recorded at ingest time. Always writes a custody event (VERIFIED
   * or VERIFY_FAILED) — including when the object can't even be
   * downloaded (e.g. tampered out of existence, or the key was removed),
   * which is itself a verification failure worth recording, not an
   * exception that skips the custody write.
   */
  async verify(evidenceId: string, organisationId: string, actor: CustodyActor): Promise<VerifyResult> {
    const row = await this.repository.findById(evidenceId, organisationId);
    if (!row) {
      throw new NotFoundException(`Evidence ${evidenceId} not found`);
    }

    let actualHash: string;
    try {
      const content = await this.objectStore.getObject(row.objectKey);
      actualHash = sha256Hex(content);
    } catch (error) {
      actualHash = `ERROR: ${error instanceof Error ? error.message : String(error)}`;
    }

    const verified = actualHash === row.contentHash;
    const checkedAt = new Date();

    await this.repository.createCustodyEvent({
      evidenceId: row.id,
      actorKind: actor.kind,
      actorId: actorId(actor),
      action: verified ? 'VERIFIED' : 'VERIFY_FAILED',
      detail: { expected_hash: row.contentHash, actual_hash: actualHash },
    });

    return {
      evidence_id: row.id,
      verified,
      expected_hash: row.contentHash,
      actual_hash: actualHash,
      checked_at: checkedAt.toISOString(),
    };
  }

  /**
   * Deliverable 6 (WP-07 helper): serialises the referenced Event rows to
   * canonical (key-sorted) JSON and ingests the result as EVIDENCE-class
   * evidence, returning the new evidence id. Tenant-scoped: any requested
   * event id that doesn't exist (or belongs to another organisation) fails
   * the whole call loudly rather than silently producing a partial
   * snapshot — an incomplete forensic snapshot that looks complete is
   * worse than a rejected request.
   */
  async preserveEventSnapshot(input: PreserveEventSnapshotInput): Promise<string> {
    const events = await this.repository.findEventsByIds(input.organisation_id, input.event_ids);
    const byId = new Map(events.map((event) => [event.id, event]));
    const missing = input.event_ids.filter((id) => !byId.has(id));
    if (missing.length > 0) {
      throw new NotFoundException(`Event ids not found for organisation ${input.organisation_id}: ${missing.join(', ')}`);
    }

    // event_ids order is the caller's, not the DB's — canonicalJson sorts
    // object keys but preserves array order, so this ordering is what
    // survives into the stored snapshot.
    const snapshot = {
      organisation_id: input.organisation_id,
      incident_id: input.incident_id,
      snapshot_taken_at: new Date().toISOString(),
      events: input.event_ids.map((id) => toSnapshotEvent(byId.get(id) as EventRow)),
    };

    const content = Buffer.from(canonicalJson(snapshot), 'utf8');

    const evidence = await this.ingest({
      organisation_id: input.organisation_id,
      source_id: 'system:event-snapshot',
      content,
      content_type: 'application/json',
      classification: 'EVIDENCE',
      related_event_ids: input.event_ids,
      incident_id: input.incident_id,
      actor: input.actor,
    });

    return evidence.id;
  }

  /** Deliverable 7 (metadata list). Tenant-scoped; no custody event — see getMetadata's doc comment for why a list read isn't itself logged as a VIEWED of any specific item. */
  async list(filter: EvidenceListFilter): Promise<EvidenceMetadataResponse[]> {
    const rows = await this.repository.list(filter);
    return rows.map(toEvidenceMetadataResponse);
  }

  /**
   * Deliverable 7 (single-item metadata read) + deliverable 3 ("every read
   * through the API writes VIEWED"). A list result is a search surface
   * over many items; fetching one specific item's record is a read *of
   * that item*, so this is where deliverable 3's custody obligation is
   * actually discharged for metadata reads (content downloads discharge it
   * separately in downloadContent below, per AC4).
   */
  async getMetadata(evidenceId: string, organisationId: string, actor: CustodyActor): Promise<EvidenceMetadataResponse> {
    const row = await this.repository.findById(evidenceId, organisationId);
    if (!row) {
      throw new NotFoundException(`Evidence ${evidenceId} not found`);
    }

    await this.repository.createCustodyEvent({
      evidenceId: row.id,
      actorKind: actor.kind,
      actorId: actorId(actor),
      action: 'VIEWED',
      detail: { via: 'metadata' },
    });

    return toEvidenceMetadataResponse(row);
  }

  /**
   * Deliverable 7 (content download): purpose-gated (AC4 — a missing or
   * blank `purpose` is denied before any object-store access or custody
   * write happens) and custody-logged (a successful download always
   * writes VIEWED with the stated purpose in `detail`, so the custody
   * trail records *why* the content was accessed, not just that it was).
   */
  async downloadContent(
    evidenceId: string,
    organisationId: string,
    purpose: string | undefined,
    actor: CustodyActor,
  ): Promise<{ metadata: EvidenceMetadataResponse; content: Buffer }> {
    if (!purpose || purpose.trim().length === 0) {
      throw new ForbiddenException('Missing required purpose (x-purpose header) for evidence content download');
    }

    const row = await this.repository.findById(evidenceId, organisationId);
    if (!row) {
      throw new NotFoundException(`Evidence ${evidenceId} not found`);
    }

    const content = await this.objectStore.getObject(row.objectKey);

    await this.repository.createCustodyEvent({
      evidenceId: row.id,
      actorKind: actor.kind,
      actorId: actorId(actor),
      action: 'VIEWED',
      detail: { via: 'content_download', purpose },
    });

    return { metadata: toEvidenceMetadataResponse(row), content };
  }
}
