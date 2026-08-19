import { randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type WhisperSignalVersion } from '@prisma/client';
import {
  WhisperActivationApprovalSchema,
  WhisperAuditPayloadSchema,
  type WhisperAuditPayload,
  type WhisperReplayIdentity,
} from '@sentinel/contracts';
import { PrismaService } from '../../prisma/prisma.service';
import type { SiteScope } from '../identity/list-pagination';
import {
  AUDIT_WHISPER_ACTIVATED,
  AUDIT_WHISPER_ROTATED,
  AUDIT_WHISPER_STATUS_TRANSITIONED,
  RECEIPT_STATUS_APPLYING,
  RECEIPT_STATUS_RECEIVED,
  RECEIPT_STATUS_UNKNOWN,
  WHISPER_PROCESSING_LEASE_MS,
} from './whisper.constants';

/**
 * WP-21B persistence primitives.
 *
 * THIS REPOSITORY HOLDS NO POLICY. Which principal may administer which
 * signal, whether an edit needs a new version, whether a recognition is
 * eligible and what a refusal is called are all DECISIONS, and they live in
 * the service. What lives here is the set of storage operations those
 * decisions need, each carrying exactly the concurrency guarantee the ruling
 * requires — the family lock that makes version numbering monotonic, the
 * single transaction that makes "exactly one ACTIVE version" true, and the
 * fenced claim/finalize that makes a recognition retryable but never
 * replayable.
 *
 * Two apparent exceptions are deliberate, and both are SHAPE checks rather
 * than policy: an audit payload is validated through WhisperAuditPayloadSchema
 * and an activation approval through WhisperActivationApprovalSchema before
 * either is written. Both schemas are `.strict()`, and that strictness is the
 * actual enforcement against a widened audit row or a malformed attestation —
 * so a service-bypassing writer must not be able to get past them either.
 */

export type Tx = Prisma.TransactionClient;

export function isUniqueViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

/**
 * A TRANSLATED P2002.
 *
 * Prisma's own error names the violated constraint and often the colliding
 * columns, which for this module would mean an anti-replay nonce, a roster
 * member or another tenant's identifiers reaching a log or a response. Every
 * uniqueness race is therefore caught at its own call site and re-raised as
 * this, carrying only what the caller needs in order to choose a status code.
 */
export class WhisperUniquenessConflictError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WhisperUniquenessConflictError';
  }
}

/**
 * The receipt as the runtime reads it back: this repository's own projection,
 * deliberately NOT the Prisma row type. Nothing reachable from here is
 * signature material — the row stores none, and a fixed projection cannot
 * start returning some by accident.
 */
export interface WhisperStoredReceipt {
  id: string;
  organisationId: string;
  siteId: string;
  actorUserId: string;
  deviceId: string;
  whisperSignalId: string;
  whisperSignalVersion: number;
  antiReplayNonce: string;
  signalVersionId: string | null;
  recognitionFingerprint: string;
  status: string;
  outcome: string | null;
  conflictCode: string | null;
  incidentId: string | null;
  attemptCount: number;
  recordedAt: Date;
  finalizedAt: Date | null;
}

const receiptProjection = {
  id: true,
  organisationId: true,
  siteId: true,
  actorUserId: true,
  deviceId: true,
  whisperSignalId: true,
  whisperSignalVersion: true,
  antiReplayNonce: true,
  signalVersionId: true,
  recognitionFingerprint: true,
  status: true,
  outcome: true,
  conflictCode: true,
  incidentId: true,
  attemptCount: true,
  recordedAt: true,
  finalizedAt: true,
} as const;

type ReceiptRow = Prisma.WhisperRecognitionReceiptGetPayload<{ select: typeof receiptProjection }>;

function mapReceipt(row: ReceiptRow): WhisperStoredReceipt {
  return { ...row };
}

/**
 * B11-03: a site-scoped grant reaches site-scoped signals ONLY.
 *
 * `site_id IN (...)` is never true for a NULL, so an ORGANISATION-WIDE signal
 * (site_id NULL, W21-03/C11-02) is invisible to a site-scoped commander by
 * construction rather than by a second filter someone could forget to apply.
 * That is the intended reading: administering a configuration that may be
 * recognised at every site in the tenant is an organisation-wide power.
 */
function versionScopeWhere(siteScope: SiteScope): Prisma.WhisperSignalVersionWhereInput {
  return siteScope.orgWide ? {} : { siteId: { in: siteScope.siteIds } };
}

/** The six semantic fields as stored columns, plus the digest taken over them. */
export interface WhisperConfigurationColumns {
  deviceActionId: string;
  /** B11-07: the caller has already SORTED these — order is not authority. */
  authorisedUserIds: string[];
  contextRequirements: Record<string, unknown>;
  minimumConfidence: number;
  responseProtocolId: string | null;
  configurationFingerprint: string;
}

export interface CreateSignalFamilyInput extends WhisperConfigurationColumns {
  organisationId: string;
  siteId: string | null;
  name: string;
  createdByUserId: string;
  traceId: string;
}

export interface PublishNewVersionInput extends WhisperConfigurationColumns {
  organisationId: string;
  whisperSignalId: string;
  siteScope: SiteScope;
  /** Optional rename; the family's existing name is kept when absent. */
  name?: string;
  createdByUserId: string;
  traceId: string;
}

export interface UpdateDraftConfigurationInput extends WhisperConfigurationColumns {
  organisationId: string;
  whisperSignalId: string;
  signalVersion: number;
  siteScope: SiteScope;
  name: string;
  actorUserId: string;
  traceId: string;
}

export interface TransitionStatusInput {
  organisationId: string;
  whisperSignalId: string;
  signalVersion: number;
  siteScope: SiteScope;
  expectedStatus: NonNullable<WhisperAuditPayload['from_status']>;
  toStatus: NonNullable<WhisperAuditPayload['to_status']>;
  actorUserId: string;
  traceId: string;
}

export interface ActivateVersionInput {
  organisationId: string;
  whisperSignalId: string;
  signalVersion: number;
  siteScope: SiteScope;
  expectedStatus: NonNullable<WhisperAuditPayload['from_status']>;
  /**
   * W21-13: the fingerprint the approver attested to. Activation is a
   * compare-and-set against it, so an approval cannot survive a configuration
   * it never saw — including one that changed between the read and this write.
   */
  expectedConfigurationFingerprint: string;
  createdByUserId: string;
  approvedByUserId: string;
  traceId: string;
}

/** Why a compare-and-set write did not land, stated precisely enough to answer with. */
export type WhisperWriteOutcome<T> =
  | { kind: 'written'; row: T }
  | { kind: 'not-found' }
  | { kind: 'status-conflict'; currentStatus: string }
  | { kind: 'fingerprint-conflict' };

export interface ActivationResult {
  activated: WhisperSignalVersion;
  /** The versions this activation ROTATED, so the audit trail can name them. */
  rotatedVersions: number[];
}

export interface WhisperAuditInput {
  organisationId: string;
  siteId: string | null;
  kind: string;
  actorUserId: string | null;
  payload: WhisperAuditPayload;
}

export interface EnsureReceiptInput {
  identity: WhisperReplayIdentity;
  signalVersionId: string | null;
  recognitionFingerprint: string;
  /** The AUTHORITATIVE server clock read when the result arrived (W21-08). */
  recordedAt: Date;
  traceId: string;
}

export interface FinalizeReceiptInput {
  receiptId: string;
  /** B11-12: the generation this attempt's claim established. */
  claimGeneration: number;
  status: string;
  outcome: string;
  conflictCode: string | null;
  incidentId: string | null;
  audit: WhisperAuditInput;
}

export interface MarkReceiptUnknownInput {
  receiptId: string;
  claimGeneration: number;
}

@Injectable()
export class WhisperRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  // ---------------------------------------------------------------------------
  // Clock
  // ---------------------------------------------------------------------------

  /**
   * The AUTHORITATIVE server clock: `clock_timestamp()`, never `now()`.
   *
   * Postgres pins `now()` to the start of the enclosing transaction, so a
   * freshness window judged against it would silently widen by however long
   * that transaction had already been running — and W21-08's whole point is
   * that the acceptance window is the server's to decide, not something a
   * device or an unlucky lock wait can extend.
   */
  private async clockNow(client: Tx): Promise<Date> {
    const rows = await client.$queryRaw<Array<{ now: Date }>>(Prisma.sql`SELECT clock_timestamp() AS now`);
    const first = rows[0];
    if (!first) throw new Error('clock_timestamp returned no row');
    return first.now;
  }

  /** The server clock outside any transaction, read as a recognition arrives. */
  async now(): Promise<Date> {
    return this.clockNow(this.prisma);
  }

  // ---------------------------------------------------------------------------
  // Tenancy facts
  // ---------------------------------------------------------------------------

  /**
   * WP-17A: a signal version carries a COMPOSITE (site_id, organisation_id)
   * relation, so a site from the wrong tenant would be refused by the database
   * anyway — as a raw foreign-key error, which is not an answer any caller can
   * be given. Proving it first turns that into a clean refusal, and makes a
   * nonexistent site and another tenant's real site indistinguishable.
   */
  async siteExistsInOrganisation(organisationId: string, siteId: string): Promise<boolean> {
    const site = await this.prisma.site.findFirst({ where: { id: siteId, organisationId }, select: { id: true } });
    return site !== null;
  }

  /**
   * B11-05: which of `userIds` are members of `organisationId`.
   *
   * Returned as a SET rather than a boolean so the service can refuse a whole
   * roster without disclosing WHICH id failed — naming it would turn a
   * signal-authoring form into a cross-tenant user-existence oracle.
   */
  async userIdsInOrganisation(organisationId: string, userIds: readonly string[]): Promise<Set<string>> {
    if (userIds.length === 0) return new Set();
    const rows = await this.prisma.user.findMany({
      where: { organisationId, id: { in: [...userIds] } },
      select: { id: true },
    });
    return new Set(rows.map((row) => row.id));
  }

  /**
   * W21-07: the SERVER's answer to "was this operative on duty here", read
   * from authoritative Field state for the EXACT (organisation, site, user).
   *
   * Returns the raw state string, or `null` when no row exists. The caller
   * turns `null` into an ABSENT fact rather than a false one: an unknown duty
   * state is a gap in evidence, and the contract's context gate fails closed
   * on an absent key.
   *
   * This is a single-column read of another domain's live state — the same
   * shape as `siteExistsInOrganisation` here and `operativeCanReceive` in
   * patrol — not a write. It therefore does not go through FieldService and
   * cannot bypass any Field rule; there is no Field rule about reading one
   * operative's own current state to answer a question about that operative.
   */
  async onDutyFact(organisationId: string, siteId: string, userId: string): Promise<string | null> {
    const row = await this.prisma.fieldOperativeCurrentState.findUnique({
      where: { organisationId_siteId_userId: { organisationId, siteId, userId } },
      select: { state: true },
    });
    return row?.state ?? null;
  }

  // ---------------------------------------------------------------------------
  // W21-14 audit
  // ---------------------------------------------------------------------------

  /**
   * Append-only. No path in this module updates or deletes an audit row;
   * corrections are subsequent entries (section 61).
   *
   * The payload is PARSED, not merely typed. `WhisperAuditPayloadSchema` is
   * `.strict()`, and that strictness is the enforcement W21-14 relies on: the
   * discreet action definition, signature material, public keys, the
   * authorised-user roster and the context VALUES have no field there, so a
   * widened row is refused at the boundary rather than written and later read
   * by oversight. A refusal aborts the enclosing transaction, which is the
   * correct trade — an effect whose audit record could not be written must not
   * commit.
   */
  private async writeAudit(client: Tx, input: WhisperAuditInput): Promise<void> {
    const payload = WhisperAuditPayloadSchema.parse(input.payload);
    await client.whisperAuditLog.create({
      data: {
        organisationId: input.organisationId,
        siteId: input.siteId,
        whisperSignalId: payload.whisper_signal_id,
        signalVersion: payload.signal_version,
        kind: input.kind,
        actorUserId: input.actorUserId,
        payload: JSON.parse(JSON.stringify(payload)) as Prisma.InputJsonObject,
      },
    });
  }

  /** Audit inside a caller's transaction, so the record and the effect commit together. */
  async audit(tx: Tx, input: WhisperAuditInput): Promise<void> {
    await this.writeAudit(tx, input);
  }

  /**
   * Audit with no accompanying effect.
   *
   * Used for the refusals that deliberately write nothing else — above all an
   * invalid signature, which must leave no receipt and consume no replay
   * identity (B11-12) while still being recorded as an attempt on a silent
   * duress channel.
   */
  async recordAudit(input: WhisperAuditInput): Promise<void> {
    await this.writeAudit(this.prisma, input);
  }

  // ---------------------------------------------------------------------------
  // Studio: signal families and versions
  // ---------------------------------------------------------------------------

  /**
   * Serialises every decision about ONE family's version history.
   *
   * Held by both `publishNewVersion` and `activate`, which is what makes
   * `max(version) + 1` genuinely monotonic and "at most one ACTIVE version"
   * genuinely true: two concurrent publishes cannot both read the same
   * maximum, and two concurrent activations cannot each miss the other's
   * rotation. Ordered by `signal_version` so every caller takes the family's
   * row locks in the same sequence and no two paths can deadlock.
   */
  private async lockFamily(tx: Tx, organisationId: string, whisperSignalId: string): Promise<void> {
    await tx.$queryRaw(Prisma.sql`
      SELECT id
      FROM whisper_signal_versions
      WHERE organisation_id = ${organisationId}
        AND whisper_signal_id = ${whisperSignalId}
      ORDER BY signal_version
      FOR UPDATE`);
  }

  /**
   * B11-03: creates a family at VERSION 1, DRAFT.
   *
   * The family id is SERVER-GENERATED. A client-chosen identifier would let a
   * caller collide with, or attempt to graft a version onto, a family they
   * cannot see — and the family id is half of the exact configuration identity
   * that C11-05 binds every recognition to.
   *
   * The fingerprint is computed by the SERVICE with the contract's helper and
   * passed in, because it is a statement about the configuration's MEANING
   * rather than a storage concern.
   */
  async createSignalFamily(input: CreateSignalFamilyInput): Promise<WhisperSignalVersion> {
    const whisperSignalId = randomUUID();
    try {
      return await this.prisma.whisperSignalVersion.create({
        data: {
          whisperSignalId,
          signalVersion: 1,
          organisationId: input.organisationId,
          siteId: input.siteId,
          name: input.name,
          status: 'DRAFT',
          modality: 'DEVICE_ACTION',
          deviceActionId: input.deviceActionId,
          authorisedUserIds: input.authorisedUserIds,
          contextRequirements: input.contextRequirements as Prisma.InputJsonObject,
          minimumConfidence: input.minimumConfidence,
          responseProtocolId: input.responseProtocolId,
          configurationFingerprint: input.configurationFingerprint,
          createdByUserId: input.createdByUserId,
          traceId: input.traceId,
        },
      });
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      // A server-generated UUID colliding is not a client-visible condition,
      // and the raw constraint name must not become one either.
      throw new WhisperUniquenessConflictError('Whisper signal family identifier collided; retry the request');
    }
  }

  /**
   * W21-02: the ONLY way to change a frozen configuration — a NEW version.
   *
   * The family is locked first, so the version number is `max + 1` against a
   * history no concurrent publish can extend underneath this one. The new
   * version inherits the family's SITE: scope belongs to the family, and
   * letting a publish move it would let a site-scoped commander widen a signal
   * to a site they never held authority over.
   */
  async publishNewVersion(input: PublishNewVersionInput): Promise<WhisperWriteOutcome<WhisperSignalVersion>> {
    return this.prisma.$transaction(async (tx) => {
      await this.lockFamily(tx, input.organisationId, input.whisperSignalId);
      const latest = await tx.whisperSignalVersion.findFirst({
        where: {
          organisationId: input.organisationId,
          whisperSignalId: input.whisperSignalId,
          ...versionScopeWhere(input.siteScope),
        },
        orderBy: { signalVersion: 'desc' },
      });
      if (latest === null) return { kind: 'not-found' };
      const row = await tx.whisperSignalVersion.create({
        data: {
          whisperSignalId: input.whisperSignalId,
          signalVersion: latest.signalVersion + 1,
          organisationId: input.organisationId,
          siteId: latest.siteId,
          name: input.name ?? latest.name,
          status: 'DRAFT',
          modality: 'DEVICE_ACTION',
          deviceActionId: input.deviceActionId,
          authorisedUserIds: input.authorisedUserIds,
          contextRequirements: input.contextRequirements as Prisma.InputJsonObject,
          minimumConfidence: input.minimumConfidence,
          responseProtocolId: input.responseProtocolId,
          configurationFingerprint: input.configurationFingerprint,
          createdByUserId: input.createdByUserId,
          traceId: input.traceId,
        },
      });
      return { kind: 'written', row };
    });
  }

  async findVersion(
    organisationId: string,
    whisperSignalId: string,
    signalVersion: number,
    siteScope: SiteScope,
  ): Promise<WhisperSignalVersion | null> {
    return this.prisma.whisperSignalVersion.findFirst({
      where: { organisationId, whisperSignalId, signalVersion, ...versionScopeWhere(siteScope) },
    });
  }

  /** Every version of one family, newest first — the Studio detail view. */
  async findFamilyVersions(organisationId: string, whisperSignalId: string, siteScope: SiteScope): Promise<WhisperSignalVersion[]> {
    return this.prisma.whisperSignalVersion.findMany({
      where: { organisationId, whisperSignalId, ...versionScopeWhere(siteScope) },
      orderBy: { signalVersion: 'desc' },
    });
  }

  /**
   * The family's ACTIVE version, if it has one. At most one can exist — see
   * `activate`, which rotates any other in the same transaction.
   */
  async findActiveVersion(organisationId: string, whisperSignalId: string, siteScope: SiteScope): Promise<WhisperSignalVersion | null> {
    return this.prisma.whisperSignalVersion.findFirst({
      where: { organisationId, whisperSignalId, status: 'ACTIVE', ...versionScopeWhere(siteScope) },
    });
  }

  /**
   * RUNTIME resolution (B11-10), by ORGANISATION and the SIGNED family and
   * version.
   *
   * Deliberately takes NO site scope. C11-02 puts the signal's own
   * organisation and site into the eligibility gate precisely so that scope is
   * decided THERE, against the authenticated device context, rather than being
   * silently pre-filtered by a query the gate would then have to trust. The
   * organisation comes from the trusted device context, never from the result,
   * so this lookup can never cross a tenant boundary.
   */
  async findVersionForRuntime(organisationId: string, whisperSignalId: string, signalVersion: number): Promise<WhisperSignalVersion | null> {
    return this.prisma.whisperSignalVersion.findUnique({
      where: { organisationId_whisperSignalId_signalVersion: { organisationId, whisperSignalId, signalVersion } },
    });
  }

  /** Bounded list for Studio, most recently touched first. */
  async listForScope(
    organisationId: string,
    siteScope: SiteScope,
    options: { limit: number; whisperSignalId?: string },
  ): Promise<WhisperSignalVersion[]> {
    return this.prisma.whisperSignalVersion.findMany({
      where: {
        organisationId,
        ...versionScopeWhere(siteScope),
        ...(options.whisperSignalId === undefined ? {} : { whisperSignalId: options.whisperSignalId }),
      },
      orderBy: [{ updatedAt: 'desc' }, { whisperSignalId: 'desc' }, { signalVersion: 'desc' }],
      take: options.limit,
    });
  }

  /**
   * W21-02: a DRAFT edit, as a compare-and-set on `status = 'DRAFT'`.
   *
   * The service has already classified the edit, but the row can advance
   * between that read and this write — and the moment a version leaves DRAFT
   * it begins accumulating evidence that an edit would invalidate. The
   * predicate therefore lives in the WHERE clause, so the database decides and
   * a lost race is reported rather than overwritten.
   */
  async updateDraftConfiguration(input: UpdateDraftConfigurationInput): Promise<WhisperWriteOutcome<WhisperSignalVersion>> {
    return this.prisma.$transaction(async (tx) => {
      const current = await tx.whisperSignalVersion.findFirst({
        where: {
          organisationId: input.organisationId,
          whisperSignalId: input.whisperSignalId,
          signalVersion: input.signalVersion,
          ...versionScopeWhere(input.siteScope),
        },
      });
      if (current === null) return { kind: 'not-found' };
      const updated = await tx.whisperSignalVersion.updateMany({
        where: { id: current.id, status: 'DRAFT' },
        data: {
          name: input.name,
          deviceActionId: input.deviceActionId,
          authorisedUserIds: { set: input.authorisedUserIds },
          contextRequirements: input.contextRequirements as Prisma.InputJsonObject,
          minimumConfidence: input.minimumConfidence,
          responseProtocolId: input.responseProtocolId,
          configurationFingerprint: input.configurationFingerprint,
          traceId: input.traceId,
        },
      });
      if (updated.count !== 1) return { kind: 'status-conflict', currentStatus: current.status };
      const row = await tx.whisperSignalVersion.findUniqueOrThrow({ where: { id: current.id } });
      return { kind: 'written', row };
    });
  }

  /**
   * One lifecycle step, as a compare-and-set on the CURRENT status.
   *
   * WHICH steps exist is the contract's `canTransitionWhisperSignalStatus`,
   * checked by the service; what this method adds is that the step is taken
   * exactly once even under concurrency. ACTIVE is unreachable from here —
   * `activate` is its only writer, because activation also inserts an approval
   * and rotates the incumbent, and those three facts must be one transaction
   * or none of them.
   */
  async transitionStatus(input: TransitionStatusInput): Promise<WhisperWriteOutcome<WhisperSignalVersion>> {
    return this.prisma.$transaction(async (tx) => {
      const current = await tx.whisperSignalVersion.findFirst({
        where: {
          organisationId: input.organisationId,
          whisperSignalId: input.whisperSignalId,
          signalVersion: input.signalVersion,
          ...versionScopeWhere(input.siteScope),
        },
      });
      if (current === null) return { kind: 'not-found' };
      const at = await this.clockNow(tx);
      const updated = await tx.whisperSignalVersion.updateMany({
        where: { id: current.id, status: input.expectedStatus },
        data: {
          status: input.toStatus,
          traceId: input.traceId,
          ...(input.toStatus === 'RETIRED' ? { retiredAt: at } : {}),
          ...(input.toStatus === 'ROTATED' ? { rotatedAt: at } : {}),
        },
      });
      if (updated.count !== 1) return { kind: 'status-conflict', currentStatus: current.status };
      const row = await tx.whisperSignalVersion.findUniqueOrThrow({ where: { id: current.id } });
      await this.writeAudit(tx, {
        organisationId: row.organisationId,
        siteId: row.siteId,
        kind: AUDIT_WHISPER_STATUS_TRANSITIONED,
        actorUserId: input.actorUserId,
        payload: {
          whisper_signal_id: row.whisperSignalId,
          signal_version: row.signalVersion,
          configuration_fingerprint: row.configurationFingerprint,
          actor_user_id: input.actorUserId,
          device_id: null,
          from_status: input.expectedStatus,
          to_status: input.toStatus,
          outcome: null,
          conflict_code: null,
          recognition_fingerprint: null,
          response_protocol_id: null,
          incident_id: null,
          trace_id: input.traceId,
        },
      });
      return { kind: 'written', row };
    });
  }

  /**
   * W21-13/B11-07: activation, as ONE transaction.
   *
   * Three facts become true together or none of them does: the approval
   * exists, this version is ACTIVE, and every OTHER active version of the same
   * family is ROTATED. Splitting them would leave a window in which two
   * versions of one family are simultaneously ACTIVE — two different rosters,
   * thresholds and context requirements both able to raise a silent dispatch,
   * with no way afterwards to say which one an operative actually fired.
   *
   * The family lock is taken first, so a concurrent activation of a sibling
   * version cannot interleave between the rotation and the promotion.
   *
   * The compare-and-set is on BOTH the expected status and the expected
   * configuration fingerprint. The fingerprint half is what makes W21-13
   * durable: an approval attests to a TESTED configuration, so if the stored
   * configuration is not the one the approver saw, activation must fail rather
   * than promote something nobody reviewed.
   */
  async activate(input: ActivateVersionInput): Promise<WhisperWriteOutcome<ActivationResult>> {
    return this.prisma.$transaction(async (tx) => {
      await this.lockFamily(tx, input.organisationId, input.whisperSignalId);
      const current = await tx.whisperSignalVersion.findFirst({
        where: {
          organisationId: input.organisationId,
          whisperSignalId: input.whisperSignalId,
          signalVersion: input.signalVersion,
          ...versionScopeWhere(input.siteScope),
        },
      });
      if (current === null) return { kind: 'not-found' };
      if (current.status !== input.expectedStatus) return { kind: 'status-conflict', currentStatus: current.status };
      if (current.configurationFingerprint !== input.expectedConfigurationFingerprint) return { kind: 'fingerprint-conflict' };

      const approvedAt = await this.clockNow(tx);

      // Rotate the incumbent FIRST. There can only ever be one, but the query
      // is written as a set operation so that a historical anomaly is
      // CORRECTED by this transaction rather than surviving it.
      const incumbents = await tx.whisperSignalVersion.findMany({
        where: {
          organisationId: input.organisationId,
          whisperSignalId: input.whisperSignalId,
          status: 'ACTIVE',
          NOT: { id: current.id },
        },
        select: { id: true, signalVersion: true, siteId: true, configurationFingerprint: true },
      });
      for (const incumbent of incumbents) {
        await tx.whisperSignalVersion.update({
          where: { id: incumbent.id },
          data: { status: 'ROTATED', rotatedAt: approvedAt },
        });
        await this.writeAudit(tx, {
          organisationId: input.organisationId,
          siteId: incumbent.siteId,
          kind: AUDIT_WHISPER_ROTATED,
          actorUserId: input.approvedByUserId,
          payload: {
            whisper_signal_id: input.whisperSignalId,
            signal_version: incumbent.signalVersion,
            configuration_fingerprint: incumbent.configurationFingerprint,
            actor_user_id: input.approvedByUserId,
            device_id: null,
            from_status: 'ACTIVE',
            to_status: 'ROTATED',
            outcome: null,
            conflict_code: null,
            recognition_fingerprint: null,
            response_protocol_id: null,
            incident_id: null,
            trace_id: input.traceId,
          },
        });
      }

      // W21-13: the attestation is validated through the contract's own
      // `.strict()` schema — INCLUDING its distinctness refinement — before it
      // can be written, so a malformed or self-approved activation cannot
      // become a durable record even if a service-layer check were bypassed.
      const approval = WhisperActivationApprovalSchema.parse({
        schema_version: 1,
        whisper_signal_id: input.whisperSignalId,
        signal_version: input.signalVersion,
        configuration_fingerprint: current.configurationFingerprint,
        approved_by_user_id: input.approvedByUserId,
        created_by_user_id: input.createdByUserId,
        approved_at: approvedAt.toISOString(),
        trace_id: input.traceId,
      });

      try {
        await tx.whisperActivationApproval.create({
          data: {
            signalVersionId: current.id,
            organisationId: input.organisationId,
            configurationFingerprint: approval.configuration_fingerprint,
            approvedByUserId: approval.approved_by_user_id,
            createdByUserId: approval.created_by_user_id,
            approvedAt,
            traceId: approval.trace_id,
          },
        });
      } catch (error) {
        if (!isUniqueViolation(error)) throw error;
        // EXACTLY ONE activation per version. A second attestation would let
        // an activation be re-attested after the fact; the status CAS above
        // has already proven this version was still awaiting one, so a
        // collision here is a concurrent activation that won the race.
        throw new WhisperUniquenessConflictError('This signal version has already been activated');
      }

      const promoted = await tx.whisperSignalVersion.updateMany({
        where: { id: current.id, status: input.expectedStatus, configurationFingerprint: input.expectedConfigurationFingerprint },
        data: { status: 'ACTIVE', activatedAt: approvedAt, traceId: input.traceId },
      });
      // The row was read under this transaction's own family lock, so a failed
      // CAS here is an integrity fault rather than a race. Throwing rolls back
      // the approval and the rotations with it.
      if (promoted.count !== 1) throw new Error('Whisper signal version changed inside its own activation transaction');

      const activated = await tx.whisperSignalVersion.findUniqueOrThrow({ where: { id: current.id } });
      await this.writeAudit(tx, {
        organisationId: activated.organisationId,
        siteId: activated.siteId,
        kind: AUDIT_WHISPER_ACTIVATED,
        actorUserId: input.approvedByUserId,
        payload: {
          whisper_signal_id: activated.whisperSignalId,
          signal_version: activated.signalVersion,
          configuration_fingerprint: activated.configurationFingerprint,
          actor_user_id: input.approvedByUserId,
          device_id: null,
          from_status: input.expectedStatus,
          to_status: 'ACTIVE',
          outcome: null,
          conflict_code: null,
          recognition_fingerprint: null,
          response_protocol_id: null,
          incident_id: null,
          trace_id: input.traceId,
        },
      });

      return { kind: 'written', row: { activated, rotatedVersions: incumbents.map((row) => row.signalVersion) } };
    });
  }

  // ---------------------------------------------------------------------------
  // Runtime: the durable anti-replay receipt (B11-12)
  // ---------------------------------------------------------------------------

  /**
   * The SEVEN identity columns (C11-01). Not a concatenation and not a hash: a
   * delimiter-joined key would let two different tuples collide, which for
   * this table means one tenant's nonce consuming another's replay slot.
   */
  async findReceiptByIdentity(identity: WhisperReplayIdentity): Promise<WhisperStoredReceipt | null> {
    const row = await this.prisma.whisperRecognitionReceipt.findUnique({
      where: {
        organisationId_siteId_actorUserId_deviceId_whisperSignalId_whisperSignalVersion_antiReplayNonce: {
          organisationId: identity.organisation_id,
          siteId: identity.site_id,
          actorUserId: identity.actor_user_id,
          deviceId: identity.device_id,
          whisperSignalId: identity.whisper_signal_id,
          whisperSignalVersion: identity.whisper_signal_version,
          antiReplayNonce: identity.anti_replay_nonce,
        },
      },
      select: receiptProjection,
    });
    return row === null ? null : mapReceipt(row);
  }

  /** A fresh, NON-transactional read — used to report what the attempt that WON actually recorded. */
  async getReceiptById(receiptId: string): Promise<WhisperStoredReceipt | null> {
    const row = await this.prisma.whisperRecognitionReceipt.findUnique({ where: { id: receiptId }, select: receiptProjection });
    return row === null ? null : mapReceipt(row);
  }

  /**
   * Materialises the receipt BEFORE any effect is attempted, so a crash
   * between here and the SILENT entry leaves a recoverable record rather than
   * an invisible one — and, critically, leaves the replay identity CONSUMED.
   *
   * Deliberately OUTSIDE any interactive transaction: a P2002 raised inside a
   * Prisma interactive transaction aborts the whole Postgres transaction (no
   * savepoint is taken), so a create/create race handled in place would poison
   * the very transaction that must go on to claim and finalize. Losing the
   * race here is not a failure — the winner's row is the one both callers then
   * classify against, which is exactly the convergence a retry needs.
   */
  async ensureReceipt(input: EnsureReceiptInput): Promise<{ receipt: WhisperStoredReceipt; created: boolean }> {
    try {
      const row = await this.prisma.whisperRecognitionReceipt.create({
        data: {
          organisationId: input.identity.organisation_id,
          siteId: input.identity.site_id,
          actorUserId: input.identity.actor_user_id,
          deviceId: input.identity.device_id,
          whisperSignalId: input.identity.whisper_signal_id,
          whisperSignalVersion: input.identity.whisper_signal_version,
          antiReplayNonce: input.identity.anti_replay_nonce,
          signalVersionId: input.signalVersionId,
          recognitionFingerprint: input.recognitionFingerprint,
          status: RECEIPT_STATUS_RECEIVED,
          recordedAt: input.recordedAt,
          traceId: input.traceId,
        },
        select: receiptProjection,
      });
      return { receipt: mapReceipt(row), created: true };
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      const existing = await this.findReceiptByIdentity(input.identity);
      if (existing === null) {
        throw new WhisperUniquenessConflictError('Whisper recognition receipt collided but could not be re-read');
      }
      return { receipt: existing, created: false };
    }
  }

  /**
   * B11-12 compare-and-set claim with a recovery lease, and the FENCING TOKEN.
   *
   * RECEIVED and UNKNOWN are claimable outright. APPLYING is claimable only
   * once its claim has aged past the lease — a NEWER claim belongs to a live
   * attempt, and stealing it would be the double-dispatch this receipt exists
   * to prevent. APPLIED and REFUSED appear in no branch, so a finalized
   * recognition can never be re-claimed and can never open a second incident.
   *
   * The whole predicate lives in the WHERE clause, so the winner is decided by
   * the database's row lock rather than by a read-then-write a loser could
   * interleave with. The generation is read back INSIDE the claiming
   * transaction, where the row stays write-locked until commit: read outside,
   * it could observe a LATER attempt's count and hand this worker a fencing
   * token belonging to someone else, which would defeat the fence entirely.
   */
  async claimReceipt(receiptId: string): Promise<number | null> {
    return this.prisma.$transaction(async (tx) => {
      const now = await this.clockNow(tx);
      const leaseExpiry = new Date(now.getTime() - WHISPER_PROCESSING_LEASE_MS);
      const claim = await tx.whisperRecognitionReceipt.updateMany({
        where: {
          id: receiptId,
          OR: [
            { status: { in: [RECEIPT_STATUS_RECEIVED, RECEIPT_STATUS_UNKNOWN] } },
            { status: RECEIPT_STATUS_APPLYING, processingClaimedAt: { lt: leaseExpiry } },
          ],
        },
        data: { status: RECEIPT_STATUS_APPLYING, processingClaimedAt: now, attemptCount: { increment: 1 } },
      });
      if (claim.count !== 1) return null;
      const claimed = await tx.whisperRecognitionReceipt.findUnique({ where: { id: receiptId }, select: { attemptCount: true } });
      // Updated inside this very transaction, so absence is an integrity fault
      // rather than a race. Fail loudly instead of inventing a fencing token
      // that no subsequent write could ever match.
      if (claimed === null) throw new Error('whisper recognition receipt vanished inside its own claim transaction');
      return claimed.attemptCount;
    });
  }

  /**
   * The terminal write, FENCED on `(id, status = APPLYING, attemptCount =
   * claimGeneration)` and running FIRST — before the audit row — so a lost
   * fence leaves the transaction having mutated nothing at all.
   *
   * THE CORRUPTION THIS PREVENTS. Attempt A claims at generation 1 and stalls
   * past its lease. Attempt B legally reclaims at generation 2, opens the
   * silent incident and finalizes ACCEPTED. A then wakes holding a verdict
   * computed from a world that no longer exists; unfenced, its `update by id`
   * would land on top of B's — a stale REFUSED overwriting a real ACCEPTED,
   * erasing the only durable record that a duress signal was acted upon.
   */
  async finalizeReceipt(input: FinalizeReceiptInput): Promise<'finalized' | 'lost'> {
    return this.prisma.$transaction(async (tx) => {
      const finalizedAt = await this.clockNow(tx);
      const fenced = await tx.whisperRecognitionReceipt.updateMany({
        where: { id: input.receiptId, status: RECEIPT_STATUS_APPLYING, attemptCount: input.claimGeneration },
        data: {
          status: input.status,
          outcome: input.outcome,
          conflictCode: input.conflictCode,
          incidentId: input.incidentId,
          finalizedAt,
        },
      });
      if (fenced.count === 0) return 'lost';
      await this.writeAudit(tx, input.audit);
      return 'finalized';
    });
  }

  /**
   * B11-12 INFRASTRUCTURE fault: the outcome is genuinely unknown, so it is
   * recorded as unknown and the receipt becomes immediately reclaimable.
   *
   * NO AUDIT ROW IS WRITTEN, deliberately. W21-14's payload can express
   * ACCEPTED and REFUSED and nothing else, and that is correct — an unresolved
   * attempt has no outcome to record, and writing one would put a verdict in
   * the audit trail that nobody actually reached. The receipt row carries the
   * UNKNOWN, which is what recovery reads.
   *
   * Fenced identically to `finalizeReceipt`, and for a sharper reason:
   * unfenced, a stale worker would DOWNGRADE a newer attempt's finalized
   * APPLIED back to UNKNOWN, re-opening a recognition whose incident has
   * already been opened.
   */
  async markReceiptUnknown(input: MarkReceiptUnknownInput): Promise<'marked' | 'lost'> {
    const fenced = await this.prisma.whisperRecognitionReceipt.updateMany({
      where: { id: input.receiptId, status: RECEIPT_STATUS_APPLYING, attemptCount: input.claimGeneration },
      data: { status: RECEIPT_STATUS_UNKNOWN },
    });
    return fenced.count === 0 ? 'lost' : 'marked';
  }
}
