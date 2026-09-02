import { Inject, Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * WP-24 Shield persistence primitives.
 *
 * THIS REPOSITORY HOLDS NO SECURITY POLICY. Every rule WP-24 enforces already
 * exists as a frozen evaluator in `packages/contracts/src/device-*.ts`
 * (D24-01), and the services call those evaluators. What lives here is the set
 * of storage operations those decisions need, each carrying exactly the
 * concurrency guarantee the directive requires — nothing more.
 *
 * WHY THE LOCK READS ARE RAW SQL
 * ------------------------------
 * D24-06 requires every authority-bearing row to be RE-READ AND LOCKED inside
 * the commit transaction, and re-validated there rather than trusted from an
 * earlier read. Prisma's query API cannot express `SELECT ... FOR UPDATE`, so
 * the lock reads below are `$queryRaw` with explicit column aliases. They are
 * the only raw reads in the module and they exist for one reason: a row read
 * without a lock can have moved by the time the decision it fed is committed,
 * and "the grant was usable when I looked" is not a fact a commit may rest on.
 *
 * APPEND-ONLY IS A PROPERTY OF THIS FILE, NOT A PROMISE ABOUT IT (D24-12)
 * ----------------------------------------------------------------------
 * `DeviceSecurityEvent`, `DeviceTrustTransition` and
 * `DeviceAttestationObservation` are reachable through exactly three writers —
 * `appendTrustTransition`, `appendAttestationObservation` and the audit
 * writer's own `create` — and every one of them calls `create`. There is no
 * update, no delete, no upsert, no `deleteMany` and no `updateMany` against
 * any of the three, anywhere in this module.
 *
 * `test/shield-append-only.architecture.spec.ts` asserts that as a SOURCE
 * SCAN, for the reason the Whisper boundary guard gives: a property protected
 * by review is a property protected until the first busy week.
 */

export type Tx = Prisma.TransactionClient;

/**
 * C16-R2: is this the driver's UNIQUENESS violation?
 *
 * Exported from the persistence layer so `@prisma/client` error internals stay
 * here rather than leaking into a service. A service that wants to resolve a
 * lost insert race needs to recognise the collision — and recognising it by
 * matching an error MESSAGE is exactly the sort of string archaeology that
 * quietly stops working on a driver upgrade.
 *
 * Deliberately NOT narrowed to one constraint name. Prisma reports
 * `meta.target` differently across connectors and versions (a string here, an
 * array of field names there), so the caller confirms WHICH row it lost to by
 * RE-READING the authoritative row it expects — a database fact — and re-throws
 * if that read does not find one.
 */
export function isUniqueConstraintViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

// ---------------------------------------------------------------------------
// Row projections
//
// Deliberately NOT the Prisma model types. A projection names exactly the
// columns a decision needs, so widening what a service can see is a visible
// diff here rather than an accident of `select: undefined`.
// ---------------------------------------------------------------------------

export interface BootstrapGrantRow {
  id: string;
  organisationId: string;
  siteId: string;
  intendedUserId: string;
  issuedByUserId: string;
  issuedAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
  revokedAt: Date | null;
}

export interface DeviceCustodyRegimeRow {
  id: string;
  organisationId: string;
  siteId: string;
  name: string;
  definedByUserId: string;
  createdAt: Date;
  retiredAt: Date | null;
}

export interface EnrollmentRequestRow {
  id: string;
  organisationId: string;
  siteId: string;
  intendedUserId: string;
  bootstrapGrantId: string;
  custody: string;
  custodyRegimeId: string | null;
  approvedSemanticsDigest: string;
  publicKey: string;
  publicKeyThumbprint: string;
  keyStorage: string;
  claimedSignatureProfile: string;
  serverSelectedSignatureProfile: string;
  requestFingerprint: string;
  attestationOutcome: string;
  attestationEvaluatedAt: Date;
  attestationReference: string | null;
  requestedAt: Date;
  state: string;
}

export interface EnrollmentApprovalRow {
  id: string;
  organisationId: string;
  enrollmentRequestId: string;
  approvedByUserId: string;
  approvedRequestFingerprint: string;
  approvedSiteId: string;
  approvedIntendedUserId: string;
  approvedCustody: string;
  approvedCustodyRegimeId: string | null;
  approvedSemanticsDigest: string;
  approvedAt: Date;
}

export interface PossessionChallengeRow {
  id: string;
  organisationId: string;
  enrollmentRequestId: string;
  nonce: string;
  issuedAt: Date;
  expiresAt: Date;
}

export interface PossessionVerificationRow {
  id: string;
  organisationId: string;
  challengeId: string;
  enrollmentRequestId: string;
  enrollmentRequestFingerprint: string;
  publicKeyThumbprint: string;
  possessionStatementFingerprint: string;
  signatureProfile: string;
  verified: boolean;
  verifiedAt: Date;
}

export interface DeviceRow {
  id: string;
  organisationId: string;
  custody: string;
  enrolledByUserId: string;
  intendedUserId: string;
  sequenceNamespaceId: string;
  trust: string;
  revocationDisposition: string | null;
  revokedAt: Date | null;
  currentKeyId: string | null;
  currentKeyVersion: number | null;
  enrollmentRequestId: string;
  enrolledAt: Date;
}

export interface DeviceKeyRow {
  id: string;
  organisationId: string;
  deviceId: string;
  keyId: string;
  keyVersion: number;
  publicKey: string;
  publicKeyThumbprint: string;
  signatureProfile: string;
  keyStorage: string;
  status: string;
  registeredAt: Date;
  rotatedAt: Date | null;
  revokedAt: Date | null;
  revocationDisposition: string | null;
}

export interface RotationRequestRow {
  id: string;
  organisationId: string;
  deviceId: string;
  currentKeyId: string;
  currentKeyVersion: number;
  proposedKeyId: string;
  proposedKeyVersion: number;
  newPublicKey: string;
  newPublicKeyThumbprint: string;
  newKeyStorage: string;
  serverResolvedSignatureProfile: string;
  requestFingerprint: string;
  requestedAt: Date;
  state: string;
}

export interface RotationChallengeRow {
  id: string;
  organisationId: string;
  deviceId: string;
  rotationRequestId: string;
  rotationRequestFingerprint: string;
  currentKeyId: string;
  currentKeyVersion: number;
  proposedKeyId: string;
  proposedKeyVersion: number;
  newPublicKeyThumbprint: string;
  nonce: string;
  issuedAt: Date;
  expiresAt: Date;
}

export interface RotationVerificationRow {
  id: string;
  organisationId: string;
  deviceId: string;
  rotationRequestId: string;
  rotationRequestFingerprint: string;
  rotationChallengeId: string;
  currentKeyId: string;
  currentKeyVersion: number;
  proposedKeyId: string;
  proposedKeyVersion: number;
  newPublicKeyThumbprint: string;
  signatureProfile: string;
  canonicalStatementFingerprint: string;
  verified: boolean;
  verifiedAt: Date;
}

/** The one row shape a raw `COUNT`/`EXISTS` probe returns. */
interface ExistsRow {
  present: boolean;
}

function first<T>(rows: T[]): T | null {
  return rows.length === 0 ? null : (rows[0] as T);
}

/**
 * C16-02/C16-03: is this string something a `uuid` column can even be compared
 * against?
 *
 * The stored outcome references the replay table holds are always ids this
 * service generated, so in a healthy registry this is always true. It is
 * checked anyway because the whole point of the resolution paths that use it is
 * to survive a store that is NOT healthy: a hand-edited or corrupted reference
 * must produce a REFUSAL, and handing a non-uuid to Prisma produces a thrown
 * driver fault instead — which would escape the refusal-as-data discipline this
 * module is built on and reach a caller as an exception.
 */
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

function isUuid(value: string): boolean {
  return UUID_PATTERN.test(value);
}

@Injectable()
export class ShieldRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  // -------------------------------------------------------------------------
  // Shared primitives
  // -------------------------------------------------------------------------

  /**
   * Runs the caller's unit of work in one interactive transaction.
   *
   * D24-06's whole argument rests on this: the lock reads, the contract
   * re-validation, the replay consumption and every write land as one unit, so
   * a decision taken against locked rows cannot be committed against a world
   * that moved underneath it.
   */
  async transaction<T>(work: (tx: Tx) => Promise<T>): Promise<T> {
    return this.prisma.$transaction(work);
  }

  /**
   * The authoritative server clock, per the WP-19/C9-06 precedent:
   * `clock_timestamp()` and never `now()`.
   *
   * Postgres pins `now()` to transaction START, which is BEFORE the row locks
   * a commit takes. Every WP-23 timing rule — the bootstrap window, the
   * challenge ceiling, C15-R3's whole chronology chain — is judged against
   * this value, so an instant taken before the serialization boundary the
   * ceremony claims to have crossed would be judging the wrong moment.
   */
  async dbNow(tx: Tx): Promise<Date> {
    const rows = await tx.$queryRaw<Array<{ now: Date }>>(Prisma.sql`SELECT clock_timestamp() AS now`);
    const row = first(rows);
    if (row === null) throw new Error('clock_timestamp returned no row');
    return row.now;
  }

  /** The same clock, outside a transaction, for the non-committing paths. */
  async now(): Promise<Date> {
    const rows = await this.prisma.$queryRaw<Array<{ now: Date }>>(Prisma.sql`SELECT clock_timestamp() AS now`);
    const row = first(rows);
    if (row === null) throw new Error('clock_timestamp returned no row');
    return row.now;
  }

  /**
   * WP-17A/C7-07 write-time integrity check, and the ISOLATION boundary.
   *
   * The composite `(id, organisation_id)` foreign keys are the real defence —
   * D24-04a puts the database itself between one tenant's organisation and
   * another tenant's site — but a raw FK violation surfacing mid-transaction is
   * a fault, not a refusal. This proves the pairing first so the service can
   * answer `SITE_NOT_FOUND`, which is the SAME answer a nonexistent site gets.
   */
  async siteExistsInOrganisation(organisationId: string, siteId: string): Promise<boolean> {
    const site = await this.prisma.site.findFirst({ where: { id: siteId, organisationId }, select: { id: true } });
    return site !== null;
  }

  /** The same, for users. `USER_NOT_FOUND` covers absent and foreign alike. */
  async userExistsInOrganisation(organisationId: string, userId: string): Promise<boolean> {
    const user = await this.prisma.user.findFirst({ where: { id: userId, organisationId }, select: { id: true } });
    return user !== null;
  }

  // -------------------------------------------------------------------------
  // Custody regimes (C16-01)
  //
  // The catalogue a CONTROLLED_SHARED enrollment names. The id is generated by
  // Postgres-side defaults through Prisma, never by a caller: there is no
  // parameter below through which one could arrive.
  // -------------------------------------------------------------------------

  async createCustodyRegime(
    tx: Tx,
    input: { organisationId: string; siteId: string; name: string; definedByUserId: string },
  ): Promise<DeviceCustodyRegimeRow> {
    return tx.deviceCustodyRegime.create({ data: input });
  }

  /**
   * C16-01: the regime, looked up by id WITHIN A TENANT.
   *
   * Keyed on organisation as well as id for the reason every other read in this
   * file is: a regime id is a registry identifier, not a global secret, and a
   * lookup by id alone would let one tenant's catalogue be selected from
   * another tenant's ceremony. The SITE match is the caller's, because a regime
   * and a request can legitimately share a tenant and differ in site — and that
   * pairing must refuse rather than silently widen the regime's reach.
   */
  async findCustodyRegime(organisationId: string, id: string): Promise<DeviceCustodyRegimeRow | null> {
    // C16-01: a caller-presented régime id is UNTRUSTED INPUT. A value that is
    // not a uuid at all must answer NOT_FOUND like any other absent régime,
    // not surface a driver fault from the `uuid` column comparison.
    if (!isUuid(id)) return null;
    return this.prisma.deviceCustodyRegime.findFirst({ where: { id, organisationId } });
  }

  /**
   * C16-R1: the SAME regime, re-read and LOCKED inside the commit transaction.
   *
   * `findCustodyRegime` above answers "was this regime acceptable when the
   * request was opened?". That question was asked minutes or hours before the
   * commit, and a regime can be retired in between. D24-06's rule — every
   * authority-bearing row is re-read under `FOR UPDATE` at commit and
   * re-validated there — applies to the custody regime exactly as it applies to
   * the grant, the request and the approval: the regime is what governs the
   * hand-over discipline of the hardware this transaction is about to register.
   *
   * `FOR UPDATE` and not `FOR SHARE`: retirement is an UPDATE of this row, and
   * the claim being made is "this regime must not be retired between the moment
   * I judged it live and the moment I commit a device under it".
   */
  async lockCustodyRegime(tx: Tx, organisationId: string, id: string): Promise<DeviceCustodyRegimeRow | null> {
    if (!isUuid(id)) return null;
    const rows = await tx.$queryRaw<DeviceCustodyRegimeRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", site_id AS "siteId", name,
             defined_by_user_id AS "definedByUserId", created_at AS "createdAt",
             retired_at AS "retiredAt"
      FROM device_custody_regimes
      WHERE id = ${id}::uuid AND organisation_id = ${organisationId}
      FOR UPDATE`);
    return first(rows);
  }

  // -------------------------------------------------------------------------
  // Bootstrap grants (D24-03a)
  // -------------------------------------------------------------------------

  async createBootstrapGrant(
    tx: Tx,
    input: {
      organisationId: string;
      siteId: string;
      intendedUserId: string;
      issuedByUserId: string;
      tokenDigest: string;
      issuedAt: Date;
      expiresAt: Date;
    },
  ): Promise<BootstrapGrantRow> {
    const row = await tx.enrollmentBootstrapGrant.create({
      data: {
        organisationId: input.organisationId,
        siteId: input.siteId,
        intendedUserId: input.intendedUserId,
        issuedByUserId: input.issuedByUserId,
        tokenDigest: input.tokenDigest,
        issuedAt: input.issuedAt,
        expiresAt: input.expiresAt,
      },
    });
    return row;
  }

  /**
   * D24-03a: THE LOOKUP IS BY DIGEST ALONE, ACROSS ORGANISATIONS. Deliberately.
   *
   * A grant presented in an unexpected organisation must BURN, and a burn is
   * impossible if the lookup is already scoped to the organisation the
   * presenter claims — the row would simply not be found and the attacker
   * could keep trying the same secret in every tenant until they hit the right
   * one. Reading by digest is what makes the probe detectable.
   *
   * This is safe precisely because the digest is not an identifier: it is
   * SHA-256 of >= 256 bits of cryptographic randomness. There is no id to
   * enumerate and no scope to widen — possession of the pre-image IS the
   * lookup key, and the service compares the row's real scope against the
   * presented one immediately afterwards.
   */
  async findBootstrapGrantByTokenDigest(tokenDigest: string): Promise<BootstrapGrantRow | null> {
    return this.prisma.enrollmentBootstrapGrant.findFirst({ where: { tokenDigest } });
  }

  /** D24-06: the grant, re-read and locked inside the commit transaction. */
  async lockBootstrapGrant(tx: Tx, organisationId: string, grantId: string): Promise<BootstrapGrantRow | null> {
    const rows = await tx.$queryRaw<BootstrapGrantRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", site_id AS "siteId",
             intended_user_id AS "intendedUserId", issued_by_user_id AS "issuedByUserId",
             issued_at AS "issuedAt", expires_at AS "expiresAt",
             consumed_at AS "consumedAt", revoked_at AS "revokedAt"
      FROM device_enrollment_bootstrap_grants
      WHERE id = ${grantId}::uuid AND organisation_id = ${organisationId}
      FOR UPDATE`);
    return first(rows);
  }

  /**
   * D24-03a: burns the grant. Used for the PROBE path and for explicit
   * revocation — a grant that survives being probed is a grant an attacker may
   * keep trying.
   *
   * `consumedAt` is set only where it is a REFUSAL, never on a successful
   * enrollment. See the long note in `device-enrollment.service.ts`: single use
   * on the success path is enforced by the durable `DeviceNonceConsumption`
   * row (D24-11), because `classifyDeviceBootstrapGrant` reports a grant with
   * `consumed_at` set as CONSUMED and the commit gate then refuses it BEFORE
   * reaching its own convergence arm — which would make D24-06's "exact retry
   * converges on the SAME device identity" unreachable.
   */
  async burnBootstrapGrant(tx: Tx, organisationId: string, grantId: string, at: Date): Promise<void> {
    await tx.enrollmentBootstrapGrant.updateMany({
      where: { id: grantId, organisationId, consumedAt: null },
      data: { consumedAt: at },
    });
  }

  async revokeBootstrapGrant(tx: Tx, organisationId: string, grantId: string, at: Date): Promise<number> {
    const result = await tx.enrollmentBootstrapGrant.updateMany({
      where: { id: grantId, organisationId, revokedAt: null },
      data: { revokedAt: at },
    });
    return result.count;
  }

  async findBootstrapGrant(organisationId: string, grantId: string): Promise<BootstrapGrantRow | null> {
    return this.prisma.enrollmentBootstrapGrant.findFirst({ where: { id: grantId, organisationId } });
  }

  // -------------------------------------------------------------------------
  // Enrollment requests, approvals, challenges, verifications
  // -------------------------------------------------------------------------

  async createEnrollmentRequest(
    tx: Tx,
    input: {
      id: string;
      organisationId: string;
      siteId: string;
      intendedUserId: string;
      bootstrapGrantId: string;
      custody: string;
      custodyRegimeId: string | null;
      publicKey: string;
      publicKeyThumbprint: string;
      keyStorage: string;
      claimedSignatureProfile: string;
      serverSelectedSignatureProfile: string;
      requestFingerprint: string;
      approvedSemanticsDigest: string;
      attestationOutcome: string;
      attestationEvaluatedAt: Date;
      attestationReference: string | null;
      requestedAt: Date;
      state: string;
    },
  ): Promise<EnrollmentRequestRow> {
    return tx.enrollmentRequest.create({ data: input });
  }

  async findEnrollmentRequest(organisationId: string, id: string): Promise<EnrollmentRequestRow | null> {
    return this.prisma.enrollmentRequest.findFirst({ where: { id, organisationId } });
  }

  /**
   * WP-26/D26-09: the enrollments in this tenant that are still awaiting a
   * human decision, optionally narrowed to the sites a reader may see.
   *
   * `siteIds === null` means GENUINE ORGANISATION-WIDE authority and must not
   * be confused with an empty list, which means "this reader holds the action at
   * no site" and must return nothing. Collapsing the two is the classic way a
   * scoped read becomes a tenant-wide one, and `readableSiteIds` returns them as
   * two different values for exactly that reason (C16-06).
   *
   * REQUESTED only. An approved, committed or otherwise advanced ceremony is
   * not awaiting a decision, and a queue that shows finished work is a queue an
   * operator stops reading.
   */
  async listPendingEnrollmentRequests(organisationId: string, siteIds: string[] | null): Promise<EnrollmentRequestRow[]> {
    return this.prisma.enrollmentRequest.findMany({
      where: {
        organisationId,
        state: 'REQUESTED',
        ...(siteIds === null ? {} : { siteId: { in: siteIds } }),
      },
      orderBy: { requestedAt: 'asc' },
    });
  }

  /**
   * C16-02: THE request a bootstrap grant has already opened, if any.
   *
   * `enrollment_request_grant_key` makes this at most one row, and the service
   * uses it to tell a RETRY from a CONFLICT: an identical repeat submission
   * converges on what is here, a materially different one is refused. Without
   * the unique index this read would be a race; with it, it is a fact.
   */
  async findEnrollmentRequestByGrant(organisationId: string, bootstrapGrantId: string): Promise<EnrollmentRequestRow | null> {
    return this.prisma.enrollmentRequest.findFirst({ where: { organisationId, bootstrapGrantId } });
  }

  /**
   * C16-R2: the SAME question, asked INSIDE the writing transaction and under
   * `FOR UPDATE`.
   *
   * `findEnrollmentRequestByGrant` above is a read-before-write, and two
   * simultaneous first submissions can both be answered "none". One then wins
   * the insert and the other collides with `enrollment_request_grant_key`. This
   * read is what the loser uses to discover the ONE authoritative request that
   * actually exists, in the transaction that is resolving its own collision, so
   * the convergence/conflict answer is decided against a row that cannot move
   * underneath it.
   */
  async lockEnrollmentRequestByGrant(
    tx: Tx,
    organisationId: string,
    bootstrapGrantId: string,
  ): Promise<EnrollmentRequestRow | null> {
    if (!isUuid(bootstrapGrantId)) return null;
    const rows = await tx.$queryRaw<EnrollmentRequestRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", site_id AS "siteId",
             intended_user_id AS "intendedUserId", bootstrap_grant_id AS "bootstrapGrantId",
             custody, custody_regime_id AS "custodyRegimeId",
             approved_semantics_digest AS "approvedSemanticsDigest",
             public_key AS "publicKey", public_key_thumbprint AS "publicKeyThumbprint",
             key_storage AS "keyStorage", claimed_signature_profile AS "claimedSignatureProfile",
             server_selected_signature_profile AS "serverSelectedSignatureProfile",
             request_fingerprint AS "requestFingerprint", attestation_outcome AS "attestationOutcome",
             attestation_evaluated_at AS "attestationEvaluatedAt",
             attestation_reference AS "attestationReference",
             requested_at AS "requestedAt", state
      FROM device_enrollment_requests
      WHERE organisation_id = ${organisationId} AND bootstrap_grant_id = ${bootstrapGrantId}::uuid
      FOR UPDATE`);
    return first(rows);
  }

  /**
   * C16-R2 — THE SAVEPOINT THE GRANT RACE IS RESOLVED INSIDE.
   *
   * A uniqueness violation aborts the whole Postgres transaction: every
   * statement after it fails with 25P02 until the transaction ends. So a
   * service that wants to CATCH the collision and then re-read the winning row
   * in the same transaction cannot simply try/catch — it has to mark a point it
   * can rewind to first.
   *
   * The name is a module constant and not a parameter. A savepoint name is a
   * SQL identifier, it cannot be bound as a parameter, and the only safe way to
   * keep an unparameterisable value out of an attacker's reach is to give
   * callers no way to supply one.
   */
  async openEnrollmentRequestSavepoint(tx: Tx): Promise<void> {
    await tx.$executeRaw(Prisma.sql`SAVEPOINT wp24_enrollment_request_insert`);
  }

  /** C16-R2: rewind to the savepoint above, leaving the transaction usable. */
  async rollbackEnrollmentRequestSavepoint(tx: Tx): Promise<void> {
    await tx.$executeRaw(Prisma.sql`ROLLBACK TO SAVEPOINT wp24_enrollment_request_insert`);
  }

  /** D24-06: the request itself, locked, so its state cannot advance mid-commit. */
  async lockEnrollmentRequest(tx: Tx, organisationId: string, id: string): Promise<EnrollmentRequestRow | null> {
    const rows = await tx.$queryRaw<EnrollmentRequestRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", site_id AS "siteId",
             intended_user_id AS "intendedUserId", bootstrap_grant_id AS "bootstrapGrantId",
             custody, custody_regime_id AS "custodyRegimeId",
             approved_semantics_digest AS "approvedSemanticsDigest",
             public_key AS "publicKey", public_key_thumbprint AS "publicKeyThumbprint",
             key_storage AS "keyStorage", claimed_signature_profile AS "claimedSignatureProfile",
             server_selected_signature_profile AS "serverSelectedSignatureProfile",
             request_fingerprint AS "requestFingerprint", attestation_outcome AS "attestationOutcome",
             attestation_evaluated_at AS "attestationEvaluatedAt",
             attestation_reference AS "attestationReference",
             requested_at AS "requestedAt", state
      FROM device_enrollment_requests
      WHERE id = ${id}::uuid AND organisation_id = ${organisationId}
      FOR UPDATE`);
    return first(rows);
  }

  /**
   * Advances the enrollment state machine.
   *
   * `canTransitionDeviceEnrollment` — the CONTRACT's matrix — is what decides
   * whether a move is legal; the caller checks it and this method performs it,
   * fenced on the state it believed it was leaving so two concurrent callers
   * cannot both advance from the same state.
   */
  async advanceEnrollmentState(tx: Tx, organisationId: string, id: string, from: string, to: string): Promise<number> {
    const result = await tx.enrollmentRequest.updateMany({ where: { id, organisationId, state: from }, data: { state: to } });
    return result.count;
  }

  async createEnrollmentApproval(
    tx: Tx,
    input: {
      organisationId: string;
      enrollmentRequestId: string;
      approvedByUserId: string;
      approvedRequestFingerprint: string;
      approvedSiteId: string;
      approvedIntendedUserId: string;
      approvedCustody: string;
      approvedCustodyRegimeId: string | null;
      approvedSemanticsDigest: string;
      approvedAt: Date;
    },
  ): Promise<EnrollmentApprovalRow> {
    return tx.enrollmentApproval.create({ data: input });
  }

  async findEnrollmentApproval(organisationId: string, enrollmentRequestId: string): Promise<EnrollmentApprovalRow | null> {
    return this.prisma.enrollmentApproval.findFirst({ where: { organisationId, enrollmentRequestId } });
  }

  /** D24-06: the approval, locked. `issuer != approver` is re-checked against THIS row. */
  async lockEnrollmentApproval(tx: Tx, organisationId: string, enrollmentRequestId: string): Promise<EnrollmentApprovalRow | null> {
    const rows = await tx.$queryRaw<EnrollmentApprovalRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", enrollment_request_id AS "enrollmentRequestId",
             approved_by_user_id AS "approvedByUserId",
             approved_request_fingerprint AS "approvedRequestFingerprint",
             approved_site_id AS "approvedSiteId", approved_intended_user_id AS "approvedIntendedUserId",
             approved_custody AS "approvedCustody",
             approved_custody_regime_id AS "approvedCustodyRegimeId",
             approved_semantics_digest AS "approvedSemanticsDigest",
             approved_at AS "approvedAt"
      FROM device_enrollment_approvals
      WHERE organisation_id = ${organisationId} AND enrollment_request_id = ${enrollmentRequestId}::uuid
      FOR UPDATE`);
    return first(rows);
  }

  async createPossessionChallenge(input: {
    organisationId: string;
    enrollmentRequestId: string;
    nonce: string;
    issuedAt: Date;
    expiresAt: Date;
  }): Promise<PossessionChallengeRow> {
    return this.prisma.possessionChallenge.create({ data: input });
  }

  async findPossessionChallenge(organisationId: string, id: string): Promise<PossessionChallengeRow | null> {
    return this.prisma.possessionChallenge.findFirst({ where: { id, organisationId } });
  }

  async lockPossessionChallenge(tx: Tx, organisationId: string, id: string): Promise<PossessionChallengeRow | null> {
    const rows = await tx.$queryRaw<PossessionChallengeRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", enrollment_request_id AS "enrollmentRequestId",
             nonce, issued_at AS "issuedAt", expires_at AS "expiresAt"
      FROM device_possession_challenges
      WHERE id = ${id}::uuid AND organisation_id = ${organisationId}
      FOR UPDATE`);
    return first(rows);
  }

  async createPossessionVerification(
    tx: Tx,
    input: {
      organisationId: string;
      challengeId: string;
      enrollmentRequestId: string;
      enrollmentRequestFingerprint: string;
      publicKeyThumbprint: string;
      possessionStatementFingerprint: string;
      signatureProfile: string;
      verified: boolean;
      verifiedAt: Date;
    },
  ): Promise<PossessionVerificationRow> {
    return tx.possessionVerification.create({ data: input });
  }

  async lockPossessionVerification(tx: Tx, organisationId: string, challengeId: string): Promise<PossessionVerificationRow | null> {
    const rows = await tx.$queryRaw<PossessionVerificationRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", challenge_id AS "challengeId",
             enrollment_request_id AS "enrollmentRequestId",
             enrollment_request_fingerprint AS "enrollmentRequestFingerprint",
             public_key_thumbprint AS "publicKeyThumbprint",
             possession_statement_fingerprint AS "possessionStatementFingerprint",
             signature_profile AS "signatureProfile", verified, verified_at AS "verifiedAt"
      FROM device_possession_verifications
      WHERE organisation_id = ${organisationId} AND challenge_id = ${challengeId}::uuid
      FOR UPDATE`);
    return first(rows);
  }

  // -------------------------------------------------------------------------
  // Devices, keys and site scope
  // -------------------------------------------------------------------------

  async createDevice(
    tx: Tx,
    input: {
      id: string;
      organisationId: string;
      custody: string;
      enrolledByUserId: string;
      intendedUserId: string;
      sequenceNamespaceId: string;
      trust: string;
      currentKeyId: string;
      currentKeyVersion: number;
      enrollmentRequestId: string;
      enrolledAt: Date;
    },
  ): Promise<DeviceRow> {
    return tx.device.create({ data: input });
  }

  /**
   * WP-25/D25-16: `tx` is an internal composition seam, not a widened API. The
   * gateway's final effect transaction re-reads this row AFTER locking it and
   * must see the transaction's own view, not a second connection's. Existing
   * callers pass nothing and reach exactly the query they always did.
   */
  async findDevice(organisationId: string, deviceId: string, tx?: Tx): Promise<DeviceRow | null> {
    const db: Tx = tx ?? this.prisma;
    return db.device.findFirst({ where: { id: deviceId, organisationId } });
  }

  async findDeviceByEnrollmentRequest(tx: Tx, organisationId: string, enrollmentRequestId: string): Promise<DeviceRow | null> {
    return tx.device.findFirst({ where: { organisationId, enrollmentRequestId } });
  }

  /**
   * C16-02: does this stored outcome reference resolve to a device that
   * ACTUALLY EXISTS and belongs to THIS EXACT ceremony?
   *
   * Both halves matter. A reference naming a device that was never created is
   * the defect C16-02 exists to close — a replay row that outlived the effect it
   * claimed. A reference naming a real device from a DIFFERENT enrollment
   * request would be worse: convergence onto someone else's hardware identity.
   * The read is taken inside the caller's transaction so the answer is the one
   * the commit will actually be judged against.
   */
  async resolveDeviceOutcomeRef(
    tx: Tx,
    organisationId: string,
    deviceId: string,
    enrollmentRequestId: string,
  ): Promise<DeviceRow | null> {
    if (!isUuid(deviceId)) return null;
    return tx.device.findFirst({ where: { id: deviceId, organisationId, enrollmentRequestId } });
  }

  /** D24-06/D24-10A: the device row, locked, so a concurrent revocation cannot slip past. */
  async lockDevice(tx: Tx, organisationId: string, deviceId: string): Promise<DeviceRow | null> {
    const rows = await tx.$queryRaw<DeviceRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", custody,
             enrolled_by_user_id AS "enrolledByUserId", intended_user_id AS "intendedUserId",
             sequence_namespace_id AS "sequenceNamespaceId", trust,
             revocation_disposition AS "revocationDisposition", revoked_at AS "revokedAt",
             current_key_id AS "currentKeyId", current_key_version AS "currentKeyVersion",
             enrollment_request_id AS "enrollmentRequestId", enrolled_at AS "enrolledAt"
      FROM devices
      WHERE id = ${deviceId}::uuid AND organisation_id = ${organisationId}
      FOR UPDATE`);
    return first(rows);
  }

  /**
   * The trust column, moved.
   *
   * Fenced on the trust the caller believed it was leaving, so two concurrent
   * decisions cannot both apply against the same starting state and lose one
   * another's transition record.
   */
  async setDeviceTrust(tx: Tx, organisationId: string, deviceId: string, from: string, to: string): Promise<number> {
    const result = await tx.device.updateMany({ where: { id: deviceId, organisationId, trust: from }, data: { trust: to } });
    return result.count;
  }

  /** D24-09: the DEVICE-level withdrawal. Independent of anything the key does. */
  async setDeviceRevocation(
    tx: Tx,
    organisationId: string,
    deviceId: string,
    input: { disposition: string; revokedAt: Date | null; trust: string },
  ): Promise<void> {
    await tx.device.updateMany({
      where: { id: deviceId, organisationId },
      data: { revocationDisposition: input.disposition, revokedAt: input.revokedAt, trust: input.trust },
    });
  }

  /** D24-10: the device keeps its id and namespace; only the key pointer advances. */
  async advanceDeviceCurrentKey(
    tx: Tx,
    organisationId: string,
    deviceId: string,
    from: { keyId: string; keyVersion: number },
    to: { keyId: string; keyVersion: number },
  ): Promise<number> {
    const result = await tx.device.updateMany({
      where: { id: deviceId, organisationId, currentKeyId: from.keyId, currentKeyVersion: from.keyVersion },
      data: { currentKeyId: to.keyId, currentKeyVersion: to.keyVersion },
    });
    return result.count;
  }

  async createDeviceKey(
    tx: Tx,
    input: {
      id: string;
      organisationId: string;
      deviceId: string;
      keyId: string;
      keyVersion: number;
      publicKey: string;
      publicKeyThumbprint: string;
      signatureProfile: string;
      keyStorage: string;
      status: string;
      registeredAt: Date;
    },
  ): Promise<DeviceKeyRow> {
    return tx.deviceKey.create({ data: input });
  }

  /** WP-25/D25-16: the same internal composition seam as `findDevice`. */
  async findDeviceKeyByKeyId(organisationId: string, keyId: string, tx?: Tx): Promise<DeviceKeyRow | null> {
    const db: Tx = tx ?? this.prisma;
    return db.deviceKey.findFirst({ where: { organisationId, keyId } });
  }

  /**
   * C16-08: THE device's CURRENT key, resolved against a constraint rather than
   * against a `findFirst` that silently picks a winner.
   *
   * `device_keys_one_current_key` is a PARTIAL unique index over
   * (organisation_id, device_id) WHERE status = 'CURRENT', so the database
   * guarantees this set is a singleton. Prisma cannot model a partial unique
   * index, so there is no generated `findUnique` for it; what this method can
   * do — and does — is take TWO rows and treat a second as the integrity fault it
   * would be, rather than quietly returning whichever the planner happened to
   * order first. A registry that answers "which credential is live?" from an
   * arbitrary pick is not a registry.
   */
  async findCurrentDeviceKey(organisationId: string, deviceId: string): Promise<DeviceKeyRow | null> {
    const rows = await this.prisma.deviceKey.findMany({ where: { organisationId, deviceId, status: 'CURRENT' }, take: 2 });
    if (rows.length > 1) {
      throw new Error('device_keys_one_current_key violated: more than one CURRENT key for one device');
    }
    return first(rows);
  }

  /**
   * C16-03: the committed key row behind a stored rotation outcome reference.
   *
   * The reference the replay table holds is the KEY ROW id the first attempt
   * pre-generated. This resolves it AUTHORITATIVELY — inside the caller's
   * transaction, by primary key, scoped to the tenant — so a convergence answer
   * is read back from the registry rather than reconstructed from the request
   * that asked for it.
   */
  async findDeviceKeyRowById(tx: Tx, organisationId: string, id: string): Promise<DeviceKeyRow | null> {
    if (!isUuid(id)) return null;
    return tx.deviceKey.findFirst({ where: { id, organisationId } });
  }

  /** D24-10A: the key row, locked, so `STALE_ROTATION` is decided against reality. */
  async lockDeviceKeyByKeyId(tx: Tx, organisationId: string, keyId: string): Promise<DeviceKeyRow | null> {
    const rows = await tx.$queryRaw<DeviceKeyRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", device_id AS "deviceId",
             key_id AS "keyId", key_version AS "keyVersion", public_key AS "publicKey",
             public_key_thumbprint AS "publicKeyThumbprint", signature_profile AS "signatureProfile",
             key_storage AS "keyStorage", status, registered_at AS "registeredAt",
             rotated_at AS "rotatedAt", revoked_at AS "revokedAt",
             revocation_disposition AS "revocationDisposition"
      FROM device_keys
      WHERE organisation_id = ${organisationId} AND key_id = ${keyId}
      FOR UPDATE`);
    return first(rows);
  }

  /**
   * D24-10: `CURRENT -> ROTATED`, with `rotated_at` at authoritative server
   * time. Fenced on `status = 'CURRENT'`, so a key that has already been
   * revoked or rotated by another path cannot be walked backwards into a
   * routine rotation.
   */
  async markDeviceKeyRotated(tx: Tx, organisationId: string, keyId: string, rotatedAt: Date): Promise<number> {
    const result = await tx.deviceKey.updateMany({
      where: { organisationId, keyId, status: 'CURRENT' },
      data: { status: 'ROTATED', rotatedAt },
    });
    return result.count;
  }

  /**
   * D24-09: the KEY-level withdrawal. `REVOKED` or `COMPROMISED`, with the
   * disposition that caused it.
   *
   * `canTransitionDeviceKeyLifecycle` — the contract's matrix — decides
   * whether the move is legal; this performs it, fenced on the status the
   * caller read, and COMPROMISED is terminal there rather than here.
   */
  async withdrawDeviceKey(
    tx: Tx,
    organisationId: string,
    keyId: string,
    input: { from: string; to: string; revokedAt: Date; disposition: string },
  ): Promise<number> {
    const result = await tx.deviceKey.updateMany({
      where: { organisationId, keyId, status: input.from },
      data: { status: input.to, revokedAt: input.revokedAt, revocationDisposition: input.disposition },
    });
    return result.count;
  }

  async createDeviceSiteScope(
    tx: Tx,
    input: {
      organisationId: string;
      deviceId: string;
      siteId: string;
      custody: string;
      assignedUserId: string | null;
      custodyRegimeId: string | null;
      associatedAt: Date;
    },
  ): Promise<void> {
    await tx.deviceSiteScope.create({ data: input });
  }

  /**
   * WP-25/C17-04 — THE ONE (organisation, device, site) SCOPE ROW A REQUEST
   * DEPENDS ON, HELD STILL FOR THE DECISION IT FEEDS.
   *
   * `listDeviceSiteIds` answers "where is this device deployed?" as an
   * unlocked list, which is the right shape for a roster read and the WRONG
   * shape for an authority fence: between reading the list and committing the
   * effect, a concurrent transaction can release or move the very association
   * the decision rested on, and nothing would have stopped it.
   *
   * `device_site_scope_key` — UNIQUE (organisation_id, device_id, site_id) —
   * means the tuple this locks is at most one row, so `FOR UPDATE` here is a
   * lock on the EXACT fact, not on a range. A concurrent release blocks until
   * the gateway's transaction commits or rolls back; a release that got there
   * first is already visible and this returns `false`.
   *
   * `released_at IS NULL` is part of the predicate rather than a check the
   * caller applies afterwards, so "no such association" and "an association
   * that has been released" are one answer, taken by the database.
   */
  async lockActiveDeviceSiteScope(tx: Tx, organisationId: string, deviceId: string, siteId: string): Promise<boolean> {
    if (!isUuid(deviceId)) return false;
    const rows = await tx.$queryRaw<Array<{ id: string }>>(Prisma.sql`
      SELECT id
      FROM device_site_scopes
      WHERE organisation_id = ${organisationId}
        AND device_id = ${deviceId}::uuid
        AND site_id = ${siteId}
        AND released_at IS NULL
      FOR UPDATE`);
    return rows.length === 1;
  }

  /** The unlocked variant of the same question, for a preflight that commits nothing. */
  async hasActiveDeviceSiteScope(organisationId: string, deviceId: string, siteId: string): Promise<boolean> {
    const row = await this.prisma.deviceSiteScope.findFirst({
      where: { organisationId, deviceId, siteId, releasedAt: null },
      select: { id: true },
    });
    return row !== null;
  }

  async listDeviceSiteIds(organisationId: string, deviceId: string): Promise<string[]> {
    const rows = await this.prisma.deviceSiteScope.findMany({
      where: { organisationId, deviceId, releasedAt: null },
      select: { siteId: true },
    });
    return rows.map((row) => row.siteId);
  }

  /**
   * The device roster, always organisation-scoped and optionally narrowed to
   * the sites the reader's grants actually cover.
   *
   * `siteIds === null` means an ORG-WIDE grant, which is the only case in which
   * no site narrowing applies; an empty array means a site-scoped reader with
   * no sites, and returns nothing rather than everything.
   */
  async listDevices(organisationId: string, siteIds: string[] | null): Promise<DeviceRow[]> {
    if (siteIds !== null && siteIds.length === 0) return [];
    return this.prisma.device.findMany({
      where:
        siteIds === null
          ? { organisationId }
          : { organisationId, siteScopes: { some: { siteId: { in: siteIds }, releasedAt: null } } },
      orderBy: [{ enrolledAt: 'desc' }, { id: 'desc' }],
    });
  }

  // -------------------------------------------------------------------------
  // Key rotation ceremony (D24-10A)
  // -------------------------------------------------------------------------

  async createRotationRequest(input: {
    id: string;
    organisationId: string;
    deviceId: string;
    currentKeyId: string;
    currentKeyVersion: number;
    proposedKeyId: string;
    proposedKeyVersion: number;
    newPublicKey: string;
    newPublicKeyThumbprint: string;
    newKeyStorage: string;
    serverResolvedSignatureProfile: string;
    requestFingerprint: string;
    requestedAt: Date;
    state: string;
  }): Promise<RotationRequestRow> {
    return this.prisma.deviceKeyRotationRequest.create({ data: input });
  }

  async findRotationRequest(organisationId: string, id: string): Promise<RotationRequestRow | null> {
    return this.prisma.deviceKeyRotationRequest.findFirst({ where: { id, organisationId } });
  }

  async lockRotationRequest(tx: Tx, organisationId: string, id: string): Promise<RotationRequestRow | null> {
    const rows = await tx.$queryRaw<RotationRequestRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", device_id AS "deviceId",
             current_key_id AS "currentKeyId", current_key_version AS "currentKeyVersion",
             proposed_key_id AS "proposedKeyId", proposed_key_version AS "proposedKeyVersion",
             new_public_key AS "newPublicKey", new_public_key_thumbprint AS "newPublicKeyThumbprint",
             new_key_storage AS "newKeyStorage",
             server_resolved_signature_profile AS "serverResolvedSignatureProfile",
             request_fingerprint AS "requestFingerprint", requested_at AS "requestedAt", state
      FROM device_key_rotation_requests
      WHERE id = ${id}::uuid AND organisation_id = ${organisationId}
      FOR UPDATE`);
    return first(rows);
  }

  async setRotationRequestState(tx: Tx, organisationId: string, id: string, from: string, to: string): Promise<number> {
    const result = await tx.deviceKeyRotationRequest.updateMany({ where: { id, organisationId, state: from }, data: { state: to } });
    return result.count;
  }

  async createRotationChallenge(
    tx: Tx,
    input: {
      organisationId: string;
      deviceId: string;
      rotationRequestId: string;
      rotationRequestFingerprint: string;
      currentKeyId: string;
      currentKeyVersion: number;
      proposedKeyId: string;
      proposedKeyVersion: number;
      newPublicKeyThumbprint: string;
      nonce: string;
      issuedAt: Date;
      expiresAt: Date;
    },
  ): Promise<RotationChallengeRow> {
    return tx.deviceKeyRotationChallenge.create({ data: input });
  }

  async findRotationChallenge(organisationId: string, id: string): Promise<RotationChallengeRow | null> {
    return this.prisma.deviceKeyRotationChallenge.findFirst({ where: { id, organisationId } });
  }

  async lockRotationChallenge(tx: Tx, organisationId: string, id: string): Promise<RotationChallengeRow | null> {
    const rows = await tx.$queryRaw<RotationChallengeRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", device_id AS "deviceId",
             rotation_request_id AS "rotationRequestId",
             rotation_request_fingerprint AS "rotationRequestFingerprint",
             current_key_id AS "currentKeyId", current_key_version AS "currentKeyVersion",
             proposed_key_id AS "proposedKeyId", proposed_key_version AS "proposedKeyVersion",
             new_public_key_thumbprint AS "newPublicKeyThumbprint",
             nonce, issued_at AS "issuedAt", expires_at AS "expiresAt"
      FROM device_key_rotation_challenges
      WHERE id = ${id}::uuid AND organisation_id = ${organisationId}
      FOR UPDATE`);
    return first(rows);
  }

  async createRotationVerification(
    tx: Tx,
    input: {
      organisationId: string;
      deviceId: string;
      rotationRequestId: string;
      rotationRequestFingerprint: string;
      rotationChallengeId: string;
      currentKeyId: string;
      currentKeyVersion: number;
      proposedKeyId: string;
      proposedKeyVersion: number;
      newPublicKeyThumbprint: string;
      signatureProfile: string;
      canonicalStatementFingerprint: string;
      verified: boolean;
      verifiedAt: Date;
    },
  ): Promise<RotationVerificationRow> {
    return tx.deviceKeyRotationVerification.create({ data: input });
  }

  async lockRotationVerification(tx: Tx, organisationId: string, rotationChallengeId: string): Promise<RotationVerificationRow | null> {
    const rows = await tx.$queryRaw<RotationVerificationRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", device_id AS "deviceId",
             rotation_request_id AS "rotationRequestId",
             rotation_request_fingerprint AS "rotationRequestFingerprint",
             rotation_challenge_id AS "rotationChallengeId",
             current_key_id AS "currentKeyId", current_key_version AS "currentKeyVersion",
             proposed_key_id AS "proposedKeyId", proposed_key_version AS "proposedKeyVersion",
             new_public_key_thumbprint AS "newPublicKeyThumbprint",
             signature_profile AS "signatureProfile",
             canonical_statement_fingerprint AS "canonicalStatementFingerprint",
             verified, verified_at AS "verifiedAt"
      FROM device_key_rotation_verifications
      WHERE organisation_id = ${organisationId} AND rotation_challenge_id = ${rotationChallengeId}::uuid
      FOR UPDATE`);
    return first(rows);
  }

  // -------------------------------------------------------------------------
  // APPEND-ONLY HISTORY (D24-12)
  //
  // Three writers, three `create` calls, and no other verb. There is no
  // `update`, `delete`, `upsert`, `updateMany` or `deleteMany` against
  // DeviceTrustTransition, DeviceAttestationObservation or DeviceSecurityEvent
  // in this file or anywhere else in the module, and a source guard asserts it.
  // -------------------------------------------------------------------------

  /**
   * D24-08: EVERY trust change writes one of these, without exception —
   * including the first record of a device's life.
   *
   * Organisation, device, previous trust, new trust, reason, server evidence
   * references, the authorised human where one is involved, the instant and
   * the trace id. A trust change with no transition row is a change nobody can
   * audit, which is the same as a change that should not have been allowed.
   */
  async appendTrustTransition(
    tx: Tx,
    input: {
      organisationId: string;
      deviceId: string;
      previousTrust: string;
      newTrust: string;
      reason: string;
      evidenceRefs: string[];
      authorisedByUserId: string | null;
      occurredAt: Date;
      traceId: string;
    },
  ): Promise<void> {
    await tx.deviceTrustTransition.create({ data: input });
  }

  /**
   * D24-07: every attestation observation is persisted, append-only, whatever
   * it said.
   *
   * UNAVAILABLE rows are kept as deliberately as VERIFIED ones: an outage that
   * left no trace would make "we could not check" indistinguishable from "we
   * never looked", and C14-05's whole distinction rests on being able to tell
   * those apart afterwards.
   */
  async appendAttestationObservation(
    tx: Tx,
    input: {
      organisationId: string;
      deviceId: string | null;
      enrollmentRequestId: string | null;
      outcome: string;
      attestationReference: string | null;
      evaluatedAt: Date;
      observedAt: Date;
      traceId: string;
    },
  ): Promise<{ id: string }> {
    const row = await tx.deviceAttestationObservation.create({ data: input, select: { id: true } });
    return row;
  }

  /**
   * C16-05: THE NEWEST OBSERVATION THAT IS NOT `UNAVAILABLE` — the DECISIVE one.
   *
   * This replaces "the newest VERIFIED observation", which was the second half
   * of C16-05's defect. Asking for the newest VERIFIED result INDEPENDENTLY of
   * the newest result meant the history
   *
   *     VERIFIED (t0) -> NEGATIVE (t1) -> UNAVAILABLE (t2)
   *
   * answered "outcome UNAVAILABLE, last verified t0", i.e. LAST_KNOWN_GOOD:
   * a provider outage RESURRECTED a positive result the device had already
   * lost, and the negative evidence in between simply vanished.
   *
   * Asking instead for the newest NON-outage observation makes that
   * impossible. If a VERIFIED result existed after the negative one, IT would
   * be this row. `UNAVAILABLE` is excluded because it is an absence of
   * evidence (C14-05) and can neither create nor destroy a standing.
   *
   * A device with no row here has never been looked at with a conclusive
   * result, and cannot become TRUSTED during an outage. The absence is
   * load-bearing, not a missing optimisation.
   */
  async latestDecisiveAttestation(
    tx: Tx,
    organisationId: string,
    deviceId: string,
  ): Promise<{ outcome: string; evaluatedAt: Date } | null> {
    return tx.deviceAttestationObservation.findFirst({
      where: { organisationId, deviceId, outcome: { not: 'UNAVAILABLE' } },
      orderBy: [{ evaluatedAt: 'desc' }, { id: 'desc' }],
      select: { outcome: true, evaluatedAt: true },
    });
  }

  /**
   * The most recent observation of ANY outcome, which is what
   * `evaluateAttestationStanding` takes as its `outcome` input.
   *
   * A device with no row here has never been looked at, and the caller treats
   * that as `UNAVAILABLE` — "we have no evidence" — rather than as a negative.
   * C14-05's asymmetry is the reason: an absence of evidence is not evidence.
   */
  async latestAttestationObservation(
    tx: Tx,
    organisationId: string,
    deviceId: string,
  ): Promise<{ outcome: string; evaluatedAt: Date } | null> {
    // C16-05: read through the CALLER'S TRANSACTION, not through `this.prisma`.
    // The row this decision is about is usually one the same transaction has
    // just appended, and a client outside the transaction cannot see it — so an
    // uncommitted NEGATIVE observation would have been judged against a history
    // that did not yet contain it.
    return tx.deviceAttestationObservation.findFirst({
      where: { organisationId, deviceId },
      orderBy: [{ evaluatedAt: 'desc' }, { id: 'desc' }],
      select: { outcome: true, evaluatedAt: true },
    });
  }

  /**
   * C16-R5: the two attestation reads AND the authoritative server instant,
   * taken together for a caller that is not already inside a transaction.
   *
   * The READ side needs the same resolution the write side performs, and the
   * one thing it must not do is take the instant from this process's clock:
   * every other timing rule in this module is judged against
   * `clock_timestamp()` (see `dbNow`), and a standing that aged against the
   * Node clock would age against a different clock from the one that recorded
   * the evidence. So the instant comes from the database, in the same
   * transaction as the reads.
   *
   * No lock is taken. This is a READ answering "what is true now", not a
   * decision about to raise trust — `lockLatestAttestationObservation` is the
   * locking variant and exists for that case. It also does not WRITE: see
   * `DeviceRegistryService.effectiveDeviceStanding` for why a read that notices
   * expiry does not mutate the device row.
   */
  async readAttestationEvidence(
    organisationId: string,
    deviceId: string,
    tx?: Tx,
  ): Promise<{
    latest: { outcome: string; evaluatedAt: Date } | null;
    decisive: { outcome: string; evaluatedAt: Date } | null;
    now: Date;
  }> {
    // WP-25/D25-16: the same internal composition seam the two finders carry.
    // Opening a NESTED transaction from inside the gateway's final effect
    // transaction would read the evidence on a second connection, outside the
    // very snapshot and the very locks the D25-04A fence rests on — so when a
    // transaction is supplied the reads join it instead of starting their own.
    const read = async (db: Tx): Promise<{
      latest: { outcome: string; evaluatedAt: Date } | null;
      decisive: { outcome: string; evaluatedAt: Date } | null;
      now: Date;
    }> => {
      const now = await this.dbNow(db);
      const latest = await this.latestAttestationObservation(db, organisationId, deviceId);
      const decisive = await this.latestDecisiveAttestation(db, organisationId, deviceId);
      return { latest, decisive, now };
    };
    return tx ? read(tx) : this.transaction(read);
  }

  /**
   * C16-05: the same two attestation reads, taken UNDER LOCK inside a
   * transaction that is about to raise a device's trust.
   *
   * WHY AN UPWARD TRANSITION NEEDS THIS AND A DOWNWARD ONE DOES NOT
   * --------------------------------------------------------------
   * Lowering trust on stale evidence is safe: the worst case is that a device
   * is degraded slightly sooner than it had to be. RAISING trust on stale
   * evidence is the whole problem — a key revoked between the pre-read and the
   * commit, or a negative attestation recorded in the gap, would otherwise be
   * invisible to the decision that restores TRUSTED.
   *
   * `FOR SHARE` and not `FOR UPDATE`, deliberately. These rows are append-only
   * history (D24-12) and this transaction has no intention of writing them; a
   * share lock is exactly the claim being made — "this evidence must not change
   * or disappear underneath the conclusion I am drawing from it" — and it does
   * not block a concurrent reader drawing the same conclusion.
   *
   * WHAT IT HONESTLY DOES NOT PREVENT: a NEW observation being appended after
   * these reads. Nothing short of serialising the table would, and that is why
   * the device row and the key row are locked `FOR UPDATE` in the same
   * transaction — the two facts that can WITHDRAW a credential are held still,
   * and new evidence arriving a millisecond later is simply the next decision.
   */
  async lockLatestAttestationObservation(
    tx: Tx,
    organisationId: string,
    deviceId: string,
  ): Promise<{ outcome: string; evaluatedAt: Date } | null> {
    const rows = await tx.$queryRaw<Array<{ outcome: string; evaluatedAt: Date }>>(Prisma.sql`
      SELECT outcome, evaluated_at AS "evaluatedAt"
      FROM device_attestation_observations
      WHERE organisation_id = ${organisationId} AND device_id = ${deviceId}::uuid
      ORDER BY evaluated_at DESC, id DESC
      LIMIT 1
      FOR SHARE`);
    return first(rows);
  }

  /** C16-05: the newest NON-`UNAVAILABLE` observation, under the same share lock. */
  async lockLatestDecisiveAttestation(
    tx: Tx,
    organisationId: string,
    deviceId: string,
  ): Promise<{ outcome: string; evaluatedAt: Date } | null> {
    const rows = await tx.$queryRaw<Array<{ outcome: string; evaluatedAt: Date }>>(Prisma.sql`
      SELECT outcome, evaluated_at AS "evaluatedAt"
      FROM device_attestation_observations
      WHERE organisation_id = ${organisationId} AND device_id = ${deviceId}::uuid
        AND outcome <> 'UNAVAILABLE'
      ORDER BY evaluated_at DESC, id DESC
      LIMIT 1
      FOR SHARE`);
    return first(rows);
  }

  /**
   * D24-08: has this device EVER held TRUSTED?
   *
   * `evaluateDeviceTrustTransition` needs `previouslyEligible` for the
   * `OFFLINE -> TRUSTED` reconnect, and this is the only honest source for it:
   * the append-only transition history. A blind reconnect — a device
   * reappearing with nothing established — has no such row and refuses.
   */
  async hasHeldTrusted(organisationId: string, deviceId: string): Promise<boolean> {
    const row = await this.prisma.deviceTrustTransition.findFirst({
      where: { organisationId, deviceId, newTrust: 'TRUSTED' },
      select: { id: true },
    });
    return row !== null;
  }

  /** Read side for the audit trail. There is no corresponding write-back. */
  async listSecurityEvents(organisationId: string, deviceId: string | null): Promise<
    Array<{ id: string; eventType: string; payload: Prisma.JsonValue; occurredAt: Date; actorUserId: string | null }>
  > {
    return this.prisma.deviceSecurityEvent.findMany({
      where: deviceId === null ? { organisationId } : { organisationId, deviceId },
      orderBy: [{ occurredAt: 'asc' }, { id: 'asc' }],
      select: { id: true, eventType: true, payload: true, occurredAt: true, actorUserId: true },
    });
  }

  /** Read side for the trust history. There is no corresponding write-back. */
  async listTrustTransitions(
    organisationId: string,
    deviceId: string,
  ): Promise<Array<{ id: string; previousTrust: string; newTrust: string; reason: string; occurredAt: Date }>> {
    return this.prisma.deviceTrustTransition.findMany({
      where: { organisationId, deviceId },
      orderBy: [{ occurredAt: 'asc' }, { id: 'asc' }],
      select: { id: true, previousTrust: true, newTrust: true, reason: true, occurredAt: true },
    });
  }

  /** Read side for attestation history. There is no corresponding write-back. */
  async listAttestationObservations(
    organisationId: string,
    deviceId: string,
  ): Promise<Array<{ id: string; outcome: string; evaluatedAt: Date }>> {
    return this.prisma.deviceAttestationObservation.findMany({
      where: { organisationId, deviceId },
      orderBy: [{ evaluatedAt: 'asc' }, { id: 'asc' }],
      select: { id: true, outcome: true, evaluatedAt: true },
    });
  }

  /**
   * D24-04a defence-in-depth probe, used only by the integration suite's
   * tenant-integrity assertions: does the database itself hold the composite
   * `(id, organisation_id)` pairing this module's foreign keys depend on?
   */
  async compositePairingExists(table: 'sites' | 'users', id: string, organisationId: string): Promise<boolean> {
    const sql =
      table === 'sites'
        ? Prisma.sql`SELECT EXISTS (SELECT 1 FROM sites WHERE id = ${id} AND organisation_id = ${organisationId}) AS present`
        : Prisma.sql`SELECT EXISTS (SELECT 1 FROM users WHERE id = ${id} AND organisation_id = ${organisationId}) AS present`;
    const rows = await this.prisma.$queryRaw<ExistsRow[]>(sql);
    const row = first(rows);
    return row !== null && row.present;
  }
}
