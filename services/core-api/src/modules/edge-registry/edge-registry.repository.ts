import { Inject, Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';

export type EdgeTx = Prisma.TransactionClient;

/**
 * WP-29B — the Edge registry's only door to the database.
 *
 * It holds no rules. Every judgement lives in `edge-enrolment.service.ts` or,
 * better, in the frozen contracts; this file exists so that a reader can see
 * the complete set of statements this module can execute in one place, and so
 * the service is testable against a transaction rather than against Prisma.
 *
 * `dbNow` is the SERVER's clock and there is no other. Nothing in the Edge
 * ceremony ever reads `Date.now()`: an enrolment window judged on the process's
 * wall clock would drift between replicas, and the whole WP-29B argument is
 * about not trusting clocks nobody owns.
 */
@Injectable()
export class EdgeRegistryRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  async transaction<T>(fn: (tx: EdgeTx) => Promise<T>): Promise<T> {
    return this.prisma.$transaction(fn);
  }

  /** The database's clock, inside the caller's transaction when one is given. */
  async dbNow(tx?: EdgeTx): Promise<Date> {
    const client = tx ?? this.prisma;
    const rows = await client.$queryRaw<Array<{ now: Date }>>(Prisma.sql`SELECT clock_timestamp() AS now`);
    const row = rows[0];
    if (row === undefined) throw new Error('the database did not answer with a clock reading');
    return row.now;
  }

  /**
   * Proven before a write so a cross-tenant pairing answers with a refusal
   * rather than surfacing the composite foreign key as a driver fault. The
   * database constraint remains the real defence (D24-04a); this is the safe,
   * non-leaking way to report it.
   */
  async siteExistsInOrganisation(organisationId: string, siteId: string, tx?: EdgeTx): Promise<boolean> {
    const client = tx ?? this.prisma;
    return (await client.site.count({ where: { id: siteId, organisationId } })) === 1;
  }

  async organisationExists(organisationId: string, tx?: EdgeTx): Promise<boolean> {
    const client = tx ?? this.prisma;
    return (await client.organisation.count({ where: { id: organisationId } })) === 1;
  }

  // -------------------------------------------------------------------------
  // Enrolment authority
  // -------------------------------------------------------------------------

  async createEnrolmentAuthority(
    tx: EdgeTx,
    input: {
      organisationId: string;
      siteId: string;
      issuedByUserId: string;
      secretDigest: string;
      issuedAt: Date;
      expiresAt: Date;
    },
  ): Promise<{ id: string }> {
    return tx.edgeEnrolmentAuthority.create({ data: input, select: { id: true } });
  }

  /**
   * Resolution is BY DIGEST, within one tenant. The raw secret is never
   * compared against anything at rest because the raw secret is not at rest.
   */
  async findAuthorityByDigest(organisationId: string, secretDigest: string, tx?: EdgeTx) {
    const client = tx ?? this.prisma;
    return client.edgeEnrolmentAuthority.findUnique({ where: { organisationId_secretDigest: { organisationId, secretDigest } } });
  }

  /** Plain read by id, for the authorisation check that precedes a revocation. */
  async findAuthorityByIdForRead(organisationId: string, authorityId: string) {
    const row = await this.prisma.edgeEnrolmentAuthority.findUnique({ where: { id: authorityId } });
    return row === null || row.organisationId !== organisationId ? null : row;
  }

  /**
   * Re-read the authority UNDER LOCK. `FOR UPDATE` is the difference between a
   * single-use authority and one two concurrent ceremonies can both spend: the
   * classification below it must see a row nobody else is mid-way through
   * burning.
   */
  async lockAuthority(tx: EdgeTx, organisationId: string, authorityId: string) {
    const rows = await tx.$queryRaw<Array<{ id: string }>>(Prisma.sql`
      SELECT id FROM edge_enrolment_authorities
      WHERE organisation_id = ${organisationId} AND id = ${authorityId}::uuid
      FOR UPDATE`);
    if (rows.length === 0) return null;
    return tx.edgeEnrolmentAuthority.findUnique({ where: { id: authorityId } });
  }

  async markAuthorityConsumed(tx: EdgeTx, authorityId: string, consumedAt: Date): Promise<number> {
    // FENCED: the count is the concurrency signal. Only a row that has not
    // already been consumed is updated, so a second burn changes nothing and
    // the caller can tell.
    const result = await tx.edgeEnrolmentAuthority.updateMany({
      where: { id: authorityId, consumedAt: null },
      data: { consumedAt },
    });
    return result.count;
  }

  async revokeAuthority(tx: EdgeTx, organisationId: string, authorityId: string, revokedAt: Date): Promise<number> {
    const result = await tx.edgeEnrolmentAuthority.updateMany({
      where: { id: authorityId, organisationId, revokedAt: null, consumedAt: null },
      data: { revokedAt },
    });
    return result.count;
  }

  // -------------------------------------------------------------------------
  // The pending Edge and its request
  // -------------------------------------------------------------------------

  async createPendingEdge(
    tx: EdgeTx,
    input: { id: string; organisationId: string; siteId: string; enrolledByUserId: string; enrolmentState: string; edgeTrust: string },
  ): Promise<void> {
    await tx.edgeNode.create({ data: input });
  }

  async createEnrolmentRequest(
    tx: EdgeTx,
    input: {
      id: string;
      organisationId: string;
      siteId: string;
      authorityId: string;
      edgeId: string;
      offeredPublicKey: string;
      offeredPublicKeyThumbprint: string;
      signatureProfile: string;
      state: string;
      requestFingerprint: string;
    },
  ): Promise<void> {
    await tx.edgeEnrolmentRequest.create({ data: input });
  }

  async findEnrolmentRequest(organisationId: string, enrolmentRequestId: string, tx?: EdgeTx) {
    const client = tx ?? this.prisma;
    const row = await client.edgeEnrolmentRequest.findUnique({ where: { id: enrolmentRequestId } });
    return row === null || row.organisationId !== organisationId ? null : row;
  }

  async lockEnrolmentRequest(tx: EdgeTx, organisationId: string, enrolmentRequestId: string) {
    const rows = await tx.$queryRaw<Array<{ id: string }>>(Prisma.sql`
      SELECT id FROM edge_enrolment_requests
      WHERE organisation_id = ${organisationId} AND id = ${enrolmentRequestId}::uuid
      FOR UPDATE`);
    if (rows.length === 0) return null;
    return tx.edgeEnrolmentRequest.findUnique({ where: { id: enrolmentRequestId } });
  }

  async advanceRequestState(tx: EdgeTx, organisationId: string, requestId: string, from: string, to: string): Promise<number> {
    // FENCED, like Shield's `advanceEnrollmentState`: the count is the
    // concurrency signal, so two racing activations cannot both believe they
    // moved the request.
    const result = await tx.edgeEnrolmentRequest.updateMany({
      where: { id: requestId, organisationId, state: from },
      data: { state: to },
    });
    return result.count;
  }

  // -------------------------------------------------------------------------
  // Possession
  // -------------------------------------------------------------------------

  async createPossessionChallenge(
    tx: EdgeTx,
    input: { organisationId: string; enrolmentRequestId: string; nonce: string; issuedAt: Date; expiresAt: Date },
  ): Promise<{ id: string }> {
    return tx.edgePossessionChallenge.create({ data: input, select: { id: true } });
  }

  async findChallenge(organisationId: string, challengeId: string, tx?: EdgeTx) {
    const client = tx ?? this.prisma;
    const row = await client.edgePossessionChallenge.findUnique({ where: { id: challengeId } });
    return row === null || row.organisationId !== organisationId ? null : row;
  }

  /**
   * The verdict already recorded against this challenge, or `null`.
   *
   * ONE VERDICT PER CHALLENGE is a database constraint
   * (`edge_possession_verification_challenge_key`), so a retry must READ the
   * existing answer rather than write a second — a challenge that could
   * accumulate verdicts is a challenge that can be answered until one of the
   * answers is `true`.
   */
  async findVerificationByChallenge(organisationId: string, challengeId: string, tx: EdgeTx) {
    return tx.edgePossessionVerification.findUnique({
      where: { organisationId_challengeId: { organisationId, challengeId } },
    });
  }

  async recordPossessionVerification(
    tx: EdgeTx,
    input: {
      organisationId: string;
      challengeId: string;
      enrolmentRequestId: string;
      enrolmentRequestFingerprint: string;
      publicKeyThumbprint: string;
      possessionStatementFingerprint: string;
      signatureProfile: string;
      verified: boolean;
      verifiedAt: Date;
    },
  ): Promise<void> {
    await tx.edgePossessionVerification.create({ data: input });
  }

  // -------------------------------------------------------------------------
  // The registry
  // -------------------------------------------------------------------------

  async createRegistryKey(
    tx: EdgeTx,
    input: {
      organisationId: string;
      edgeId: string;
      enrolmentRequestId: string;
      edgeKeyId: string;
      edgeKeyVersion: number;
      publicKey: string;
      publicKeyThumbprint: string;
      signatureProfile: string;
      status: string;
      registeredAt: Date;
      activatedAt: Date;
    },
  ): Promise<void> {
    await tx.edgeRegistryKey.create({ data: input });
  }

  async activateEdge(tx: EdgeTx, organisationId: string, edgeId: string, activatedAt: Date, state: string, trust: string): Promise<number> {
    const result = await tx.edgeNode.updateMany({
      where: { id: edgeId, organisationId, enrolmentState: 'PENDING' },
      data: { enrolmentState: state, edgeTrust: trust, activatedAt },
    });
    return result.count;
  }

  async findEdge(organisationId: string, edgeId: string, tx?: EdgeTx) {
    const client = tx ?? this.prisma;
    const row = await client.edgeNode.findUnique({ where: { id: edgeId } });
    return row === null || row.organisationId !== organisationId ? null : row;
  }

  async lockEdge(tx: EdgeTx, organisationId: string, edgeId: string) {
    const rows = await tx.$queryRaw<Array<{ id: string }>>(Prisma.sql`
      SELECT id FROM edges WHERE organisation_id = ${organisationId} AND id = ${edgeId}::uuid FOR UPDATE`);
    if (rows.length === 0) return null;
    return tx.edgeNode.findUnique({ where: { id: edgeId } });
  }

  /** The lookup a receipt performs: `edge_key_id` resolves to exactly one key in a tenant. */
  async findRegistryKeyByKeyId(organisationId: string, edgeKeyId: string, tx?: EdgeTx) {
    const client = tx ?? this.prisma;
    return client.edgeRegistryKey.findUnique({ where: { organisationId_edgeKeyId: { organisationId, edgeKeyId } } });
  }

  /**
   * WP-29B EDGE-B — THE LOOKUP AN AUTHENTICATING EDGE PERFORMS, AND THE ONLY
   * QUERY IN THIS FILE WITH NO TENANT ON THE LEFT-HAND SIDE.
   *
   * A device request resolves its context under the SESSION's tenant (C17-02).
   * An Edge has no session, so there is no server-established tenant to resolve
   * under — and a tenant taken from the request would be exactly the defect
   * C17-02 corrected, arriving through a different door. The tenant is
   * therefore an OUTPUT of this lookup, derived from the row, and the caller
   * must not have been able to influence which row that is.
   *
   * `edge_registry_key_id_key` is unique per TENANT, not globally, so this
   * query cannot assume uniqueness — it asks for two rows and refuses unless
   * exactly one came back. `edge_key_id` is a server-minted `randomUUID`, so
   * two tenants sharing one is not a situation that arises; if it ever did, the
   * honest answer is "this names no key" rather than a coin toss between two
   * tenants' credentials. It fails CLOSED, and it takes no second opinion.
   */
  async findRegistryKeyByKeyIdAcrossTenants(edgeKeyId: string, tx?: EdgeTx) {
    const client = tx ?? this.prisma;
    const rows = await client.edgeRegistryKey.findMany({ where: { edgeKeyId }, take: 2 });
    return rows.length === 1 ? (rows[0] ?? null) : null;
  }

  async findCurrentRegistryKey(organisationId: string, edgeId: string, tx?: EdgeTx) {
    const client = tx ?? this.prisma;
    // RELIES on the partial unique index `edge_registry_keys_one_current_key`
    // rather than letting `findFirst` pick a winner out of a set the database
    // has already made a singleton.
    return client.edgeRegistryKey.findFirst({ where: { organisationId, edgeId, status: 'CURRENT' } });
  }

  async withdrawEdge(
    tx: EdgeTx,
    input: { organisationId: string; edgeId: string; withdrawnAt: Date; state: string; trust: string },
  ): Promise<number> {
    const result = await tx.edgeNode.updateMany({
      where: { id: input.edgeId, organisationId: input.organisationId, enrolmentState: { not: input.state } },
      data: { enrolmentState: input.state, edgeTrust: input.trust, withdrawnAt: input.withdrawnAt },
    });
    return result.count;
  }

  /**
   * Withdrawal REVOKES the key; it never deletes it. `deviceKeyStatePermitsHistoricalVerification`
   * still admits the record for checking receipts this key legitimately signed,
   * and the frozen evaluator refuses new work on the revocation instant alone.
   */
  async revokeRegistryKeys(tx: EdgeTx, organisationId: string, edgeId: string, revokedAt: Date): Promise<number> {
    const result = await tx.edgeRegistryKey.updateMany({
      where: { organisationId, edgeId, revokedAt: null },
      data: { status: 'REVOKED', revokedAt },
    });
    return result.count;
  }

  // -------------------------------------------------------------------------
  // Audit
  // -------------------------------------------------------------------------

  async appendSecurityEvent(
    tx: EdgeTx,
    input: {
      organisationId: string;
      edgeId: string | null;
      siteId: string | null;
      eventType: string;
      actorUserId: string | null;
      edgeKeyId: string | null;
      edgeKeyVersion: number | null;
      outcome: string | null;
      refusalCode: string | null;
      payload: Prisma.InputJsonValue;
      occurredAt: Date;
      traceId: string;
    },
  ): Promise<void> {
    await tx.edgeSecurityEvent.create({ data: input });
  }

  /**
   * WP-29B EDGE-B — the same audit row, for a decision that has no transaction
   * to join.
   *
   * An authentication refusal commits nothing, so there is no effect for the
   * event to be atomic with; writing it inside a transaction opened purely to
   * hold it would be ceremony, and worse, a transaction that rolled back would
   * ERASE the record of a refused request — which is the one record an
   * investigation needs. It mirrors `appendOperationEventOutsideTransaction` on
   * the device gateway for exactly that reason.
   *
   * IT STILL REQUIRES A TENANT, and the caller must have ESTABLISHED that
   * tenant from server state. There is deliberately no nullable-organisation
   * overload: a refusal taken before any registry row resolved has no tenant at
   * all, and filing it under an invented one would corrupt every tenant-scoped
   * audit query in the estate. Those refusals are logged and not filed — see
   * `EdgeAuthenticationService`.
   */
  async appendSecurityEventOutsideTransaction(input: {
    organisationId: string;
    edgeId: string | null;
    siteId: string | null;
    eventType: string;
    actorUserId: string | null;
    edgeKeyId: string | null;
    edgeKeyVersion: number | null;
    outcome: string | null;
    refusalCode: string | null;
    payload: Prisma.InputJsonValue;
    occurredAt: Date;
    traceId: string;
  }): Promise<void> {
    await this.prisma.edgeSecurityEvent.create({ data: input });
  }
}

/** Prisma's unique-violation code, for the paths that treat a collision as a convergence signal. */
export function isUniqueConstraintViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}
