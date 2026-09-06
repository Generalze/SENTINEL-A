import { Inject, Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { DEVICE_GATEWAY_EVENT_OUTCOME, buildDeviceGatewayEventPayload, type DeviceGatewayEventEnvelope, type DeviceGatewayEventInput } from './device-gateway.audit';

/**
 * WP-25 device gateway persistence primitives.
 *
 * THIS REPOSITORY HOLDS NO SECURITY POLICY. Every rule the gateway enforces
 * already exists as a frozen evaluator in `packages/contracts/src/device-*.ts`
 * and the services call those evaluators; what lives here is the storage the
 * decisions need, each carrying exactly the concurrency guarantee D25-02
 * requires and nothing more. It is `shield.repository.ts`'s discipline, and the
 * same sentence applies: a row read without a lock can have moved by the time
 * the decision it fed is committed, and "the context was open when I looked" is
 * not a fact a commit may rest on.
 *
 * WHY THE LOCK READS ARE RAW SQL. Prisma's query API cannot express
 * `SELECT ... FOR UPDATE`. The lock reads below are `$queryRaw` with explicit
 * column aliases, exactly as Shield's, Field's and Patrol's are.
 *
 * `DeviceGatewayOperationEvent` IS APPEND-ONLY, AND THAT IS A PROPERTY OF THIS
 * FILE RATHER THAN A PROMISE ABOUT IT (D25-13)
 * ------------------------------------------------------------------------
 * The model is reachable through exactly one writer, `appendOperationEvent`,
 * and that writer calls `create`. There is no update, no delete, no upsert, no
 * `updateMany`, no `deleteMany` and no raw mutating statement against it
 * anywhere in this module. `test/device-gateway-boundary.architecture.spec.ts`
 * asserts that as a SOURCE SCAN, for the reason the Shield and Whisper guards
 * give: a property protected by review is a property protected until the first
 * busy week.
 *
 * WHAT THIS REPOSITORY DELIBERATELY DOES NOT TOUCH
 * ------------------------------------------------
 * No Field table. No Field Messaging table. No Shield table. The gateway
 * orchestrates domain SERVICES (D25-16) and reads Shield through
 * `ShieldRepository` and `DeviceRegistryService`; it writes exactly the four
 * tables `device-gateway.prisma` defines and no others. The two reads below
 * that are not gateway tables — the actor's user row and the organisation's
 * site roster — are IDENTITY reads, the same rows the global DevAuthGuard
 * resolves a principal from, and they are reads.
 */

export type GatewayTx = Prisma.TransactionClient;

export interface EstablishmentChallengeRow {
  id: string;
  organisationId: string;
  proposedContextId: string;
  actorUserId: string;
  deviceId: string;
  siteId: string;
  keyId: string;
  keyVersion: number;
  nonce: string;
  issuedAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
}

export interface IssuedContextRow {
  id: string;
  organisationId: string;
  actorUserId: string;
  deviceId: string;
  keyId: string;
  keyVersion: number;
  issuedAt: Date;
  expiresAt: Date;
  closedAt: Date | null;
  closeReason: string | null;
  establishmentId: string;
}

export interface ActorAuthorityRow {
  userId: string;
  organisationId: string;
  clearance: number;
  roles: ReadonlyArray<{ role: string; siteId: string | null }>;
}

function first<T>(rows: T[]): T | null {
  return rows.length === 0 ? null : (rows[0] as T);
}

@Injectable()
export class DeviceGatewayRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  /**
   * The ONE final effect transaction of D25-02.
   *
   * The timeout is raised above Prisma's 5-second default deliberately: this
   * transaction takes five lock reads, re-runs two frozen evaluators, claims a
   * replay identity and then calls a domain service that does its own locked
   * read-check-write. A transaction that times out mid-flight rolls back, which
   * is safe — but a gateway that intermittently rolls back sound requests under
   * ordinary load is a gateway whose refusals stop meaning anything.
   */
  async transaction<T>(work: (tx: GatewayTx) => Promise<T>): Promise<T> {
    return this.prisma.$transaction(work, { timeout: 20_000, maxWait: 10_000 });
  }

  /**
   * The authoritative server clock — `clock_timestamp()`, never `now()`.
   *
   * The WP-19/C9-06 precedent Shield restates: Postgres pins `now()` to
   * transaction START, which is BEFORE the row locks a commit takes. Every
   * timing rule the gateway applies — the context ceiling, the establishment
   * ceiling, the frozen proof freshness — is judged against this value, so an
   * instant taken before the serialization boundary would be judging the wrong
   * moment.
   */
  async dbNow(tx: GatewayTx): Promise<Date> {
    const rows = await tx.$queryRaw<Array<{ now: Date }>>(Prisma.sql`SELECT clock_timestamp() AS now`);
    const row = first(rows);
    if (row === null) throw new Error('clock_timestamp returned no row');
    return row.now;
  }

  /** The same clock outside a transaction, for the preflight that commits nothing. */
  async now(): Promise<Date> {
    const rows = await this.prisma.$queryRaw<Array<{ now: Date }>>(Prisma.sql`SELECT clock_timestamp() AS now`);
    const row = first(rows);
    if (row === null) throw new Error('clock_timestamp returned no row');
    return row.now;
  }

  /** A read-only transaction, so the preflight replay PEEK observes one snapshot. */
  async readOnly<T>(work: (tx: GatewayTx) => Promise<T>): Promise<T> {
    return this.prisma.$transaction(work);
  }

  // -------------------------------------------------------------------------
  // Establishment ceremony state
  // -------------------------------------------------------------------------

  async createEstablishmentChallenge(input: {
    organisationId: string;
    proposedContextId: string;
    actorUserId: string;
    deviceId: string;
    siteId: string;
    keyId: string;
    keyVersion: number;
    nonce: string;
    issuedAt: Date;
    expiresAt: Date;
  }): Promise<EstablishmentChallengeRow> {
    const row = await this.prisma.deviceContextEstablishmentChallenge.create({ data: input });
    return row;
  }

  async findEstablishmentChallenge(organisationId: string, id: string): Promise<EstablishmentChallengeRow | null> {
    if (!isUuid(id)) return null;
    return this.prisma.deviceContextEstablishmentChallenge.findFirst({ where: { id, organisationId } });
  }

  /**
   * The challenge, LOCKED, so "one-shot" is decided against reality.
   *
   * Two concurrent completions of the same ceremony must not both observe
   * `consumed_at IS NULL`. The lock serialises them; the compare-and-set below
   * is what actually spends it, and the
   * `authenticated_device_context_establishment_key` unique index is the third
   * line — a duplicate commit CANNOT mint a second context off one ceremony
   * even if both of the first two were somehow bypassed.
   */
  async lockEstablishmentChallenge(tx: GatewayTx, organisationId: string, id: string): Promise<EstablishmentChallengeRow | null> {
    if (!isUuid(id)) return null;
    const rows = await tx.$queryRaw<EstablishmentChallengeRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", proposed_context_id AS "proposedContextId",
             actor_user_id AS "actorUserId", device_id AS "deviceId", site_id AS "siteId",
             key_id AS "keyId", key_version AS "keyVersion", nonce,
             issued_at AS "issuedAt", expires_at AS "expiresAt", consumed_at AS "consumedAt"
      FROM device_context_establishment_challenges
      WHERE id = ${id}::uuid AND organisation_id = ${organisationId}
      FOR UPDATE`);
    return first(rows);
  }

  /**
   * Spends the ceremony. Fenced on `consumed_at IS NULL`, so a second use
   * updates ZERO rows and the caller rolls the whole transaction back.
   *
   * It is never cleared: a spent ceremony does not become unspent.
   */
  async consumeEstablishmentChallenge(tx: GatewayTx, organisationId: string, id: string, at: Date): Promise<number> {
    const result = await tx.deviceContextEstablishmentChallenge.updateMany({
      where: { id, organisationId, consumedAt: null },
      data: { consumedAt: at },
    });
    return result.count;
  }

  // -------------------------------------------------------------------------
  // Issued contexts
  // -------------------------------------------------------------------------

  async createIssuedContext(
    tx: GatewayTx,
    input: {
      id: string;
      organisationId: string;
      actorUserId: string;
      deviceId: string;
      keyId: string;
      keyVersion: number;
      issuedAt: Date;
      expiresAt: Date;
      establishmentId: string;
      issuanceTraceId: string;
    },
  ): Promise<IssuedContextRow> {
    return tx.authenticatedDeviceContextRecord.create({ data: input });
  }

  /**
   * The site binding, as a CHILD ROW rather than a string array — see
   * `device-gateway.prisma`. The composite foreign key means a site that does
   * not exist, or a real site in another tenant, is not a bad row: it is an
   * impossible one.
   */
  async createContextSite(tx: GatewayTx, input: { contextId: string; organisationId: string; siteId: string }): Promise<void> {
    await tx.authenticatedDeviceContextSite.create({ data: input });
  }

  async findContext(organisationId: string, contextId: string): Promise<IssuedContextRow | null> {
    if (!isUuid(contextId)) return null;
    return this.prisma.authenticatedDeviceContextRecord.findFirst({ where: { id: contextId, organisationId } });
  }

  /**
   * The context, LOCKED, inside the final effect transaction.
   *
   * D25-04A: an open connection is not a grant, and neither is a context that
   * was open during preflight. Server-side invalidation lands on `closed_at`,
   * and this is where a close that happened between preflight and commit is
   * seen — held still for the duration of the decision it feeds.
   */
  async lockContext(tx: GatewayTx, organisationId: string, contextId: string): Promise<IssuedContextRow | null> {
    if (!isUuid(contextId)) return null;
    const rows = await tx.$queryRaw<IssuedContextRow[]>(Prisma.sql`
      SELECT id, organisation_id AS "organisationId", actor_user_id AS "actorUserId",
             device_id AS "deviceId", key_id AS "keyId", key_version AS "keyVersion",
             issued_at AS "issuedAt", expires_at AS "expiresAt",
             closed_at AS "closedAt", close_reason AS "closeReason",
             establishment_id AS "establishmentId"
      FROM authenticated_device_contexts
      WHERE id = ${contextId}::uuid AND organisation_id = ${organisationId}
      FOR UPDATE`);
    return first(rows);
  }

  async listContextSiteIds(db: GatewayTx, organisationId: string, contextId: string): Promise<string[]> {
    const rows = await db.authenticatedDeviceContextSite.findMany({
      where: { contextId, organisationId },
      select: { siteId: true },
      orderBy: { siteId: 'asc' },
    });
    return rows.map((row) => row.siteId);
  }

  /**
   * WP-25/C17-04 — the EXACT site binding the request depends on, LOCKED.
   *
   * `listContextSiteIds` above answers "which sites does this context cover?"
   * and joins the transaction, which makes it a consistent read. It does not
   * make it a HELD one: the row backing the answer is not locked, so a
   * concurrent writer could move the binding between the read and the commit.
   *
   * `authenticated_device_context_site_key` — UNIQUE (context_id, site_id) —
   * means the tuple below is at most one row, so this is a lock on the exact
   * fact the decision rests on rather than on a range.
   */
  async lockContextSiteBinding(tx: GatewayTx, organisationId: string, contextId: string, siteId: string): Promise<boolean> {
    if (!isUuid(contextId)) return false;
    const rows = await tx.$queryRaw<Array<{ id: string }>>(Prisma.sql`
      SELECT id
      FROM authenticated_device_context_sites
      WHERE context_id = ${contextId}::uuid AND organisation_id = ${organisationId} AND site_id = ${siteId}
      FOR UPDATE`);
    return rows.length === 1;
  }

  /** The unlocked variant, for the preflight that establishes nothing. */
  async listContextSiteIdsUnlocked(organisationId: string, contextId: string): Promise<string[]> {
    const rows = await this.prisma.authenticatedDeviceContextSite.findMany({
      where: { contextId, organisationId },
      select: { siteId: true },
      orderBy: { siteId: 'asc' },
    });
    return rows.map((row) => row.siteId);
  }

  /**
   * Server-side invalidation. Fenced on `closed_at IS NULL` so a close is
   * idempotent and a second close cannot rewrite the reason the first recorded.
   *
   * The context row is LIVE STATE, not history — closing one is the invalidation
   * D25-10 persists contexts in order to have, and it is the only update this
   * repository performs on any row.
   */
  async closeContext(organisationId: string, contextId: string, reason: string, at: Date): Promise<number> {
    const result = await this.prisma.authenticatedDeviceContextRecord.updateMany({
      where: { id: contextId, organisationId, closedAt: null },
      data: { closedAt: at, closeReason: reason },
    });
    return result.count;
  }

  // -------------------------------------------------------------------------
  // Identity reads — CURRENT actor authority, read now (C15-04)
  // -------------------------------------------------------------------------

  /**
   * The actor's CURRENT user row and role assignments.
   *
   * The context names an actor and a site list resolved AT ISSUANCE. Between
   * issuance and use that person can be suspended, moved off the site, or have
   * a capability withdrawn — so this is read on EVERY request, inside the final
   * transaction, and it is what the frozen evaluator judges against. The
   * context's own snapshot is never consulted for an authorisation answer.
   *
   * These are the same two tables the global DevAuthGuard resolves a principal
   * from. Reading them here is not a second identity model; it is the same read
   * taken by a caller that has no HTTP session to read it from.
   */
  async findActorAuthority(organisationId: string, userId: string, tx?: GatewayTx): Promise<ActorAuthorityRow | null> {
    const db: GatewayTx = tx ?? this.prisma;
    const user = await db.user.findFirst({
      where: { id: userId, organisationId },
      select: { id: true, organisationId: true, clearance: true, roles: { select: { role: true, siteId: true } } },
    });
    if (user === null) return null;
    return {
      userId: user.id,
      organisationId: user.organisationId,
      clearance: user.clearance,
      roles: user.roles.map((assignment) => ({ role: assignment.role, siteId: assignment.siteId })),
    };
  }

  /**
   * Every site in the tenant.
   *
   * Used only to expand an ORGANISATION-WIDE role assignment into the concrete
   * site list the frozen `DeviceActorAuthorityFacts.authorised_site_ids`
   * requires. The alternative — putting the requested site into the list
   * because the assignment is org-wide — would make the contract's
   * `authorised_site_ids.includes(proof.site_id)` check answer itself, which is
   * not a check at all.
   */
  async listOrganisationSiteIds(organisationId: string, tx?: GatewayTx): Promise<string[]> {
    const db: GatewayTx = tx ?? this.prisma;
    const rows = await db.site.findMany({ where: { organisationId }, select: { id: true }, orderBy: { id: 'asc' } });
    return rows.map((row) => row.id);
  }

  // -------------------------------------------------------------------------
  // The append-only gateway audit
  // -------------------------------------------------------------------------

  /**
   * ONE THING THE GATEWAY DID, appended.
   *
   * The only writer of `DeviceGatewayOperationEvent`, and its only verb is
   * `create`. The payload crossing the JSON boundary was built by the allowlist
   * in `device-gateway.audit.ts` and by nothing else, so no field reaches this
   * table that somebody did not write out by hand.
   *
   * It takes a `GatewayTx` rather than opening one: a COMMITTED event must land
   * in the same transaction as the effect it attests to, and a REFUSED event
   * must land in its OWN transaction AFTER the rollback — otherwise the trail
   * of a refusal would be rolled back along with the security state it is the
   * record of. Both callers exist, and which one applies is the caller's
   * decision, not this method's.
   */
  async appendOperationEvent(db: GatewayTx, envelope: DeviceGatewayEventEnvelope, input: DeviceGatewayEventInput): Promise<void> {
    await db.deviceGatewayOperationEvent.create({
      data: {
        organisationId: envelope.organisationId,
        contextId: envelope.contextId,
        deviceId: envelope.deviceId,
        actorUserId: envelope.actorUserId,
        operationKind: envelope.operationKind,
        eventType: input.type,
        outcome: DEVICE_GATEWAY_EVENT_OUTCOME[input.type],
        refusalReason: refusalReasonOf(input),
        payload: buildDeviceGatewayEventPayload(input) as Prisma.InputJsonObject,
        occurredAt: envelope.occurredAt,
        traceId: envelope.traceId,
      },
    });
  }

  /** A refusal event, written in its OWN transaction after the effect transaction rolled back. */
  async appendOperationEventOutsideTransaction(envelope: DeviceGatewayEventEnvelope, input: DeviceGatewayEventInput): Promise<void> {
    await this.appendOperationEvent(this.prisma, envelope, input);
  }

  // -------------------------------------------------------------------------
  // WP-29A — device policy leases (D29A-26)
  // -------------------------------------------------------------------------

  /**
   * D29A-26 §5 — THE CAPABILITY GRANT AN ISSUANCE RESTED ON.
   *
   * Returns the `user_roles` row id that covers `siteId` for this actor, or
   * `null` when none does. A SITE-SCOPED assignment is preferred over an
   * organisation-wide one, and ties break on the lowest id, so the recorded
   * basis is deterministic and is the NARROWEST assignment that could have
   * justified the lease — the most conservative thing we can truthfully say
   * about why authority was cached.
   *
   * It is deliberately a query of its own rather than a field added to
   * `findActorAuthority`. That method feeds the frozen
   * `DeviceActorAuthorityFacts`, which has no place for a role id and should
   * not grow one: what grants a capability is a policy question answered from
   * roles and actions together, while this is an AUDIT POINTER recorded beside
   * the answer. Conflating them would put an identifier into a security
   * evaluation that has no business reading it.
   *
   * The id is stored as a plain column with NO foreign key — see
   * `DevicePolicyLease` in `shield.prisma`. A `Restrict` relation to a live,
   * mutable role would make the database refuse to remove a user's role while
   * any lease named it, so withdrawing someone's authority could be blocked for
   * six hours by a queued acknowledgement. The lease must survive that change,
   * not prevent it.
   */
  async findAuthorityBasis(organisationId: string, userId: string, siteId: string): Promise<string | null> {
    const rows = await this.prisma.userRole.findMany({
      where: {
        userId,
        user: { organisationId },
        OR: [{ siteId }, { siteId: null }],
      },
      select: { id: true, siteId: true },
      orderBy: { id: 'asc' },
    });
    const siteScoped = rows.find((row) => row.siteId === siteId);
    if (siteScoped !== undefined) return siteScoped.id;
    return rows[0]?.id ?? null;
  }

  /**
   * Persists one issued lease.
   *
   * No upsert, and no `skipDuplicates`. A lease id is freshly generated per
   * issuance, so a collision is not a retry — it is a bug or a supplied id, and
   * either must fail loudly rather than silently returning somebody else's
   * authority record.
   */
  async createPolicyLease(input: {
    id: string;
    organisationId: string;
    deviceId: string;
    siteId: string;
    actorUserId: string;
    authorityBasisId: string;
    scope: string[];
    issuedAt: Date;
    expiresAt: Date;
  }): Promise<void> {
    await this.prisma.devicePolicyLease.create({ data: input });
  }

  /**
   * Resolves a lease by its identity WITHIN a tenant.
   *
   * Both halves of the key are in the `where`, so a foreign tenant's real lease
   * and an id that never existed return `null` from the same query. There is no
   * branch on which they could diverge, which is what stops this becoming an
   * enumeration oracle (D25-13).
   */
  async findPolicyLease(organisationId: string, leaseId: string, tx?: GatewayTx): Promise<DevicePolicyLeaseRow | null> {
    const db = tx ?? this.prisma;
    return db.devicePolicyLease.findFirst({ where: { id: leaseId, organisationId } });
  }

  /**
   * Marks a lease revoked, keeping the FIRST withdrawal instant.
   *
   * `revokedAt: null` in the filter is what makes this idempotent: a second
   * revocation matches no row and returns `false`, so the moment authority was
   * withdrawn cannot be moved later by repeating the call.
   */
  async revokePolicyLease(organisationId: string, leaseId: string, at: Date): Promise<boolean> {
    const updated = await this.prisma.devicePolicyLease.updateMany({
      where: { id: leaseId, organisationId, revokedAt: null },
      data: { revokedAt: at },
    });
    return updated.count === 1;
  }
}

/** One persisted lease row, exactly as stored. */
export interface DevicePolicyLeaseRow {
  id: string;
  organisationId: string;
  deviceId: string;
  siteId: string;
  actorUserId: string;
  authorityBasisId: string;
  scope: string[];
  issuedAt: Date;
  expiresAt: Date;
  revokedAt: Date | null;
}

/**
 * The PRECISE internal reason, `null` when the outcome is not a refusal.
 *
 * It is derived from the typed input rather than passed alongside it, so an
 * event cannot be filed as a refusal with no reason or as a success carrying
 * one.
 */
function refusalReasonOf(input: DeviceGatewayEventInput): string | null {
  if (input.type === 'ESTABLISHMENT_REFUSED' || input.type === 'OPERATION_REFUSED') {
    return input.contractRefusal === null ? input.refusal : `${input.refusal}/${input.contractRefusal}`;
  }
  return null;
}

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

/**
 * Guards the `::uuid` casts and the UUID-typed lookups.
 *
 * A malformed id reaching Postgres as a cast raises a driver error, and inside
 * an interactive transaction that error aborts the whole transaction. A caller
 * probing with a non-UUID `context_id` would then get a 500 where every other
 * unresolvable id gets the single D25-13 refusal — which is an oracle built out
 * of error shapes. `null` here means "no such row", exactly as a genuine miss
 * does.
 */
function isUuid(value: string): boolean {
  return UUID_PATTERN.test(value);
}
