import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type PatrolCheckpoint, type PatrolCheckpointVerification, type PatrolRoute, type PatrolRun, type PatrolRunCheckpoint } from '@prisma/client';
import {
  canCompletePatrolRun,
  canTransitionPatrolRunStatus,
  canVerifySequence,
  isCheckpointMissed,
  materialiseCheckpointWindow,
  resolveAbandonedCheckpointState,
  resolveCheckpointTiming,
  type PatrolRunCheckpointState,
  type PatrolRunStatus,
} from '@sentinel/contracts';
import { PrismaService } from '../../prisma/prisma.service';
import {
  AUDIT_PATROL_CHECKPOINT_MISSED,
  AUDIT_PATROL_CHECKPOINT_VERIFIED,
  AUDIT_PATROL_ROUTE_CREATED,
  AUDIT_PATROL_ROUTE_VERSION_PUBLISHED,
  AUDIT_PATROL_RUN_ABANDONED,
  AUDIT_PATROL_RUN_CANCELLED,
  AUDIT_PATROL_RUN_COMPLETED,
  AUDIT_PATROL_RUN_SCHEDULED,
  AUDIT_PATROL_RUN_STARTED,
  OUTBOX_KIND_PATROL_RUN_UPDATED,
  RUN_ACTION_ABANDON,
  RUN_ACTION_CANCEL,
  RUN_ACTION_START,
  TIMELINE_PATROL_CHECKPOINT_MISSED,
  TIMELINE_PATROL_CHECKPOINT_VERIFIED,
  TIMELINE_PATROL_RUN_ABANDONED,
  TIMELINE_PATROL_RUN_CANCELLED,
  TIMELINE_PATROL_RUN_COMPLETED,
  TIMELINE_PATROL_RUN_SCHEDULED,
  TIMELINE_PATROL_RUN_STARTED,
} from './patrol.constants';
import { assignmentAllowsExecution, assignmentAllowsScheduling } from './patrol.eligibility';
import type { SiteScope } from './patrol.types';

export function isUniqueViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

/**
 * Audit batch, correction 4: raised when START cannot atomically materialise
 * exactly one run checkpoint per definition. Thrown INSIDE the transaction so
 * everything — rows, audit, outbox, status — rolls back together.
 */
class PatrolVersionIntegrityError extends Error {
  constructor() {
    super('patrol route version produced no coherent materialisation');
  }
}

function routeSiteScopeWhere(siteScope: SiteScope): Prisma.PatrolRouteWhereInput {
  return siteScope.orgWide ? {} : { siteId: { in: siteScope.siteIds } };
}

function runSiteScopeWhere(siteScope: SiteScope): Prisma.PatrolRunWhereInput {
  return siteScope.orgWide ? {} : { siteId: { in: siteScope.siteIds } };
}

type Tx = Prisma.TransactionClient;

/**
 * Audit batch, correction 2: canonical JSON for semantic request comparison.
 * Key order must not distinguish two identical requests, and a stored JSONB
 * value read back is not guaranteed to preserve the request's key order.
 */
function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeysDeep);
  if (typeof value === 'object' && value !== null) {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      Object.keys(record)
        .sort()
        .map((key) => [key, sortKeysDeep(record[key])]),
    );
  }
  return value;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeysDeep(value)) ?? 'null';
}

export interface CheckpointDefinitionInput {
  name: string;
  zoneId: string | null;
  location: Prisma.JsonObject | null;
  windowOpenOffsetMs: number;
  lateAfterOffsetMs: number;
  missedAfterOffsetMs: number;
}

/**
 * Correction 2: same identity + key + same semantic request is a replay; same
 * identity + key + materially different request is a 409, never a mutation
 * and never the old representation. `trace_id` is deliberately NOT semantic —
 * a legitimate retry may carry a fresh trace.
 */
function sameCheckpointDefinitions(rows: readonly PatrolCheckpoint[], defs: readonly CheckpointDefinitionInput[]): boolean {
  if (rows.length !== defs.length) return false;
  return rows.every((row, index) => {
    const def = defs[index];
    return (
      row.name === def.name &&
      row.zoneId === def.zoneId &&
      canonicalJson(row.location) === canonicalJson(def.location) &&
      row.windowOpenOffsetMs === def.windowOpenOffsetMs &&
      row.lateAfterOffsetMs === def.lateAfterOffsetMs &&
      row.missedAfterOffsetMs === def.missedAfterOffsetMs
    );
  });
}

export interface CreateRouteInput {
  organisationId: string;
  siteId: string;
  name: string;
  checkpoints: CheckpointDefinitionInput[];
  actorUserId: string;
  idempotencyKey: string;
  traceId: string;
}

export interface ScheduleRunInput {
  organisationId: string;
  patrolRouteId: string;
  siteScope: SiteScope;
  assignedOperativeUserId: string;
  incidentId: string | null;
  scheduledStartAt: Date;
  actorUserId: string;
  idempotencyKey: string;
  traceId: string;
}

export interface RunActionInput {
  organisationId: string;
  runId: string;
  actorUserId: string;
  idempotencyKey: string;
  traceId: string;
  siteScope: SiteScope;
}

export interface VerifyInput extends RunActionInput {
  runCheckpointId: string;
  deviceId: string;
  verificationMethod: string;
  verificationContext: Prisma.JsonObject;
  sourceAt: Date;
}

export type RouteWithCheckpoints = { route: PatrolRoute; checkpoints: PatrolCheckpoint[] };
export type RunWithCheckpoints = { run: PatrolRun; checkpoints: PatrolRunCheckpoint[] };

export type RouteWriteResult =
  | { kind: 'created' | 'duplicate'; result: RouteWithCheckpoints }
  | { kind: 'idempotency_conflict' };

export type ScheduleRunResult =
  | { kind: 'created' | 'duplicate'; result: RunWithCheckpoints }
  | { kind: 'route_not_found' }
  | { kind: 'incident_not_in_scope' }
  | { kind: 'operative_not_eligible' }
  | { kind: 'idempotency_conflict' };

export type RunActionResult =
  | { kind: 'updated' | 'duplicate' | 'noop'; run: PatrolRun; checkpoints: PatrolRunCheckpoint[] }
  | { kind: 'not_found' }
  | { kind: 'conflict'; currentStatus: string }
  | { kind: 'assignment_not_active'; currentStatus: string | null }
  | { kind: 'idempotency_conflict' }
  | { kind: 'version_integrity' };

export type VerifyResult =
  | {
      kind: 'verified' | 'duplicate';
      verification: PatrolCheckpointVerification;
      runCheckpoint: PatrolRunCheckpoint;
      runStatus: PatrolRunStatus;
    }
  | { kind: 'not_found' }
  | { kind: 'run_not_in_progress'; currentStatus: string }
  | { kind: 'assignment_not_active'; currentStatus: string | null }
  | { kind: 'already_resolved'; currentState: string }
  | { kind: 'out_of_order'; blockingSequence: number }
  | { kind: 'too_early'; windowOpensAt: Date }
  | { kind: 'expired'; missedAfter: Date }
  | { kind: 'idempotency_conflict' };

const runCheckpointOrder = { sequenceNumber: 'asc' } as const;

@Injectable()
export class PatrolRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  // -------------------------------------------------------------------------
  // Shared primitives
  // -------------------------------------------------------------------------

  /**
   * C9-06: the authoritative receipt clock. `clock_timestamp()` deliberately,
   * not `now()`: Postgres pins `now()` to transaction START, which is BEFORE
   * the row lock was acquired — the ruling requires the receipt time to be
   * taken after the serialization boundary, so the winner of a race is stamped
   * with a time at which it actually held the row.
   */
  private async dbNow(tx: Tx): Promise<Date> {
    const rows = await tx.$queryRaw<Array<{ now: Date }>>(Prisma.sql`SELECT clock_timestamp() AS now`);
    const first = rows[0];
    if (!first) throw new Error('clock_timestamp returned no row');
    return first.now;
  }

  /**
   * Deterministic lock order across the whole feature (audit batch,
   * correction 3): run row -> matching FieldAssignment rows ordered by id ->
   * run checkpoint row. Schedule and publish, which have no run yet, lock the
   * ROUTE row first and touch nothing later in the order. One consistent
   * order cannot deadlock, and every patrol decision that depends on a
   * mutable row now reads it under a lock the mutator must also take.
   */
  private async lockRun(tx: Tx, runId: string): Promise<void> {
    await tx.$queryRaw(Prisma.sql`SELECT id FROM patrol_runs WHERE id = ${runId}::uuid FOR UPDATE`);
  }

  private async lockRoute(tx: Tx, routeId: string): Promise<void> {
    await tx.$queryRaw(Prisma.sql`SELECT id FROM patrol_routes WHERE id = ${routeId}::uuid FOR UPDATE`);
  }

  private async lockRunCheckpoint(tx: Tx, runCheckpointId: string): Promise<void> {
    await tx.$queryRaw(Prisma.sql`SELECT id FROM patrol_run_checkpoints WHERE id = ${runCheckpointId}::uuid FOR UPDATE`);
  }

  /**
   * Correction 3: the Field assignment rows an incident-linked decision reads
   * are locked INSIDE the patrol transaction, in deterministic id order, and
   * the statuses are read from the locked rows. A concurrent assignment
   * transition (its own row update) must now wait for — or be waited on by —
   * this transaction, so eligibility can no longer flip between the read and
   * the patrol mutation's commit.
   */
  private async lockAssignmentStatuses(tx: Tx, organisationId: string, siteId: string, incidentId: string, userId: string): Promise<string[]> {
    const rows = await tx.$queryRaw<Array<{ status: string }>>(Prisma.sql`
      SELECT status FROM field_assignments
      WHERE organisation_id = ${organisationId}
        AND site_id = ${siteId}
        AND incident_id = ${incidentId}::uuid
        AND assignee_user_id = ${userId}
      ORDER BY id
      FOR UPDATE`);
    return rows.map((row) => row.status);
  }

  /** Content-free realtime signal on the WP-17 Field path (directive s.12). */
  private async signalRunUpdated(tx: Tx, run: Pick<PatrolRun, 'id' | 'organisationId' | 'siteId'>): Promise<void> {
    await tx.fieldOutbox.create({
      data: {
        organisationId: run.organisationId,
        siteId: run.siteId,
        payload: {
          kind: OUTBOX_KIND_PATROL_RUN_UPDATED,
          patrol_run_id: run.id,
          organisation_id: run.organisationId,
          site_id: run.siteId,
        },
      },
    });
  }

  private async audit(tx: Tx, run: Pick<PatrolRun, 'organisationId' | 'siteId'>, actorUserId: string | null, kind: string, payload: Prisma.InputJsonValue): Promise<void> {
    await tx.fieldAuditLog.create({
      data: { organisationId: run.organisationId, siteId: run.siteId, actorUserId, kind, payload },
    });
  }

  private async timeline(tx: Tx, incidentId: string | null, actorUserId: string | null, kind: string, payload: Prisma.InputJsonValue): Promise<void> {
    if (incidentId === null) return;
    await tx.incidentTimelineEntry.create({ data: { incidentId, kind, actorUserId, payload } });
  }

  /**
   * System-owned completion (C9-09): runs inside whichever transaction resolved
   * the final checkpoint. C9-08 fails closed via canCompletePatrolRun — an
   * empty, PENDING-containing or CANCELLED-containing set never completes.
   */
  private async completeIfFinished(tx: Tx, runId: string, at: Date, traceId: string): Promise<boolean> {
    const run = await tx.patrolRun.findUniqueOrThrow({ where: { id: runId }, include: { checkpoints: { select: { state: true } } } });
    if (run.status !== 'IN_PROGRESS') return false;
    if (!canCompletePatrolRun(run.checkpoints.map((checkpoint) => checkpoint.state as PatrolRunCheckpointState))) return false;
    await tx.patrolRun.update({ where: { id: runId }, data: { status: 'COMPLETED', endedAt: at } });
    await this.audit(tx, run, null, AUDIT_PATROL_RUN_COMPLETED, {
      patrol_run_id: runId,
      from_status: 'IN_PROGRESS',
      to_status: 'COMPLETED',
      trace_id: traceId,
    });
    await this.timeline(tx, run.incidentId, null, TIMELINE_PATROL_RUN_COMPLETED, { patrol_run_id: runId, trace_id: traceId });
    await this.signalRunUpdated(tx, run);
    return true;
  }

  // -------------------------------------------------------------------------
  // Validation lookups (service calls these BEFORE mutating, WP-17A precedent)
  // -------------------------------------------------------------------------

  async siteExistsInOrganisation(organisationId: string, siteId: string): Promise<boolean> {
    const site = await this.prisma.site.findFirst({ where: { id: siteId, organisationId }, select: { id: true } });
    return site !== null;
  }

  /** Which of `zoneIds` exist at this site. Unknown zones fail route creation. */
  async existingZoneIds(siteId: string, zoneIds: readonly string[]): Promise<Set<string>> {
    if (zoneIds.length === 0) return new Set();
    const zones = await this.prisma.zone.findMany({ where: { siteId, id: { in: [...zoneIds] } }, select: { id: true } });
    return new Set(zones.map((zone) => zone.id));
  }

  /** WP-16 precedent: the assignee must hold field.operative at this exact site. */
  async operativeCanReceive(organisationId: string, siteId: string, userId: string): Promise<boolean> {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, organisationId, roles: { some: { role: 'field.operative', siteId } } },
      select: { id: true },
    });
    return user !== null;
  }

  // -------------------------------------------------------------------------
  // Routes
  // -------------------------------------------------------------------------

  async createRoute(input: CreateRouteInput): Promise<RouteWriteResult> {
    try {
      const created = await this.prisma.$transaction(async (tx) => {
        const route = await tx.patrolRoute.create({
          data: {
            organisationId: input.organisationId,
            siteId: input.siteId,
            name: input.name,
            currentVersion: 1,
            createdByUserId: input.actorUserId,
            idempotencyKey: input.idempotencyKey,
            traceId: input.traceId,
          },
        });
        await tx.patrolRouteVersion.create({
          data: {
            patrolRouteId: route.id,
            version: 1,
            organisationId: input.organisationId,
            siteId: input.siteId,
            publishedByUserId: input.actorUserId,
            idempotencyKey: input.idempotencyKey,
            traceId: input.traceId,
          },
        });
        await this.createCheckpointRows(tx, route, 1, input.checkpoints, input.traceId);
        await this.audit(tx, route, input.actorUserId, AUDIT_PATROL_ROUTE_CREATED, {
          patrol_route_id: route.id,
          route_version: 1,
          checkpoint_count: input.checkpoints.length,
          trace_id: input.traceId,
        });
        const checkpoints = await tx.patrolCheckpoint.findMany({
          where: { patrolRouteId: route.id, routeVersion: 1 },
          orderBy: runCheckpointOrder,
        });
        return { route, checkpoints };
      });
      return { kind: 'created', result: created };
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      // Replay lookup is scoped to the full idempotency identity, creator
      // included (C8-05 lesson): a replay only ever returns a route this same
      // authenticated user created.
      const route = await this.prisma.patrolRoute.findFirst({
        where: {
          organisationId: input.organisationId,
          siteId: input.siteId,
          createdByUserId: input.actorUserId,
          idempotencyKey: input.idempotencyKey,
        },
      });
      if (!route) throw error;
      // Correction 2: the replay returns the representation ESTABLISHED BY THE
      // ORIGINAL CREATION — the version row published under this same actor +
      // key — never whatever the route's current version has since become.
      const established = await this.prisma.patrolRouteVersion.findUnique({
        where: {
          patrolRouteId_publishedByUserId_idempotencyKey: {
            patrolRouteId: route.id,
            publishedByUserId: input.actorUserId,
            idempotencyKey: input.idempotencyKey,
          },
        },
      });
      if (!established) throw error;
      const checkpoints = await this.prisma.patrolCheckpoint.findMany({
        where: { patrolRouteId: route.id, routeVersion: established.version },
        orderBy: runCheckpointOrder,
      });
      if (route.name !== input.name || !sameCheckpointDefinitions(checkpoints, input.checkpoints)) {
        return { kind: 'idempotency_conflict' };
      }
      return { kind: 'duplicate', result: { route: { ...route, currentVersion: established.version }, checkpoints } };
    }
  }

  private async createCheckpointRows(tx: Tx, route: Pick<PatrolRoute, 'id' | 'organisationId' | 'siteId'>, version: number, checkpoints: CheckpointDefinitionInput[], traceId: string): Promise<void> {
    await tx.patrolCheckpoint.createMany({
      data: checkpoints.map((checkpoint, index) => ({
        patrolRouteId: route.id,
        routeVersion: version,
        organisationId: route.organisationId,
        siteId: route.siteId,
        // The server assigns the ordering; a caller supplies an ordered list
        // and may not invent or reuse sequence numbers (directive s.6).
        sequenceNumber: index + 1,
        name: checkpoint.name,
        zoneId: checkpoint.zoneId,
        location: checkpoint.location === null ? Prisma.DbNull : checkpoint.location,
        windowOpenOffsetMs: checkpoint.windowOpenOffsetMs,
        lateAfterOffsetMs: checkpoint.lateAfterOffsetMs,
        missedAfterOffsetMs: checkpoint.missedAfterOffsetMs,
        traceId,
      })),
    });
  }

  /**
   * C9-04: publishing is the ONLY way to change a patrol standard. The route
   * row is locked so two concurrent publishes cannot mint the same version
   * number — and so a concurrent schedule, which locks the same row before
   * pinning, cannot pin a version this publish is about to supersede without
   * one of the two strictly ordering before the other (correction 3).
   */
  async publishVersion(
    organisationId: string,
    routeId: string,
    siteScope: SiteScope,
    checkpoints: CheckpointDefinitionInput[],
    actorUserId: string,
    idempotencyKey: string,
    traceId: string,
  ): Promise<RouteWriteResult | null> {
    return this.prisma.$transaction(async (tx) => {
      const found = await tx.patrolRoute.findFirst({
        where: { id: routeId, organisationId, ...routeSiteScopeWhere(siteScope) },
        select: { id: true },
      });
      if (!found) return null;
      await this.lockRoute(tx, found.id);
      const route = await tx.patrolRoute.findUniqueOrThrow({ where: { id: found.id } });

      const duplicate = await tx.patrolRouteVersion.findUnique({
        where: {
          patrolRouteId_publishedByUserId_idempotencyKey: { patrolRouteId: route.id, publishedByUserId: actorUserId, idempotencyKey },
        },
      });
      if (duplicate) {
        const existing = await tx.patrolCheckpoint.findMany({
          where: { patrolRouteId: route.id, routeVersion: duplicate.version },
          orderBy: runCheckpointOrder,
        });
        // Correction 2: a reused key must carry the same semantic request.
        if (!sameCheckpointDefinitions(existing, checkpoints)) return { kind: 'idempotency_conflict' };
        return { kind: 'duplicate', result: { route: { ...route, currentVersion: duplicate.version }, checkpoints: existing } };
      }

      const version = route.currentVersion + 1;
      await tx.patrolRouteVersion.create({
        data: {
          patrolRouteId: route.id,
          version,
          organisationId: route.organisationId,
          siteId: route.siteId,
          publishedByUserId: actorUserId,
          idempotencyKey,
          traceId,
        },
      });
      await this.createCheckpointRows(tx, route, version, checkpoints, traceId);
      const updated = await tx.patrolRoute.update({ where: { id: route.id }, data: { currentVersion: version } });
      await this.audit(tx, route, actorUserId, AUDIT_PATROL_ROUTE_VERSION_PUBLISHED, {
        patrol_route_id: route.id,
        route_version: version,
        checkpoint_count: checkpoints.length,
        trace_id: traceId,
      });
      const created = await tx.patrolCheckpoint.findMany({
        where: { patrolRouteId: route.id, routeVersion: version },
        orderBy: runCheckpointOrder,
      });
      return { kind: 'created', result: { route: updated, checkpoints: created } };
    });
  }

  async getRoute(organisationId: string, routeId: string, siteScope: SiteScope): Promise<RouteWithCheckpoints | null> {
    const route = await this.prisma.patrolRoute.findFirst({ where: { id: routeId, organisationId, ...routeSiteScopeWhere(siteScope) } });
    if (!route) return null;
    const checkpoints = await this.prisma.patrolCheckpoint.findMany({
      where: { patrolRouteId: route.id, routeVersion: route.currentVersion },
      orderBy: runCheckpointOrder,
    });
    return { route, checkpoints };
  }

  async listRoutes(organisationId: string, siteScope: SiteScope): Promise<RouteWithCheckpoints[]> {
    const routes = await this.prisma.patrolRoute.findMany({
      where: { organisationId, ...routeSiteScopeWhere(siteScope) },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: 200,
    });
    if (routes.length === 0) return [];
    const checkpoints = await this.prisma.patrolCheckpoint.findMany({
      where: { OR: routes.map((route) => ({ patrolRouteId: route.id, routeVersion: route.currentVersion })) },
      orderBy: runCheckpointOrder,
    });
    const byRoute = new Map<string, PatrolCheckpoint[]>();
    for (const checkpoint of checkpoints) {
      const bucket = byRoute.get(checkpoint.patrolRouteId) ?? [];
      bucket.push(checkpoint);
      byRoute.set(checkpoint.patrolRouteId, bucket);
    }
    return routes.map((route) => ({ route, checkpoints: byRoute.get(route.id) ?? [] }));
  }

  // -------------------------------------------------------------------------
  // Run lifecycle
  // -------------------------------------------------------------------------

  /**
   * Correction 3: everything a schedule decision depends on is resolved and
   * locked INSIDE the creating transaction — the route row (so a concurrent
   * publish serializes against the version pin) and, for an incident-linked
   * run, the operative's Field assignment rows (so eligibility cannot go
   * terminal between the check and the insert).
   */
  async scheduleRun(input: ScheduleRunInput): Promise<ScheduleRunResult> {
    try {
      const outcome = await this.prisma.$transaction(async (tx): Promise<{ kind: 'created'; run: PatrolRun } | Exclude<ScheduleRunResult, { kind: 'created' | 'duplicate' | 'idempotency_conflict' }>> => {
        const found = await tx.patrolRoute.findFirst({
          where: { id: input.patrolRouteId, organisationId: input.organisationId, ...routeSiteScopeWhere(input.siteScope) },
          select: { id: true },
        });
        if (!found) return { kind: 'route_not_found' };
        await this.lockRoute(tx, found.id);
        const route = await tx.patrolRoute.findUniqueOrThrow({ where: { id: found.id } });

        if (input.incidentId !== null) {
          const incident = await tx.incident.findFirst({
            where: { id: input.incidentId, organisationId: input.organisationId, siteId: route.siteId },
            select: { id: true },
          });
          if (!incident) return { kind: 'incident_not_in_scope' };
          // C9-05 scheduling eligibility, from rows locked in this transaction.
          const statuses = await this.lockAssignmentStatuses(tx, input.organisationId, route.siteId, input.incidentId, input.assignedOperativeUserId);
          if (!statuses.some(assignmentAllowsScheduling)) return { kind: 'operative_not_eligible' };
        }

        const row = await tx.patrolRun.create({
          data: {
            organisationId: input.organisationId,
            siteId: route.siteId,
            patrolRouteId: route.id,
            // Pinned from the LOCKED route row, so a concurrent publish either
            // completed before this (new version pinned) or waits for us.
            routeVersion: route.currentVersion,
            assignedOperativeUserId: input.assignedOperativeUserId,
            incidentId: input.incidentId,
            status: 'SCHEDULED',
            scheduledStartAt: input.scheduledStartAt,
            createdByUserId: input.actorUserId,
            idempotencyKey: input.idempotencyKey,
            traceId: input.traceId,
          },
        });
        await this.audit(tx, row, input.actorUserId, AUDIT_PATROL_RUN_SCHEDULED, {
          patrol_run_id: row.id,
          patrol_route_id: route.id,
          route_version: row.routeVersion,
          assigned_operative_user_id: input.assignedOperativeUserId,
          incident_id: input.incidentId,
          trace_id: input.traceId,
        });
        await this.timeline(tx, input.incidentId, input.actorUserId, TIMELINE_PATROL_RUN_SCHEDULED, {
          patrol_run_id: row.id,
          patrol_route_id: route.id,
          route_version: row.routeVersion,
          trace_id: input.traceId,
        });
        await this.signalRunUpdated(tx, row);
        return { kind: 'created', run: row };
      });
      if (outcome.kind !== 'created') return outcome;
      return { kind: 'created', result: { run: outcome.run, checkpoints: [] } };
    } catch (error) {
      if (!isUniqueViolation(error)) throw error;
      // The schedule idempotency identity is (organisation, site, creator,
      // key); site comes from the route, resolved read-only here.
      const route = await this.prisma.patrolRoute.findFirst({
        where: { id: input.patrolRouteId, organisationId: input.organisationId, ...routeSiteScopeWhere(input.siteScope) },
        select: { siteId: true },
      });
      if (!route) throw error;
      const existing = await this.prisma.patrolRun.findFirst({
        where: {
          organisationId: input.organisationId,
          siteId: route.siteId,
          createdByUserId: input.actorUserId,
          idempotencyKey: input.idempotencyKey,
        },
        include: { checkpoints: { orderBy: runCheckpointOrder } },
      });
      if (!existing) throw error;
      const { checkpoints, ...run } = existing;
      // Correction 2 semantic identity: route, operative, incident and the
      // scheduled start. route_version is deliberately absent — it is derived
      // server-side, so two identical requests replay even if a publish moved
      // the pointer in between; the established run is the answer.
      const sameRequest =
        run.patrolRouteId === input.patrolRouteId &&
        run.assignedOperativeUserId === input.assignedOperativeUserId &&
        run.incidentId === input.incidentId &&
        run.scheduledStartAt.getTime() === input.scheduledStartAt.getTime();
      if (!sameRequest) return { kind: 'idempotency_conflict' };
      return { kind: 'duplicate', result: { run, checkpoints } };
    }
  }

  /**
   * START (C9-09: assigned operative only — the service resolves visibility,
   * this method still re-checks the assignee under the lock).
   *
   * Materialisation happens here, exactly once (directive s.2/3): the pinned
   * version's offsets and the database-clock `started_at` produce the run's
   * absolute instants; nothing ever recomputes them. Correction 4: START is
   * fail-closed — a pinned version that yields no checkpoints, or a
   * materialisation that writes fewer rows than definitions, aborts the whole
   * transaction; no status change, audit, timeline or outbox row survives.
   */
  async startRun(input: RunActionInput): Promise<RunActionResult> {
    try {
      return await this.prisma.$transaction(async (tx): Promise<RunActionResult> => {
        const found = await tx.patrolRun.findFirst({
          where: { id: input.runId, organisationId: input.organisationId, ...runSiteScopeWhere(input.siteScope) },
          select: { id: true, assignedOperativeUserId: true },
        });
        // An unassigned reader gets the same 404 as a nonexistent run (C9-05).
        if (!found || found.assignedOperativeUserId !== input.actorUserId) return { kind: 'not_found' };

        await this.lockRun(tx, found.id);
        const run = await tx.patrolRun.findUniqueOrThrow({ where: { id: found.id } });

        const duplicate = await this.findActionDuplicate(tx, run.id, input.actorUserId, RUN_ACTION_START, input.idempotencyKey);
        if (duplicate) return { kind: 'duplicate', run, checkpoints: await this.runCheckpoints(tx, run.id) };
        if (run.status === 'IN_PROGRESS') return { kind: 'noop', run, checkpoints: await this.runCheckpoints(tx, run.id) };
        if (!canTransitionPatrolRunStatus(run.status as PatrolRunStatus, 'IN_PROGRESS')) {
          return { kind: 'conflict', currentStatus: run.status };
        }

        // C9-05: an incident-linked patrol may only be EXECUTED under an
        // assignment the operative has actually taken on — read from rows
        // locked in THIS transaction (correction 3), so a concurrent
        // assignment transition cannot slip between check and start.
        if (run.incidentId !== null) {
          const statuses = await this.lockAssignmentStatuses(tx, run.organisationId, run.siteId, run.incidentId, input.actorUserId);
          if (!statuses.some(assignmentAllowsExecution)) {
            return { kind: 'assignment_not_active', currentStatus: statuses[0] ?? null };
          }
        }

        const startedAt = await this.dbNow(tx);
        const definitions = await tx.patrolCheckpoint.findMany({
          where: { patrolRouteId: run.patrolRouteId, routeVersion: run.routeVersion },
          orderBy: runCheckpointOrder,
        });
        // Correction 4: the public API cannot publish an empty version, but a
        // corrupted or bypassed database could present one. A patrol that
        // "starts" with nothing it must prove may not exist.
        if (definitions.length === 0) return { kind: 'version_integrity' };
        const created = await tx.patrolRunCheckpoint.createMany({
          data: definitions.map((definition) => {
            const window = materialiseCheckpointWindow(startedAt, {
              window_open_offset_ms: definition.windowOpenOffsetMs,
              late_after_offset_ms: definition.lateAfterOffsetMs,
              missed_after_offset_ms: definition.missedAfterOffsetMs,
            });
            return {
              patrolRunId: run.id,
              patrolCheckpointId: definition.id,
              organisationId: run.organisationId,
              siteId: run.siteId,
              patrolRouteId: run.patrolRouteId,
              routeVersion: run.routeVersion,
              sequenceNumber: definition.sequenceNumber,
              windowOpensAt: new Date(window.window_opens_at),
              lateAfter: new Date(window.late_after),
              missedAfter: new Date(window.missed_after),
              state: 'PENDING',
              traceId: input.traceId,
            };
          }),
        });
        // One materialised expectation per definition, atomically, or nothing.
        if (created.count !== definitions.length) throw new PatrolVersionIntegrityError();
        const updated = await tx.patrolRun.update({ where: { id: run.id }, data: { status: 'IN_PROGRESS', startedAt } });
        await this.recordAction(tx, run.id, input.actorUserId, RUN_ACTION_START, input.idempotencyKey);
        await this.audit(tx, run, input.actorUserId, AUDIT_PATROL_RUN_STARTED, {
          patrol_run_id: run.id,
          from_status: 'SCHEDULED',
          to_status: 'IN_PROGRESS',
          started_at: startedAt.toISOString(),
          checkpoint_count: definitions.length,
          trace_id: input.traceId,
        });
        await this.timeline(tx, run.incidentId, input.actorUserId, TIMELINE_PATROL_RUN_STARTED, {
          patrol_run_id: run.id,
          started_at: startedAt.toISOString(),
          trace_id: input.traceId,
        });
        await this.signalRunUpdated(tx, run);
        return { kind: 'updated', run: updated, checkpoints: await this.runCheckpoints(tx, run.id) };
      });
    } catch (error) {
      if (error instanceof PatrolVersionIntegrityError) return { kind: 'version_integrity' };
      throw error;
    }
  }

  /** CANCEL (C9-09: command authority; a run that never started, called off). */
  async cancelRun(input: RunActionInput): Promise<RunActionResult> {
    return this.prisma.$transaction(async (tx) => {
      const found = await tx.patrolRun.findFirst({
        where: { id: input.runId, organisationId: input.organisationId, ...runSiteScopeWhere(input.siteScope) },
        select: { id: true },
      });
      if (!found) return { kind: 'not_found' };

      await this.lockRun(tx, found.id);
      const run = await tx.patrolRun.findUniqueOrThrow({ where: { id: found.id } });

      const duplicate = await this.findActionDuplicate(tx, run.id, input.actorUserId, RUN_ACTION_CANCEL, input.idempotencyKey);
      if (duplicate) return { kind: 'duplicate', run, checkpoints: await this.runCheckpoints(tx, run.id) };
      if (run.status === 'CANCELLED') return { kind: 'noop', run, checkpoints: [] };
      if (!canTransitionPatrolRunStatus(run.status as PatrolRunStatus, 'CANCELLED')) {
        return { kind: 'conflict', currentStatus: run.status };
      }

      const at = await this.dbNow(tx);
      const updated = await tx.patrolRun.update({ where: { id: run.id }, data: { status: 'CANCELLED', endedAt: at } });
      await this.recordAction(tx, run.id, input.actorUserId, RUN_ACTION_CANCEL, input.idempotencyKey);
      await this.audit(tx, run, input.actorUserId, AUDIT_PATROL_RUN_CANCELLED, {
        patrol_run_id: run.id,
        from_status: run.status,
        to_status: 'CANCELLED',
        trace_id: input.traceId,
      });
      await this.timeline(tx, run.incidentId, input.actorUserId, TIMELINE_PATROL_RUN_CANCELLED, { patrol_run_id: run.id, trace_id: input.traceId });
      await this.signalRunUpdated(tx, run);
      return { kind: 'updated', run: updated, checkpoints: [] };
    });
  }

  /**
   * ABANDON (C9-03/C9-09). `mode` decides who may reach the row: the operative
   * path requires the caller to BE the assignee (a non-assignee gets 404); the
   * command path requires a reason, validated by the service.
   *
   * C9-03's laundering rule is applied per checkpoint under the run lock: a
   * pending expectation already past its deadline becomes MISSED — with its own
   * audit and timeline evidence — and only a still-future one is CANCELLED.
   */
  async abandonRun(input: RunActionInput & { mode: 'operative' | 'command'; reason: string | null }): Promise<RunActionResult> {
    return this.prisma.$transaction(async (tx) => {
      const found = await tx.patrolRun.findFirst({
        where: { id: input.runId, organisationId: input.organisationId, ...runSiteScopeWhere(input.siteScope) },
        select: { id: true, assignedOperativeUserId: true },
      });
      if (!found) return { kind: 'not_found' };
      if (input.mode === 'operative' && found.assignedOperativeUserId !== input.actorUserId) return { kind: 'not_found' };

      await this.lockRun(tx, found.id);
      const run = await tx.patrolRun.findUniqueOrThrow({ where: { id: found.id } });

      const duplicate = await this.findActionDuplicate(tx, run.id, input.actorUserId, RUN_ACTION_ABANDON, input.idempotencyKey);
      if (duplicate) {
        // Correction 2: the reason is part of the semantic request. A reused
        // key with a different reason is a conflict, not a replay.
        if ((input.reason ?? null) !== run.abandonReason) return { kind: 'idempotency_conflict' };
        return { kind: 'duplicate', run, checkpoints: await this.runCheckpoints(tx, run.id) };
      }
      if (run.status === 'ABANDONED') return { kind: 'noop', run, checkpoints: await this.runCheckpoints(tx, run.id) };
      if (!canTransitionPatrolRunStatus(run.status as PatrolRunStatus, 'ABANDONED')) {
        return { kind: 'conflict', currentStatus: run.status };
      }

      const at = await this.dbNow(tx);
      const pending = await tx.patrolRunCheckpoint.findMany({ where: { patrolRunId: run.id, state: 'PENDING' }, orderBy: runCheckpointOrder });
      for (const checkpoint of pending) {
        const resolution = resolveAbandonedCheckpointState(at, { state: 'PENDING', missed_after: checkpoint.missedAfter.toISOString() });
        if (resolution === null) continue;
        await tx.patrolRunCheckpoint.update({ where: { id: checkpoint.id }, data: { state: resolution } });
        if (resolution === 'MISSED') {
          await this.audit(tx, run, input.actorUserId, AUDIT_PATROL_CHECKPOINT_MISSED, {
            patrol_run_id: run.id,
            patrol_run_checkpoint_id: checkpoint.id,
            sequence_number: checkpoint.sequenceNumber,
            missed_after: checkpoint.missedAfter.toISOString(),
            cause: 'abandonment',
            trace_id: input.traceId,
          });
          await this.timeline(tx, run.incidentId, null, TIMELINE_PATROL_CHECKPOINT_MISSED, {
            patrol_run_id: run.id,
            patrol_run_checkpoint_id: checkpoint.id,
            sequence_number: checkpoint.sequenceNumber,
            cause: 'abandonment',
            trace_id: input.traceId,
          });
        }
      }

      const updated = await tx.patrolRun.update({
        where: { id: run.id },
        data: { status: 'ABANDONED', endedAt: at, abandonReason: input.reason },
      });
      await this.recordAction(tx, run.id, input.actorUserId, RUN_ACTION_ABANDON, input.idempotencyKey);
      await this.audit(tx, run, input.actorUserId, AUDIT_PATROL_RUN_ABANDONED, {
        patrol_run_id: run.id,
        from_status: 'IN_PROGRESS',
        to_status: 'ABANDONED',
        mode: input.mode,
        reason: input.reason,
        trace_id: input.traceId,
      });
      await this.timeline(tx, run.incidentId, input.actorUserId, TIMELINE_PATROL_RUN_ABANDONED, {
        patrol_run_id: run.id,
        mode: input.mode,
        reason: input.reason,
        trace_id: input.traceId,
      });
      await this.signalRunUpdated(tx, run);
      return { kind: 'updated', run: updated, checkpoints: await this.runCheckpoints(tx, run.id) };
    });
  }

  // -------------------------------------------------------------------------
  // Verification (C9-01, C9-02, C9-06)
  // -------------------------------------------------------------------------

  async verifyCheckpoint(input: VerifyInput): Promise<VerifyResult> {
    return this.prisma.$transaction(async (tx) => {
      const found = await tx.patrolRun.findFirst({
        where: { id: input.runId, organisationId: input.organisationId, ...runSiteScopeWhere(input.siteScope) },
        select: { id: true, assignedOperativeUserId: true },
      });
      // C9-05: only the assigned operative may even learn the run exists.
      if (!found || found.assignedOperativeUserId !== input.actorUserId) return { kind: 'not_found' };

      // Correction 3 lock order: run -> assignment rows -> run checkpoint.
      await this.lockRun(tx, found.id);
      const run = await tx.patrolRun.findUniqueOrThrow({ where: { id: found.id } });

      // A device may not nominate a checkpoint outside its own run.
      const target = await tx.patrolRunCheckpoint.findFirst({ where: { id: input.runCheckpointId, patrolRunId: run.id } });
      if (!target) return { kind: 'not_found' };

      // Replay: the full C9-06 namespace, actor and run scope included. A
      // replay may only ever return a verification this same operative
      // recorded on this same run checkpoint — and only for the same request:
      // a reused key with different device, method, context or source time is
      // a conflict, never the old record (correction 2).
      const established = await tx.patrolCheckpointVerification.findUnique({
        where: {
          organisationId_patrolRunId_patrolRunCheckpointId_operativeUserId_idempotencyKey: {
            organisationId: run.organisationId,
            patrolRunId: run.id,
            patrolRunCheckpointId: target.id,
            operativeUserId: input.actorUserId,
            idempotencyKey: input.idempotencyKey,
          },
        },
      });
      if (established) {
        const sameRequest =
          established.deviceId === input.deviceId &&
          established.verificationMethod === input.verificationMethod &&
          canonicalJson(established.verificationContext) === canonicalJson(input.verificationContext) &&
          established.sourceAt.getTime() === input.sourceAt.getTime();
        if (!sameRequest) return { kind: 'idempotency_conflict' };
        const checkpoint = await tx.patrolRunCheckpoint.findUniqueOrThrow({ where: { id: target.id } });
        return { kind: 'duplicate', verification: established, runCheckpoint: checkpoint, runStatus: run.status as PatrolRunStatus };
      }

      if (run.status !== 'IN_PROGRESS') return { kind: 'run_not_in_progress', currentStatus: run.status };

      // C9-05: executing an incident-linked patrol requires a live assignment,
      // read from rows locked in THIS transaction (correction 3).
      if (run.incidentId !== null) {
        const statuses = await this.lockAssignmentStatuses(tx, run.organisationId, run.siteId, run.incidentId, input.actorUserId);
        if (!statuses.some(assignmentAllowsExecution)) {
          return { kind: 'assignment_not_active', currentStatus: statuses[0] ?? null };
        }
      }

      await this.lockRunCheckpoint(tx, target.id);
      const checkpoint = await tx.patrolRunCheckpoint.findUniqueOrThrow({ where: { id: target.id } });
      if (checkpoint.state !== 'PENDING') return { kind: 'already_resolved', currentState: checkpoint.state };

      // Directive s.6: ordering is server-authoritative. Sibling states are
      // stable here because every sibling mutation holds the run lock.
      const siblings = await tx.patrolRunCheckpoint.findMany({
        where: { patrolRunId: run.id },
        select: { sequenceNumber: true, state: true },
      });
      if (
        !canVerifySequence(
          checkpoint.sequenceNumber,
          siblings.map((sibling) => ({ sequence_number: sibling.sequenceNumber, state: sibling.state as PatrolRunCheckpointState })),
        )
      ) {
        const blocking = siblings
          .filter((sibling) => sibling.sequenceNumber < checkpoint.sequenceNumber && sibling.state === 'PENDING')
          .reduce((lowest, sibling) => Math.min(lowest, sibling.sequenceNumber), Number.POSITIVE_INFINITY);
        return { kind: 'out_of_order', blockingSequence: blocking };
      }

      // C9-06: the authoritative receipt time, read from the database AFTER
      // the serialization boundary. The client's source_at is telemetry and
      // plays no part in this decision.
      const recordedAt = await this.dbNow(tx);
      const outcome = resolveCheckpointTiming(recordedAt, {
        window_opens_at: checkpoint.windowOpensAt.toISOString(),
        late_after: checkpoint.lateAfter.toISOString(),
        missed_after: checkpoint.missedAfter.toISOString(),
      });
      // C9-02: TOO_EARLY and EXPIRED refuse without mutating anything. An
      // expired checkpoint stays PENDING for the sweep to stamp MISSED —
      // MISSED is the sweep's judgement alone, never the verify path's.
      if (outcome === 'TOO_EARLY') return { kind: 'too_early', windowOpensAt: checkpoint.windowOpensAt };
      if (outcome === 'EXPIRED') return { kind: 'expired', missedAfter: checkpoint.missedAfter };

      const verification = await tx.patrolCheckpointVerification.create({
        data: {
          organisationId: run.organisationId,
          siteId: run.siteId,
          patrolRunId: run.id,
          patrolRunCheckpointId: checkpoint.id,
          patrolRouteId: run.patrolRouteId,
          // Correction 1: the pinned version is part of the evidence identity,
          // and the composite FK proves it agrees with the run checkpoint.
          routeVersion: run.routeVersion,
          patrolCheckpointId: checkpoint.patrolCheckpointId,
          operativeUserId: input.actorUserId,
          deviceId: input.deviceId,
          verificationMethod: input.verificationMethod,
          verificationContext: input.verificationContext,
          sourceAt: input.sourceAt,
          recordedAt,
          idempotencyKey: input.idempotencyKey,
          traceId: input.traceId,
        },
      });
      const resolved = await tx.patrolRunCheckpoint.update({
        where: { id: checkpoint.id },
        data: { state: outcome, resolvedAt: recordedAt, verificationId: verification.id },
      });
      await this.audit(tx, run, input.actorUserId, AUDIT_PATROL_CHECKPOINT_VERIFIED, {
        patrol_run_id: run.id,
        patrol_run_checkpoint_id: checkpoint.id,
        checkpoint_verification_id: verification.id,
        sequence_number: checkpoint.sequenceNumber,
        outcome,
        recorded_at: recordedAt.toISOString(),
        source_at: input.sourceAt.toISOString(),
        trace_id: input.traceId,
      });
      await this.timeline(tx, run.incidentId, input.actorUserId, TIMELINE_PATROL_CHECKPOINT_VERIFIED, {
        patrol_run_id: run.id,
        patrol_run_checkpoint_id: checkpoint.id,
        sequence_number: checkpoint.sequenceNumber,
        outcome,
        trace_id: input.traceId,
      });
      await this.signalRunUpdated(tx, run);

      const completed = await this.completeIfFinished(tx, run.id, recordedAt, input.traceId);
      return {
        kind: 'verified',
        verification,
        runCheckpoint: resolved,
        runStatus: completed ? 'COMPLETED' : (run.status as PatrolRunStatus),
      };
    });
  }

  // -------------------------------------------------------------------------
  // Missed sweep (directive s.3: MISSED is the server sweep's judgement alone)
  // -------------------------------------------------------------------------

  /**
   * One sweep pass. Candidates are located optimistically, then each is
   * re-judged under the run lock with a fresh database clock — so a
   * verification that wins the race leaves the sweep nothing to do, and a
   * sweep that wins leaves the verification refused as EXPIRED (C9-06).
   */
  async sweepMissedOnce(limit = 100): Promise<number> {
    const candidates = await this.prisma.patrolRunCheckpoint.findMany({
      where: { state: 'PENDING', missedAfter: { lt: new Date() }, run: { status: 'IN_PROGRESS' } },
      select: { id: true, patrolRunId: true },
      orderBy: { missedAfter: 'asc' },
      take: limit,
    });

    let transitioned = 0;
    for (const candidate of candidates) {
      const changed = await this.prisma.$transaction(async (tx) => {
        await this.lockRun(tx, candidate.patrolRunId);
        const run = await tx.patrolRun.findUnique({ where: { id: candidate.patrolRunId } });
        if (!run || run.status !== 'IN_PROGRESS') return false;
        await this.lockRunCheckpoint(tx, candidate.id);
        const checkpoint = await tx.patrolRunCheckpoint.findUnique({ where: { id: candidate.id } });
        if (!checkpoint) return false;

        const now = await this.dbNow(tx);
        // The contract's own predicate, judged against this checkpoint's own
        // deadline and the database clock — never a sibling, never a client.
        const missed = isCheckpointMissed(now, {
          state: checkpoint.state as PatrolRunCheckpointState,
          missed_after: checkpoint.missedAfter.toISOString(),
        });
        if (!missed) return false;

        await tx.patrolRunCheckpoint.update({ where: { id: checkpoint.id }, data: { state: 'MISSED' } });
        await this.audit(tx, run, null, AUDIT_PATROL_CHECKPOINT_MISSED, {
          patrol_run_id: run.id,
          patrol_run_checkpoint_id: checkpoint.id,
          sequence_number: checkpoint.sequenceNumber,
          missed_after: checkpoint.missedAfter.toISOString(),
          cause: 'sweep',
          trace_id: checkpoint.traceId,
        });
        await this.timeline(tx, run.incidentId, null, TIMELINE_PATROL_CHECKPOINT_MISSED, {
          patrol_run_id: run.id,
          patrol_run_checkpoint_id: checkpoint.id,
          sequence_number: checkpoint.sequenceNumber,
          cause: 'sweep',
          trace_id: checkpoint.traceId,
        });
        await this.signalRunUpdated(tx, run);
        await this.completeIfFinished(tx, run.id, now, checkpoint.traceId);
        return true;
      });
      if (changed) transitioned += 1;
    }
    return transitioned;
  }

  // -------------------------------------------------------------------------
  // Reads
  // -------------------------------------------------------------------------

  async getRun(organisationId: string, runId: string, siteScope: SiteScope): Promise<RunWithCheckpoints | null> {
    const run = await this.prisma.patrolRun.findFirst({
      where: { id: runId, organisationId, ...runSiteScopeWhere(siteScope) },
      include: { checkpoints: { orderBy: runCheckpointOrder } },
    });
    if (!run) return null;
    const { checkpoints, ...rest } = run;
    return { run: rest, checkpoints };
  }

  async listRuns(organisationId: string, siteScope: SiteScope, assignedOperativeUserId?: string): Promise<RunWithCheckpoints[]> {
    const runs = await this.prisma.patrolRun.findMany({
      where: {
        organisationId,
        ...runSiteScopeWhere(siteScope),
        ...(assignedOperativeUserId === undefined ? {} : { assignedOperativeUserId }),
      },
      include: { checkpoints: { orderBy: runCheckpointOrder } },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: 200,
    });
    return runs.map(({ checkpoints, ...run }) => ({ run, checkpoints }));
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  private async runCheckpoints(tx: Tx, runId: string): Promise<PatrolRunCheckpoint[]> {
    return tx.patrolRunCheckpoint.findMany({ where: { patrolRunId: runId }, orderBy: runCheckpointOrder });
  }

  private async findActionDuplicate(tx: Tx, runId: string, actorUserId: string, action: string, idempotencyKey: string): Promise<boolean> {
    const duplicate = await tx.patrolRunActionIdempotency.findUnique({
      where: { patrolRunId_actorUserId_action_idempotencyKey: { patrolRunId: runId, actorUserId, action, idempotencyKey } },
    });
    return duplicate !== null;
  }

  private async recordAction(tx: Tx, runId: string, actorUserId: string, action: string, idempotencyKey: string): Promise<void> {
    await tx.patrolRunActionIdempotency.create({ data: { patrolRunId: runId, actorUserId, action, idempotencyKey } });
  }
}
