import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { Prisma } from '@prisma/client';
import {
  CheckpointVerificationSchema,
  isWithinJsonByteBudget,
  MAX_BOUNDED_JSON_BYTES,
  PatrolCheckpointSchema,
  PatrolRouteSchema,
  PatrolRunCheckpointSchema,
  PatrolRunSchema,
  type CheckpointTimingOutcome,
} from '@sentinel/contracts';
import { z } from 'zod';
import { isSafeSubjectToken, SUBJECT_TOKEN_RULE } from '../../common/messaging/subject-token';
import type { Principal } from '../../common/security/principal';
import { ACTION_PATROL_RUN_MANAGE } from './patrol.constants';
import { mapRoute, mapRun, mapRunCheckpoint, mapVerification } from './patrol.mapper';
import {
  PatrolRepository,
  type CheckpointDefinitionInput,
  type RouteWithCheckpoints,
  type RouteWriteResult,
  type RunActionResult,
  type RunWithCheckpoints,
  type ScheduleRunResult,
  type VerifyResult,
} from './patrol.repository';
import type { PatrolRouteView, PatrolRunView, SiteScope, VerifyCheckpointResultView } from './patrol.types';

/**
 * WP-17/D3 precedent: the site id becomes a NATS subject token on the outbox
 * path, so an unsafe id is rejected at the API boundary and never persisted.
 */
const subjectSafeSiteId = z.string().min(1).refine(isSafeSubjectToken, { message: `site_id ${SUBJECT_TOKEN_RULE}` });

/**
 * One versioned checkpoint definition as supplied by the caller. The server
 * assigns sequence numbers from array order (directive s.6); offsets are the
 * C9-02 ordered triple and are re-validated here so a violation is a 400 with
 * a usable message rather than a contract assertion failure after the write.
 */
/**
 * Audit batch, correction 5: the contract's byte budget is enforced HERE, at
 * the request boundary, with the exact predicate the contract schema applies.
 * An oversized object is a 400 before any transaction begins; the service's
 * post-write contract assertion is thereby an unreachable backstop rather
 * than a path to "request failed, durable side effect succeeded".
 */
const boundedJson = z
  .record(z.unknown())
  .refine((value) => isWithinJsonByteBudget(value, MAX_BOUNDED_JSON_BYTES), {
    message: `bounded JSON must serialize to at most ${MAX_BOUNDED_JSON_BYTES} bytes`,
  });

const CheckpointDefinitionSchema = z
  .object({
    name: z.string().min(1).max(256),
    zone_id: z.string().min(1).max(256).nullable().optional(),
    location: boundedJson.nullable().optional(),
    window_open_offset_ms: z.number().int().nonnegative(),
    late_after_offset_ms: z.number().int().nonnegative(),
    missed_after_offset_ms: z.number().int().nonnegative(),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.late_after_offset_ms < value.window_open_offset_ms) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['late_after_offset_ms'], message: 'late_after_offset_ms must be >= window_open_offset_ms' });
    }
    if (value.missed_after_offset_ms < value.late_after_offset_ms) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['missed_after_offset_ms'], message: 'missed_after_offset_ms must be >= late_after_offset_ms' });
    }
  });

const CreateRouteInputSchema = z
  .object({
    site_id: subjectSafeSiteId,
    name: z.string().min(1).max(256),
    checkpoints: z.array(CheckpointDefinitionSchema).min(1).max(512),
    idempotency_key: z.string().min(1).max(256),
    trace_id: z.string().min(1).max(256),
  })
  .strict();
export type CreateRouteInput = z.infer<typeof CreateRouteInputSchema>;

const PublishVersionInputSchema = z
  .object({
    checkpoints: z.array(CheckpointDefinitionSchema).min(1).max(512),
    idempotency_key: z.string().min(1).max(256),
    trace_id: z.string().min(1).max(256),
  })
  .strict();
export type PublishVersionInput = z.infer<typeof PublishVersionInputSchema>;

/**
 * C9-04/lead ruling: there is deliberately NO route_version and NO timing
 * field here. The pinned version is the route's current version at schedule
 * time, and timing belongs to the version — a scheduler cannot weaken a patrol
 * standard for one shift. Site is derived from the route, never the body.
 */
const ScheduleRunInputSchema = z
  .object({
    patrol_route_id: z.string().uuid(),
    assigned_operative_user_id: z.string().min(1).max(256),
    incident_id: z.string().uuid().nullable().optional(),
    scheduled_start_at: z.string().datetime(),
    idempotency_key: z.string().min(1).max(256),
    trace_id: z.string().min(1).max(256),
  })
  .strict();
export type ScheduleRunInput = z.infer<typeof ScheduleRunInputSchema>;

const RunActionInputSchema = z
  .object({
    idempotency_key: z.string().min(1).max(256),
    trace_id: z.string().min(1).max(256),
  })
  .strict();
export type RunActionInput = z.infer<typeof RunActionInputSchema>;

const AbandonInputSchema = z
  .object({
    idempotency_key: z.string().min(1).max(256),
    trace_id: z.string().min(1).max(256),
    reason: z.string().min(1).max(2048).nullable().optional(),
  })
  .strict();
export type AbandonInput = z.infer<typeof AbandonInputSchema>;

const VerifyInputSchema = z
  .object({
    device_id: z.string().min(1).max(256),
    verification_method: z.string().min(1).max(128),
    verification_context: boundedJson.optional(),
    /** Client-observed time. Telemetry only — never part of the timing decision. */
    source_at: z.string().datetime(),
    idempotency_key: z.string().min(1).max(256),
    trace_id: z.string().min(1).max(256),
  })
  .strict();
export type VerifyCheckpointInput = z.infer<typeof VerifyInputSchema>;

function parseOrBadRequest<T>(schema: z.ZodSchema<T>, raw: unknown): T {
  const parsed = schema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException({ message: parsed.error.issues.map((issue) => issue.message) });
  return parsed.data;
}

function siteAllowed(siteScope: SiteScope, siteId: string): boolean {
  return siteScope.orgWide || siteScope.siteIds.includes(siteId);
}

/**
 * Correction 2: one deliberately generic shape for every idempotency-reuse
 * refusal, so the response cannot disclose WHICH field differed from the
 * request that established the key.
 */
function idempotencyConflict(): ConflictException {
  return new ConflictException('Idempotency key was already used with a different request');
}

function toDefinitionInputs(checkpoints: CreateRouteInput['checkpoints']): CheckpointDefinitionInput[] {
  return checkpoints.map((checkpoint) => ({
    name: checkpoint.name,
    zoneId: checkpoint.zone_id ?? null,
    location: checkpoint.location === null || checkpoint.location === undefined ? null : (checkpoint.location as Prisma.JsonObject),
    windowOpenOffsetMs: checkpoint.window_open_offset_ms,
    lateAfterOffsetMs: checkpoint.late_after_offset_ms,
    missedAfterOffsetMs: checkpoint.missed_after_offset_ms,
  }));
}

@Injectable()
export class PatrolService {
  constructor(@Inject(PatrolRepository) private readonly repository: PatrolRepository) {}

  parseCreateRoute(raw: unknown): CreateRouteInput {
    return parseOrBadRequest(CreateRouteInputSchema, raw);
  }

  parsePublishVersion(raw: unknown): PublishVersionInput {
    return parseOrBadRequest(PublishVersionInputSchema, raw);
  }

  parseScheduleRun(raw: unknown): ScheduleRunInput {
    return parseOrBadRequest(ScheduleRunInputSchema, raw);
  }

  parseRunAction(raw: unknown): RunActionInput {
    return parseOrBadRequest(RunActionInputSchema, raw);
  }

  parseAbandon(raw: unknown): AbandonInput {
    return parseOrBadRequest(AbandonInputSchema, raw);
  }

  parseVerify(raw: unknown): VerifyCheckpointInput {
    return parseOrBadRequest(VerifyInputSchema, raw);
  }

  // -------------------------------------------------------------------------
  // Routes
  // -------------------------------------------------------------------------

  private async validateZones(siteId: string, checkpoints: CreateRouteInput['checkpoints']): Promise<void> {
    const zoneIds = [...new Set(checkpoints.map((checkpoint) => checkpoint.zone_id).filter((zone): zone is string => zone !== null && zone !== undefined))];
    if (zoneIds.length === 0) return;
    const existing = await this.repository.existingZoneIds(siteId, zoneIds);
    if (zoneIds.some((zone) => !existing.has(zone))) {
      throw new BadRequestException('one or more zone_ids do not exist at this site');
    }
  }

  async createRoute(principal: Principal, siteScope: SiteScope, input: CreateRouteInput): Promise<PatrolRouteView> {
    if (!siteAllowed(siteScope, input.site_id)) throw new ForbiddenException('Principal is not scoped to this site');
    // WP-17A/C7-07: nonexistent site and another tenant's site are the same 404.
    if (!(await this.repository.siteExistsInOrganisation(principal.organisation_id, input.site_id))) {
      throw new NotFoundException('Site not found');
    }
    await this.validateZones(input.site_id, input.checkpoints);
    const outcome = await this.repository.createRoute({
      organisationId: principal.organisation_id,
      siteId: input.site_id,
      name: input.name,
      checkpoints: toDefinitionInputs(input.checkpoints),
      actorUserId: principal.user.id,
      idempotencyKey: input.idempotency_key,
      traceId: input.trace_id,
    });
    return this.mapRouteWriteResult(outcome);
  }

  async publishVersion(principal: Principal, siteScope: SiteScope, routeId: string, input: PublishVersionInput): Promise<PatrolRouteView> {
    const existing = await this.repository.getRoute(principal.organisation_id, routeId, siteScope);
    if (!existing) throw new NotFoundException('Patrol route not found');
    await this.validateZones(existing.route.siteId, input.checkpoints);
    const published = await this.repository.publishVersion(
      principal.organisation_id,
      routeId,
      siteScope,
      toDefinitionInputs(input.checkpoints),
      principal.user.id,
      input.idempotency_key,
      input.trace_id,
    );
    if (!published) throw new NotFoundException('Patrol route not found');
    return this.mapRouteWriteResult(published);
  }

  async getRoute(principal: Principal, siteScope: SiteScope, routeId: string): Promise<PatrolRouteView> {
    const result = await this.repository.getRoute(principal.organisation_id, routeId, siteScope);
    if (!result) throw new NotFoundException('Patrol route not found');
    return this.toRouteView(result);
  }

  async listRoutes(principal: Principal, siteScope: SiteScope): Promise<PatrolRouteView[]> {
    const rows = await this.repository.listRoutes(principal.organisation_id, siteScope);
    return rows.map((row) => this.toRouteView(row));
  }

  // -------------------------------------------------------------------------
  // Run lifecycle
  // -------------------------------------------------------------------------

  async scheduleRun(principal: Principal, siteScope: SiteScope, input: ScheduleRunInput): Promise<PatrolRunView> {
    // Site and version are derived from the route server-side; the body cannot
    // choose either (lead ruling / C9-04). This read only shapes the 404 and
    // the operative-role check — the repository re-resolves and LOCKS the
    // route inside the creating transaction (audit batch, correction 3), so
    // the version pinned is the one current when the run row is inserted, and
    // incident-assignment eligibility is judged from rows locked there too.
    const route = await this.repository.getRoute(principal.organisation_id, input.patrol_route_id, siteScope);
    if (!route) throw new NotFoundException('Patrol route not found');

    if (!(await this.repository.operativeCanReceive(principal.organisation_id, route.route.siteId, input.assigned_operative_user_id))) {
      throw new BadRequestException('Assignee is not a field operative at this site');
    }

    const outcome = await this.repository.scheduleRun({
      organisationId: principal.organisation_id,
      patrolRouteId: input.patrol_route_id,
      siteScope,
      assignedOperativeUserId: input.assigned_operative_user_id,
      incidentId: input.incident_id ?? null,
      scheduledStartAt: new Date(input.scheduled_start_at),
      actorUserId: principal.user.id,
      idempotencyKey: input.idempotency_key,
      traceId: input.trace_id,
    });
    return this.mapScheduleResult(outcome);
  }

  async startRun(principal: Principal, siteScope: SiteScope, runId: string, input: RunActionInput): Promise<PatrolRunView> {
    const result = await this.repository.startRun({
      organisationId: principal.organisation_id,
      runId,
      actorUserId: principal.user.id,
      idempotencyKey: input.idempotency_key,
      traceId: input.trace_id,
      siteScope,
    });
    return this.mapRunActionResult(result);
  }

  async cancelRun(principal: Principal, siteScope: SiteScope, runId: string, input: RunActionInput): Promise<PatrolRunView> {
    const result = await this.repository.cancelRun({
      organisationId: principal.organisation_id,
      runId,
      actorUserId: principal.user.id,
      idempotencyKey: input.idempotency_key,
      traceId: input.trace_id,
      siteScope,
    });
    return this.mapRunActionResult(result);
  }

  /** Operative abandonment of their own run. A reason is welcome but optional. */
  async abandonOwnRun(principal: Principal, siteScope: SiteScope, runId: string, input: AbandonInput): Promise<PatrolRunView> {
    const result = await this.repository.abandonRun({
      organisationId: principal.organisation_id,
      runId,
      actorUserId: principal.user.id,
      idempotencyKey: input.idempotency_key,
      traceId: input.trace_id,
      siteScope,
      mode: 'operative',
      reason: input.reason ?? null,
    });
    return this.mapRunActionResult(result);
  }

  /** C9-09: command intervention MUST carry its reason into the audit record. */
  async abandonAsCommand(principal: Principal, siteScope: SiteScope, runId: string, input: AbandonInput): Promise<PatrolRunView> {
    if (input.reason === null || input.reason === undefined) {
      throw new BadRequestException('command abandonment requires a reason');
    }
    const result = await this.repository.abandonRun({
      organisationId: principal.organisation_id,
      runId,
      actorUserId: principal.user.id,
      idempotencyKey: input.idempotency_key,
      traceId: input.trace_id,
      siteScope,
      mode: 'command',
      reason: input.reason,
    });
    return this.mapRunActionResult(result);
  }

  // -------------------------------------------------------------------------
  // Verification
  // -------------------------------------------------------------------------

  async verifyCheckpoint(
    principal: Principal,
    siteScope: SiteScope,
    runId: string,
    runCheckpointId: string,
    input: VerifyCheckpointInput,
  ): Promise<VerifyCheckpointResultView> {
    const result = await this.repository.verifyCheckpoint({
      organisationId: principal.organisation_id,
      runId,
      runCheckpointId,
      actorUserId: principal.user.id,
      deviceId: input.device_id,
      verificationMethod: input.verification_method,
      verificationContext: (input.verification_context ?? {}) as Prisma.JsonObject,
      sourceAt: new Date(input.source_at),
      idempotencyKey: input.idempotency_key,
      traceId: input.trace_id,
      siteScope,
    });
    return this.mapVerifyResult(result);
  }

  // -------------------------------------------------------------------------
  // Reads (C9-05: command sees the site; an operative sees only their own runs)
  // -------------------------------------------------------------------------

  async listRuns(principal: Principal, siteScope: SiteScope): Promise<PatrolRunView[]> {
    const operativeOnly = this.commandVisibility(principal) ? undefined : principal.user.id;
    const rows = await this.repository.listRuns(principal.organisation_id, siteScope, operativeOnly);
    return rows.map((row) => this.toRunView(row));
  }

  async getRun(principal: Principal, siteScope: SiteScope, runId: string): Promise<PatrolRunView> {
    const result = await this.repository.getRun(principal.organisation_id, runId, siteScope);
    if (!result) throw new NotFoundException('Patrol run not found');
    // C9-05: an eligible same-site operative who is NOT assigned this run gets
    // the same 404 as a nonexistent run — existence is itself need-to-know.
    if (!this.commandVisibility(principal) && result.run.assignedOperativeUserId !== principal.user.id) {
      throw new NotFoundException('Patrol run not found');
    }
    return this.toRunView(result);
  }

  /**
   * C9-05 visibility split. `patrol.run.read` is held by command roles and by
   * operatives; what differs is REACH. Command reach is defined by also holding
   * `patrol.run.manage` (site.commander, dispatcher) — an operative holds only
   * read/act/verify and is narrowed to their own runs.
   */
  private commandVisibility(principal: Principal): boolean {
    return principal.hasAction(ACTION_PATROL_RUN_MANAGE);
  }

  // -------------------------------------------------------------------------
  // Result mapping and contract assertions
  // -------------------------------------------------------------------------

  private mapRouteWriteResult(result: RouteWriteResult): PatrolRouteView {
    if (result.kind === 'idempotency_conflict') throw idempotencyConflict();
    return this.toRouteView(result.result);
  }

  private mapScheduleResult(result: ScheduleRunResult): PatrolRunView {
    switch (result.kind) {
      case 'route_not_found':
        throw new NotFoundException('Patrol route not found');
      case 'incident_not_in_scope':
        throw new BadRequestException('Incident is not in the caller organisation/site scope');
      case 'operative_not_eligible':
        throw new BadRequestException('Operative is not eligible for this incident');
      case 'idempotency_conflict':
        throw idempotencyConflict();
      default:
        return this.toRunView(result.result);
    }
  }

  private mapRunActionResult(result: RunActionResult): PatrolRunView {
    if (result.kind === 'not_found') throw new NotFoundException('Patrol run not found');
    if (result.kind === 'conflict') throw new ConflictException(`Patrol run status is ${result.currentStatus}`);
    if (result.kind === 'idempotency_conflict') throw idempotencyConflict();
    if (result.kind === 'version_integrity') throw new ConflictException('Patrol route version integrity conflict');
    if (result.kind === 'assignment_not_active') {
      throw new ConflictException(
        result.currentStatus === null
          ? 'Operative has no Field assignment for this incident'
          : `Operative Field assignment status is ${result.currentStatus}`,
      );
    }
    return this.toRunView({ run: result.run, checkpoints: result.checkpoints });
  }

  private mapVerifyResult(result: VerifyResult): VerifyCheckpointResultView {
    switch (result.kind) {
      case 'not_found':
        throw new NotFoundException('Patrol run not found');
      case 'run_not_in_progress':
        throw new ConflictException(`Patrol run status is ${result.currentStatus}`);
      case 'assignment_not_active':
        throw new ConflictException(
          result.currentStatus === null
            ? 'Operative has no Field assignment for this incident'
            : `Operative Field assignment status is ${result.currentStatus}`,
        );
      case 'already_resolved':
        throw new ConflictException(`Checkpoint is already ${result.currentState}`);
      case 'out_of_order':
        throw new ConflictException(`Checkpoint ${result.blockingSequence} is still PENDING`);
      case 'too_early':
        throw new ConflictException(`Verification window opens at ${result.windowOpensAt.toISOString()}`);
      case 'expired':
        throw new ConflictException(`Verification deadline passed at ${result.missedAfter.toISOString()}`);
      case 'idempotency_conflict':
        throw idempotencyConflict();
      default: {
        const outcome = result.runCheckpoint.state as Extract<CheckpointTimingOutcome, 'VERIFIED' | 'LATE'>;
        this.assertVerificationContract(result);
        return {
          verification: mapVerification(result.verification, outcome),
          run_checkpoint: mapRunCheckpoint(result.runCheckpoint),
          run_status: result.runStatus,
        };
      }
    }
  }

  /** Round-trips persisted rows through the WP-15/WP-19 contracts before they leave the service. */
  private toRouteView(result: RouteWithCheckpoints): PatrolRouteView {
    const view = mapRoute(result.route, result.checkpoints);
    PatrolRouteSchema.parse({
      schema_version: 1,
      patrol_route_id: view.id,
      organisation_id: view.organisation_id,
      site_id: view.site_id,
      name: view.name,
      route_version: view.route_version,
      checkpoint_ids: view.checkpoints.map((checkpoint) => checkpoint.id),
      created_at: view.created_at,
      updated_at: view.updated_at,
      created_by_user_id: view.created_by_user_id,
      trace_id: view.trace_id,
    });
    for (const checkpoint of result.checkpoints) {
      PatrolCheckpointSchema.parse({
        schema_version: 1,
        patrol_checkpoint_id: checkpoint.id,
        patrol_route_id: checkpoint.patrolRouteId,
        route_version: checkpoint.routeVersion,
        organisation_id: checkpoint.organisationId,
        site_id: checkpoint.siteId,
        sequence_number: checkpoint.sequenceNumber,
        name: checkpoint.name,
        zone_id: checkpoint.zoneId,
        location: checkpoint.location,
        window_open_offset_ms: checkpoint.windowOpenOffsetMs,
        late_after_offset_ms: checkpoint.lateAfterOffsetMs,
        missed_after_offset_ms: checkpoint.missedAfterOffsetMs,
        trace_id: checkpoint.traceId,
      });
    }
    return view;
  }

  private toRunView(result: RunWithCheckpoints): PatrolRunView {
    const view = mapRun(result.run, result.checkpoints);
    PatrolRunSchema.parse({
      schema_version: 1,
      patrol_run_id: view.id,
      organisation_id: view.organisation_id,
      site_id: view.site_id,
      patrol_route_id: view.patrol_route_id,
      route_version: view.route_version,
      assigned_operative_user_id: view.assigned_operative_user_id,
      incident_id: view.incident_id,
      status: view.status,
      scheduled_start_at: view.scheduled_start_at,
      started_at: view.started_at,
      ended_at: view.ended_at,
      created_by_user_id: view.created_by_user_id,
      trace_id: view.trace_id,
    });
    for (const checkpoint of view.checkpoints) {
      PatrolRunCheckpointSchema.parse({
        schema_version: 1,
        patrol_run_checkpoint_id: checkpoint.id,
        patrol_run_id: checkpoint.patrol_run_id,
        patrol_checkpoint_id: checkpoint.patrol_checkpoint_id,
        patrol_route_id: checkpoint.patrol_route_id,
        route_version: checkpoint.route_version,
        organisation_id: view.organisation_id,
        site_id: view.site_id,
        sequence_number: checkpoint.sequence_number,
        window_opens_at: checkpoint.window_opens_at,
        late_after: checkpoint.late_after,
        missed_after: checkpoint.missed_after,
        state: checkpoint.state,
        resolved_at: checkpoint.resolved_at,
        checkpoint_verification_id: checkpoint.checkpoint_verification_id,
        trace_id: view.trace_id,
      });
    }
    return view;
  }

  private assertVerificationContract(result: Extract<VerifyResult, { kind: 'verified' | 'duplicate' }>): void {
    CheckpointVerificationSchema.parse({
      schema_version: 1,
      checkpoint_verification_id: result.verification.id,
      organisation_id: result.verification.organisationId,
      site_id: result.verification.siteId,
      patrol_run_id: result.verification.patrolRunId,
      patrol_run_checkpoint_id: result.verification.patrolRunCheckpointId,
      patrol_route_id: result.verification.patrolRouteId,
      route_version: result.verification.routeVersion,
      patrol_checkpoint_id: result.verification.patrolCheckpointId,
      operative_user_id: result.verification.operativeUserId,
      device_id: result.verification.deviceId,
      verification_method: result.verification.verificationMethod,
      verification_context: result.verification.verificationContext,
      source_at: result.verification.sourceAt.toISOString(),
      recorded_at: result.verification.recordedAt.toISOString(),
      idempotency_key: result.verification.idempotencyKey,
      trace_id: result.verification.traceId,
    });
  }
}
