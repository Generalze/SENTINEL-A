import type { ServerResponse } from 'node:http';
import { BadRequestException, Body, Controller, Get, HttpStatus, Inject, Logger, Param, Post, Query, Req, Res } from '@nestjs/common';
import { z } from 'zod';
import { RequiresAction } from '../../common/security/requires-action.decorator';
import type { RequestWithPrincipal } from '../../common/security/principal';
import { EVIDENCE_CLASSIFICATION_LEVELS } from './classification';
import { ACTION_EVIDENCE_INGEST, ACTION_EVIDENCE_READ, ACTION_EVIDENCE_VERIFY, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT, PURPOSE_HEADER } from './evidence.constants';
import { formatValidationIssues } from './evidence.mapper';
import { EvidenceService } from './evidence.service';
import type { CustodyActor } from './evidence.types';

const IngestBodySchema = z.object({
  organisation_id: z.string().min(1),
  source_id: z.string().min(1),
  content_base64: z.string().min(1),
  content_type: z.string().min(1),
  classification: z.enum(EVIDENCE_CLASSIFICATION_LEVELS),
  related_event_ids: z.array(z.string()).optional(),
  incident_id: z.string().min(1).optional(),
  captured_at: z.string().datetime().optional(),
});

const DeriveBodySchema = z.object({
  transform_label: z.string().min(1),
  content_base64: z.string().min(1),
  content_type: z.string().min(1),
  classification: z.enum(EVIDENCE_CLASSIFICATION_LEVELS).optional(),
});

const ListQuerySchema = z.object({
  incident_id: z.string().min(1).optional(),
  limit: z.coerce.number().int().positive().max(MAX_LIST_LIMIT).optional(),
  // Dev-bypass only (TODO-WIRED-IN-WAVE-4): required when no principal is present.
  organisation_id: z.string().min(1).optional(),
});

const OrgOnlyQuerySchema = z.object({
  organisation_id: z.string().min(1).optional(),
});

function writeJson(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(body));
}

function traceIdOf(req: RequestWithPrincipal): string {
  return req.traceId ?? 'unknown';
}

function purposeHeaderOf(req: RequestWithPrincipal): string | undefined {
  const raw = (req.headers as Record<string, string | string[] | undefined>)[PURPOSE_HEADER];
  const value = Array.isArray(raw) ? raw[0] : raw;
  return value;
}

/** A human actor when the principal carries a known user id; otherwise a system actor (only reachable when no principal is attached, e.g. direct-constructed integration tests). */
function actorFor(req: RequestWithPrincipal): CustodyActor {
  const userId = req.principal?.user.id;
  return userId ? { kind: 'user', id: userId } : { kind: 'system' };
}

/**
 * Resolves the tenant to scope a request to. A present principal always
 * wins (client-supplied organisation_id is ignored, mirroring
 * events.controller.ts's list handler) so a caller can never widen its own
 * scope by lying in a query param. With no principal (dev bypass only),
 * an explicit organisation_id is required — there is otherwise no tenant
 * to scope to.
 */
function resolveOrganisationId(req: RequestWithPrincipal, queryOrganisationId: string | undefined): string {
  if (req.principal) {
    return req.principal.organisation_id;
  }
  if (!queryOrganisationId) {
    throw new BadRequestException('organisation_id query param is required when no principal is present (dev bypass)');
  }
  return queryOrganisationId;
}

@Controller('api/v1/evidence')
export class EvidenceController {
  private readonly logger = new Logger(EvidenceController.name);

  constructor(@Inject(EvidenceService) private readonly evidenceService: EvidenceService) {}

  /** Deliverable 2/7: ingest write path, exposed over HTTP. */
  @Post()
  @RequiresAction(ACTION_EVIDENCE_INGEST)
  async ingest(@Req() req: RequestWithPrincipal, @Body() rawBody: unknown, @Res() res: ServerResponse): Promise<void> {
    const parsed = IngestBodySchema.safeParse(rawBody);
    if (!parsed.success) {
      writeJson(res, HttpStatus.BAD_REQUEST, {
        error: 'Invalid ingest payload',
        trace_id: traceIdOf(req),
        field_errors: formatValidationIssues(parsed.error),
      });
      return;
    }
    const body = parsed.data;
    const principal = req.principal;

    if (principal) {
      if (principal.organisation_id !== body.organisation_id) {
        this.logger.warn(
          `evidence.ingest denied: organisation mismatch (principal_org=${principal.organisation_id}, body_org=${body.organisation_id}, trace_id=${traceIdOf(req)})`,
        );
        // 404-style denial: never confirm/deny existence of another org's data.
        writeJson(res, HttpStatus.NOT_FOUND, { error: 'Not Found', trace_id: traceIdOf(req) });
        return;
      }
    } else {
      this.logger.warn(`evidence.ingest: no principal on request, org-match not enforced (dev bypass, trace_id=${traceIdOf(req)})`);
    }

    const evidence = await this.evidenceService.ingest({
      organisation_id: body.organisation_id,
      source_id: body.source_id,
      content: Buffer.from(body.content_base64, 'base64'),
      content_type: body.content_type,
      classification: body.classification,
      related_event_ids: body.related_event_ids,
      incident_id: body.incident_id,
      captured_at: body.captured_at ? new Date(body.captured_at) : undefined,
      actor: actorFor(req),
    });

    writeJson(res, HttpStatus.CREATED, { evidence });
  }

  /** Deliverable 7: tenant-scoped metadata list. No per-item custody logging — see EvidenceService.list's doc comment. */
  @Get()
  @RequiresAction(ACTION_EVIDENCE_READ)
  async list(@Req() req: RequestWithPrincipal, @Query() rawQuery: Record<string, unknown>): Promise<{ items: unknown[] }> {
    const parsed = ListQuerySchema.safeParse(rawQuery);
    if (!parsed.success) {
      throw new BadRequestException({ message: formatValidationIssues(parsed.error) });
    }
    const query = parsed.data;
    const organisationId = resolveOrganisationId(req, query.organisation_id);

    const items = await this.evidenceService.list({
      organisationId,
      incidentId: query.incident_id,
      limit: query.limit ?? DEFAULT_LIST_LIMIT,
    });
    return { items };
  }

  /** Deliverable 7: single-item metadata read. Writes VIEWED (deliverable 3). */
  @Get(':id')
  @RequiresAction(ACTION_EVIDENCE_READ)
  async getMetadata(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Query() rawQuery: Record<string, unknown>): Promise<unknown> {
    const parsed = OrgOnlyQuerySchema.safeParse(rawQuery);
    if (!parsed.success) {
      throw new BadRequestException({ message: formatValidationIssues(parsed.error) });
    }
    const organisationId = resolveOrganisationId(req, parsed.data.organisation_id);
    return this.evidenceService.getMetadata(id, organisationId, actorFor(req));
  }

  /**
   * Deliverable 7: content download. Requires the `evidence.read` action
   * (route guard) AND a non-empty `x-purpose` header (AC4) — the purpose
   * gate itself lives in EvidenceService.downloadContent so it can never
   * be bypassed by a caller that reaches the service directly.
   */
  @Get(':id/content')
  @RequiresAction(ACTION_EVIDENCE_READ)
  async downloadContent(
    @Req() req: RequestWithPrincipal,
    @Param('id') id: string,
    @Query() rawQuery: Record<string, unknown>,
    @Res() res: ServerResponse,
  ): Promise<void> {
    const parsed = OrgOnlyQuerySchema.safeParse(rawQuery);
    if (!parsed.success) {
      writeJson(res, HttpStatus.BAD_REQUEST, { error: 'Invalid query', trace_id: traceIdOf(req), field_errors: formatValidationIssues(parsed.error) });
      return;
    }
    const organisationId = resolveOrganisationId(req, parsed.data.organisation_id);
    const purpose = purposeHeaderOf(req);

    const { metadata, content } = await this.evidenceService.downloadContent(id, organisationId, purpose, actorFor(req));

    res.statusCode = HttpStatus.OK;
    res.setHeader('Content-Type', metadata.content_type);
    res.setHeader('X-Evidence-Content-Hash', metadata.content_hash);
    res.end(content);
  }

  /** Deliverable 4: derived object write path, exposed over HTTP. */
  @Post(':id/derive')
  @RequiresAction(ACTION_EVIDENCE_INGEST)
  async derive(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Body() rawBody: unknown, @Query() rawQuery: Record<string, unknown>): Promise<unknown> {
    const queryParsed = OrgOnlyQuerySchema.safeParse(rawQuery);
    if (!queryParsed.success) {
      throw new BadRequestException({ message: formatValidationIssues(queryParsed.error) });
    }
    const bodyParsed = DeriveBodySchema.safeParse(rawBody);
    if (!bodyParsed.success) {
      throw new BadRequestException({ message: formatValidationIssues(bodyParsed.error) });
    }
    const organisationId = resolveOrganisationId(req, queryParsed.data.organisation_id);
    const body = bodyParsed.data;

    return this.evidenceService.derive({
      evidence_id: id,
      organisation_id: organisationId,
      transform_label: body.transform_label,
      content: Buffer.from(body.content_base64, 'base64'),
      content_type: body.content_type,
      classification: body.classification,
      actor: actorFor(req),
    });
  }

  /** Deliverable 5: admin integrity-check endpoint. */
  @Post(':id/verify')
  @RequiresAction(ACTION_EVIDENCE_VERIFY)
  async verify(@Req() req: RequestWithPrincipal, @Param('id') id: string, @Query() rawQuery: Record<string, unknown>): Promise<unknown> {
    const parsed = OrgOnlyQuerySchema.safeParse(rawQuery);
    if (!parsed.success) {
      throw new BadRequestException({ message: formatValidationIssues(parsed.error) });
    }
    const organisationId = resolveOrganisationId(req, parsed.data.organisation_id);
    return this.evidenceService.verify(id, organisationId, actorFor(req));
  }
}
