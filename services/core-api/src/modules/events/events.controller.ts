import { BadRequestException, Body, Controller, Get, HttpStatus, Inject, Logger, Post, Query, Req, Res, UseGuards } from '@nestjs/common';
import { ThrottlerGuard, Throttle } from '@nestjs/throttler';
import type { ServerResponse } from 'node:http';
import { NormalisedEventSchema } from '@sentinel/contracts';
import { z } from 'zod';
import { isSafeSubjectToken, SUBJECT_TOKEN_RULE } from '../../common/messaging/subject-token';
import { RequiresAction } from '../../common/security/requires-action.decorator';
import type { RequestWithPrincipal } from '../../common/security/principal';
import { ACTION_EVENT_INGEST, ACTION_EVENT_READ, DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT } from './events.constants';
import { formatValidationIssues } from './events.mapper';
import { EventsService } from './events.service';
import type { EventsListResult } from './events.types';

const ListQuerySchema = z.object({
  site_id: z.string().min(1).optional(),
  source_type: z.string().min(1).optional(),
  occurred_from: z.string().datetime().optional(),
  occurred_to: z.string().datetime().optional(),
  limit: z.coerce.number().int().positive().max(MAX_LIST_LIMIT).optional(),
  cursor: z.string().min(1).optional(),
  // Development bypass only: required when no principal is
  // present, since there is otherwise no tenant to scope the list to.
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

@Controller('api/v1/events')
export class EventsController {
  private readonly logger = new Logger(EventsController.name);

  constructor(@Inject(EventsService) private readonly eventsService: EventsService) {}

  /**
   * Deliverable #3. Validation, auth and org-match all happen before
   * anything is persisted (acceptance criteria 2 & 3): the guard checks
   * principal/action first, then this handler validates the body against
   * `NormalisedEventSchema` (zero local redefinition) and checks the org
   * match, and only then calls the service.
   */
  @Post()
  // WP-14/M7: rate-limit the raw ingest surface (per caller) so a single
  // source cannot flood the pipeline. Generous enough for legitimate bulk
  // ingest; the guard only runs on the real HTTP path.
  @UseGuards(ThrottlerGuard)
  @Throttle({ default: { limit: 600, ttl: 60_000 } })
  @RequiresAction(ACTION_EVENT_INGEST)
  async ingest(@Req() req: RequestWithPrincipal, @Body() rawBody: unknown, @Res() res: ServerResponse): Promise<void> {
    const parsed = NormalisedEventSchema.safeParse(rawBody);
    if (!parsed.success) {
      writeJson(res, HttpStatus.BAD_REQUEST, {
        error: 'Invalid event payload',
        trace_id: traceIdOf(req),
        field_errors: formatValidationIssues(parsed.error),
      });
      return;
    }
    const event = parsed.data;

    // WP-17/C7-06: `organisation_id` and `site_id` are interpolated into this
    // event's JetStream subject (`sentinel.events.{org}.{site}`), and `site_id`
    // is free client text. A value carrying `.`, `*`, `>` or whitespace either
    // re-shapes the subject or makes NATS reject the publish outright — and
    // because ingest persists first and publishes as a follow-up step (§76),
    // the caller would get a 201 for an event that can never reach Fusion. On a
    // protective platform a silently undeliverable detection is a worse outcome
    // than a rejected request, so this fails at the boundary instead.
    for (const [field, value] of [['organisation_id', event.organisation_id], ['site_id', event.site_id]] as const) {
      if (!isSafeSubjectToken(value)) {
        writeJson(res, HttpStatus.BAD_REQUEST, {
          error: 'Invalid event payload',
          trace_id: traceIdOf(req),
          field_errors: [`${field} ${SUBJECT_TOKEN_RULE}`],
        });
        return;
      }
    }

    const principal = req.principal;

    if (principal) {
      if (principal.organisation_id !== event.organisation_id) {
        this.logger.warn(
          `event.ingest denied: organisation mismatch (principal_org=${principal.organisation_id}, body_org=${event.organisation_id}, trace_id=${traceIdOf(req)})`,
        );
        // 404-style denial: never confirm/deny existence of another org's data.
        writeJson(res, HttpStatus.NOT_FOUND, { error: 'Not Found', trace_id: traceIdOf(req) });
        return;
      }
    } else {
      // Development bypass path: only reachable through the guard's
      // DEV_AUTH_ENABLED bypass (principal-action.guard.ts) — there is no
      // principal org to compare the body against, so org-match cannot be
      // enforced here. Logged loudly so this is never silently relied on.
      this.logger.warn(`event.ingest: no principal on request, org-match not enforced (dev bypass, trace_id=${traceIdOf(req)})`);
    }

    const result = await this.eventsService.ingest(event);
    if (result.duplicate) {
      writeJson(res, HttpStatus.OK, { duplicate: true, original_event_id: result.original_event_id });
      return;
    }
    writeJson(res, HttpStatus.CREATED, { duplicate: false, event: result.event });
  }

  /** Deliverable #5: tenant-scoped, filterable, cursor-paginated, newest first. */
  @Get()
  @RequiresAction(ACTION_EVENT_READ)
  async list(@Req() req: RequestWithPrincipal, @Query() rawQuery: Record<string, unknown>): Promise<EventsListResult> {
    const parsed = ListQuerySchema.safeParse(rawQuery);
    if (!parsed.success) {
      throw new BadRequestException({ message: formatValidationIssues(parsed.error) });
    }
    const query = parsed.data;
    const principal = req.principal;

    let organisationId: string;
    if (principal) {
      organisationId = principal.organisation_id;
    } else {
      // Development bypass: no principal means no inferred
      // tenant. Listing across every organisation is never acceptable,
      // even in dev, so require the caller to say which org explicitly.
      if (!query.organisation_id) {
        throw new BadRequestException('organisation_id query param is required when no principal is present (dev bypass)');
      }
      organisationId = query.organisation_id;
    }

    return this.eventsService.list({
      organisationId,
      siteId: query.site_id,
      sourceType: query.source_type,
      occurredFrom: query.occurred_from ? new Date(query.occurred_from) : undefined,
      occurredTo: query.occurred_to ? new Date(query.occurred_to) : undefined,
      limit: query.limit ?? DEFAULT_LIST_LIMIT,
      cursor: query.cursor,
    });
  }
}
