import { BadRequestException } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { describe, expect, it, vi } from 'vitest';
import { EventsController } from './events.controller';
import type { EventsService } from './events.service';
import { buildPrincipal, type Principal, type RequestWithPrincipal } from '../../common/security/principal';
import { makeNormalisedEvent } from './test-fixtures';

/** A canonical principal for `org`; the concrete roles are irrelevant to these
 * controller tests (the global AccessGuard, not the controller, enforces actions). */
function principalFor(org: string): Principal {
  return buildPrincipal({ user: { id: `u_${org}`, clearance: 5 }, organisation_id: org, roles: [{ role: 'operator', site_id: null }] });
}

function makeRes(): ServerResponse & { statusCode: number; body?: string } {
  const res = {
    setHeader: vi.fn(),
    end: vi.fn(function (this: { body?: string }, chunk: string) {
      this.body = chunk;
    }),
    statusCode: 0,
  };
  return res as unknown as ServerResponse & { statusCode: number; body?: string };
}

function makeReq(overrides: Partial<RequestWithPrincipal> = {}): RequestWithPrincipal {
  return { traceId: 'trace-abc', ...overrides } as RequestWithPrincipal;
}

function makeService(): EventsService {
  return { ingest: vi.fn(), list: vi.fn() } as unknown as EventsService;
}

describe('EventsController#ingest (POST /api/v1/events)', () => {
  it('returns 400 with field-level errors for an invalid body and never calls the service', async () => {
    const service = makeService();
    const controller = new EventsController(service);
    const req = makeReq({ principal: principalFor('org-1') });
    const res = makeRes();

    await controller.ingest(req, { not: 'a valid event' }, res);

    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.body ?? '{}');
    expect(body.error).toBe('Invalid event payload');
    expect(Array.isArray(body.field_errors)).toBe(true);
    expect(body.field_errors.length).toBeGreaterThan(0);
    expect(service.ingest).not.toHaveBeenCalled();
  });

  it('WP-17/C7-06: returns 400 for a site_id that cannot form a NATS subject token, and never persists it', async () => {
    // `site_id` is free client text and is interpolated into this event's
    // JetStream subject. Persisting first and publishing after (§76) would
    // otherwise return 201 for an event that can never reach Fusion.
    for (const unsafe of ['site.a', 'site-a.>', 'site *', 'site a']) {
      const service = makeService();
      const controller = new EventsController(service);
      const event = makeNormalisedEvent({ organisation_id: 'org-1', site_id: unsafe });
      const res = makeRes();

      await controller.ingest(makeReq({ principal: principalFor('org-1') }), event, res);

      expect(res.statusCode).toBe(400);
      expect(JSON.parse(res.body ?? '{}').field_errors[0]).toMatch(/site_id/);
      expect(service.ingest).not.toHaveBeenCalled();
    }
  });

  it('WP-17/C7-06: returns 400 for an organisation_id that cannot form a NATS subject token', async () => {
    const service = makeService();
    const controller = new EventsController(service);
    const event = makeNormalisedEvent({ organisation_id: 'org.1', site_id: 'site-a' });
    const res = makeRes();

    await controller.ingest(makeReq({ principal: principalFor('org.1') }), event, res);

    expect(res.statusCode).toBe(400);
    expect(JSON.parse(res.body ?? '{}').field_errors[0]).toMatch(/organisation_id/);
    expect(service.ingest).not.toHaveBeenCalled();
  });

  it('returns 404 and never calls the service when the body organisation does not match the principal', async () => {
    const service = makeService();
    const controller = new EventsController(service);
    const event = makeNormalisedEvent({ organisation_id: 'org-body' });
    const req = makeReq({ principal: principalFor('org-principal') });
    const res = makeRes();

    await controller.ingest(req, event, res);

    expect(res.statusCode).toBe(404);
    expect(service.ingest).not.toHaveBeenCalled();
  });

  it('returns 200 { duplicate: true, original_event_id } when the service reports a duplicate', async () => {
    const service = makeService();
    vi.mocked(service.ingest).mockResolvedValue({ duplicate: true, original_event_id: 'evt_original' });
    const controller = new EventsController(service);
    const event = makeNormalisedEvent({ organisation_id: 'org-1' });
    const req = makeReq({ principal: principalFor('org-1') });
    const res = makeRes();

    await controller.ingest(req, event, res);

    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body ?? '{}')).toEqual({ duplicate: true, original_event_id: 'evt_original' });
  });

  it('returns 201 { duplicate: false, event } for a newly accepted event', async () => {
    const service = makeService();
    const stored = { ...makeNormalisedEvent(), id: 'row-1', received_count: 1, published_at: null };
    vi.mocked(service.ingest).mockResolvedValue({ duplicate: false, event: stored });
    const controller = new EventsController(service);
    const event = makeNormalisedEvent({ organisation_id: 'org-1' });
    const req = makeReq({ principal: principalFor('org-1') });
    const res = makeRes();

    await controller.ingest(req, event, res);

    expect(res.statusCode).toBe(201);
    expect(JSON.parse(res.body ?? '{}')).toEqual({ duplicate: false, event: stored });
  });

  it('skips the org-match check and still ingests when no principal is present (DEV_AUTH_ENABLED bypass)', async () => {
    const service = makeService();
    vi.mocked(service.ingest).mockResolvedValue({ duplicate: false, event: { ...makeNormalisedEvent(), id: 'row-1', received_count: 1, published_at: null } });
    const controller = new EventsController(service);
    const event = makeNormalisedEvent({ organisation_id: 'whatever-org' });
    const req = makeReq(); // no principal
    const res = makeRes();

    await controller.ingest(req, event, res);

    expect(service.ingest).toHaveBeenCalledWith(event);
    expect(res.statusCode).toBe(201);
  });
});

describe('EventsController#list (GET /api/v1/events)', () => {
  it('scopes the query by the principal organisation, ignoring any client-supplied organisation_id', async () => {
    const service = makeService();
    vi.mocked(service.list).mockResolvedValue({ items: [], next_cursor: null });
    const controller = new EventsController(service);
    const req = makeReq({ principal: principalFor('org-principal') });

    await controller.list(req, { organisation_id: 'org-attacker-supplied', site_id: 'site-1' });

    expect(service.list).toHaveBeenCalledWith(expect.objectContaining({ organisationId: 'org-principal', siteId: 'site-1' }));
  });

  it('requires an explicit organisation_id query param when no principal is present', async () => {
    const service = makeService();
    const controller = new EventsController(service);
    const req = makeReq();

    await expect(controller.list(req, {})).rejects.toThrow(BadRequestException);
    expect(service.list).not.toHaveBeenCalled();
  });

  it('uses the dev-bypass organisation_id query param when no principal is present', async () => {
    const service = makeService();
    vi.mocked(service.list).mockResolvedValue({ items: [], next_cursor: null });
    const controller = new EventsController(service);
    const req = makeReq();

    await controller.list(req, { organisation_id: 'org-dev' });

    expect(service.list).toHaveBeenCalledWith(expect.objectContaining({ organisationId: 'org-dev' }));
  });

  it('rejects an out-of-range limit with a 400', async () => {
    const service = makeService();
    const controller = new EventsController(service);
    const req = makeReq({ principal: principalFor('org-1') });

    await expect(controller.list(req, { limit: '99999' })).rejects.toThrow(BadRequestException);
  });
});
