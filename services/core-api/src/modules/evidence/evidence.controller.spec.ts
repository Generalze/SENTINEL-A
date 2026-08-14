import { BadRequestException } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { describe, expect, it, vi } from 'vitest';
import { EvidenceController } from './evidence.controller';
import type { EvidenceService } from './evidence.service';
import type { RequestWithPrincipal } from './principal.types';

function makeRes(): ServerResponse & { statusCode: number; body?: string; endedBuffer?: Buffer; headers: Record<string, string> } {
  const headers: Record<string, string> = {};
  const res = {
    setHeader: vi.fn((name: string, value: string) => {
      headers[name.toLowerCase()] = value;
    }),
    headers,
    end: vi.fn(function (this: { body?: string; endedBuffer?: Buffer }, chunk?: string | Buffer) {
      if (Buffer.isBuffer(chunk)) this.endedBuffer = chunk;
      else if (typeof chunk === 'string') this.body = chunk;
    }),
    statusCode: 0,
  };
  return res as unknown as ServerResponse & { statusCode: number; body?: string; endedBuffer?: Buffer; headers: Record<string, string> };
}

function makeReq(overrides: Partial<RequestWithPrincipal> & { headers?: Record<string, string> } = {}): RequestWithPrincipal {
  return { traceId: 'trace-abc', headers: {}, ...overrides } as RequestWithPrincipal;
}

function makeService(): EvidenceService {
  return {
    ingest: vi.fn(),
    list: vi.fn(),
    getMetadata: vi.fn(),
    downloadContent: vi.fn(),
    derive: vi.fn(),
    verify: vi.fn(),
  } as unknown as EvidenceService;
}

const validIngestBody = {
  organisation_id: 'org-1',
  source_id: 'camera-1',
  content_base64: Buffer.from('hello', 'utf8').toString('base64'),
  content_type: 'application/octet-stream',
  classification: 'EVIDENCE',
};

describe('EvidenceController#ingest (POST /api/v1/evidence)', () => {
  it('returns 400 with field-level errors for an invalid body and never calls the service', async () => {
    const service = makeService();
    const controller = new EvidenceController(service);
    const req = makeReq({ principal: { organisation_id: 'org-1', hasAction: () => true } });
    const res = makeRes();

    await controller.ingest(req, { not: 'valid' }, res);

    expect(res.statusCode).toBe(400);
    const body = JSON.parse(res.body ?? '{}');
    expect(body.error).toBe('Invalid ingest payload');
    expect(service.ingest).not.toHaveBeenCalled();
  });

  it('returns 404 and never calls the service when the body organisation does not match the principal', async () => {
    const service = makeService();
    const controller = new EvidenceController(service);
    const req = makeReq({ principal: { organisation_id: 'org-principal', hasAction: () => true } });
    const res = makeRes();

    await controller.ingest(req, validIngestBody, res);

    expect(res.statusCode).toBe(404);
    expect(service.ingest).not.toHaveBeenCalled();
  });

  it('decodes content_base64 to a Buffer and returns 201 with the ingested evidence', async () => {
    const service = makeService();
    vi.mocked(service.ingest).mockResolvedValue({ id: 'ev-1' } as never);
    const controller = new EvidenceController(service);
    const req = makeReq({ principal: { organisation_id: 'org-1', hasAction: () => true } });
    const res = makeRes();

    await controller.ingest(req, validIngestBody, res);

    expect(res.statusCode).toBe(201);
    const call = vi.mocked(service.ingest).mock.calls[0][0];
    expect(call.content).toEqual(Buffer.from('hello', 'utf8'));
    expect(call.actor).toEqual({ kind: 'system' });
    expect(JSON.parse(res.body ?? '{}')).toEqual({ evidence: { id: 'ev-1' } });
  });

  it('attributes a user actor when the principal carries a user_id', async () => {
    const service = makeService();
    vi.mocked(service.ingest).mockResolvedValue({ id: 'ev-1' } as never);
    const controller = new EvidenceController(service);
    const req = makeReq({ principal: { organisation_id: 'org-1', user_id: 'user-7', hasAction: () => true } });
    const res = makeRes();

    await controller.ingest(req, validIngestBody, res);

    const call = vi.mocked(service.ingest).mock.calls[0][0];
    expect(call.actor).toEqual({ kind: 'user', id: 'user-7' });
  });

  it('skips the org-match check and still ingests when no principal is present (DEV_AUTH_ENABLED bypass)', async () => {
    const service = makeService();
    vi.mocked(service.ingest).mockResolvedValue({ id: 'ev-1' } as never);
    const controller = new EvidenceController(service);
    const req = makeReq();
    const res = makeRes();

    await controller.ingest(req, validIngestBody, res);

    expect(service.ingest).toHaveBeenCalled();
    expect(res.statusCode).toBe(201);
  });
});

describe('EvidenceController#list (GET /api/v1/evidence)', () => {
  it('scopes the query by the principal organisation, ignoring any client-supplied organisation_id', async () => {
    const service = makeService();
    vi.mocked(service.list).mockResolvedValue([]);
    const controller = new EvidenceController(service);
    const req = makeReq({ principal: { organisation_id: 'org-principal', hasAction: () => true } });

    await controller.list(req, { organisation_id: 'org-attacker-supplied' });

    expect(service.list).toHaveBeenCalledWith(expect.objectContaining({ organisationId: 'org-principal' }));
  });

  it('requires an explicit organisation_id query param when no principal is present', async () => {
    const service = makeService();
    const controller = new EvidenceController(service);
    const req = makeReq();

    await expect(controller.list(req, {})).rejects.toThrow(BadRequestException);
    expect(service.list).not.toHaveBeenCalled();
  });

  it('rejects an out-of-range limit with a 400', async () => {
    const service = makeService();
    const controller = new EvidenceController(service);
    const req = makeReq({ principal: { organisation_id: 'org-1', hasAction: () => true } });

    await expect(controller.list(req, { limit: '99999' })).rejects.toThrow(BadRequestException);
  });
});

describe('EvidenceController#getMetadata (GET /api/v1/evidence/:id)', () => {
  it('resolves the organisation from the principal and delegates to the service', async () => {
    const service = makeService();
    vi.mocked(service.getMetadata).mockResolvedValue({ id: 'ev-1' } as never);
    const controller = new EvidenceController(service);
    const req = makeReq({ principal: { organisation_id: 'org-1', hasAction: () => true } });

    const result = await controller.getMetadata(req, 'ev-1', {});

    expect(service.getMetadata).toHaveBeenCalledWith('ev-1', 'org-1', { kind: 'system' });
    expect(result).toEqual({ id: 'ev-1' });
  });
});

describe('EvidenceController#downloadContent (GET /api/v1/evidence/:id/content)', () => {
  it('AC4: forwards the x-purpose header to the service and streams the returned content with its content-type', async () => {
    const service = makeService();
    vi.mocked(service.downloadContent).mockResolvedValue({
      metadata: { content_type: 'image/png', content_hash: 'hash-1' } as never,
      content: Buffer.from('bytes'),
    });
    const controller = new EvidenceController(service);
    const req = makeReq({ principal: { organisation_id: 'org-1', hasAction: () => true }, headers: { 'x-purpose': 'investigation' } });
    const res = makeRes();

    await controller.downloadContent(req, 'ev-1', {}, res);

    expect(service.downloadContent).toHaveBeenCalledWith('ev-1', 'org-1', 'investigation', { kind: 'system' });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('image/png');
    expect(res.headers['x-evidence-content-hash']).toBe('hash-1');
    expect(res.endedBuffer).toEqual(Buffer.from('bytes'));
  });

  it('forwards an absent purpose header as undefined (the service is the one that denies it, per AC4)', async () => {
    const service = makeService();
    vi.mocked(service.downloadContent).mockResolvedValue({ metadata: { content_type: 'text/plain', content_hash: 'h' } as never, content: Buffer.from('x') });
    const controller = new EvidenceController(service);
    const req = makeReq({ principal: { organisation_id: 'org-1', hasAction: () => true } });
    const res = makeRes();

    await controller.downloadContent(req, 'ev-1', {}, res);

    expect(service.downloadContent).toHaveBeenCalledWith('ev-1', 'org-1', undefined, { kind: 'system' });
  });
});

describe('EvidenceController#derive (POST /api/v1/evidence/:id/derive)', () => {
  it('decodes content_base64 and delegates to the service', async () => {
    const service = makeService();
    vi.mocked(service.derive).mockResolvedValue({ id: 'ev-2' } as never);
    const controller = new EvidenceController(service);
    const req = makeReq({ principal: { organisation_id: 'org-1', hasAction: () => true } });

    const result = await controller.derive(
      req,
      'ev-1',
      { transform_label: 'thumbnail', content_base64: Buffer.from('clip').toString('base64'), content_type: 'image/png' },
      {},
    );

    expect(result).toEqual({ id: 'ev-2' });
    const call = vi.mocked(service.derive).mock.calls[0][0];
    expect(call.evidence_id).toBe('ev-1');
    expect(call.content).toEqual(Buffer.from('clip'));
  });
});

describe('EvidenceController#verify (POST /api/v1/evidence/:id/verify)', () => {
  it('resolves the organisation from the principal and delegates to the service', async () => {
    const service = makeService();
    vi.mocked(service.verify).mockResolvedValue({ evidence_id: 'ev-1', verified: true } as never);
    const controller = new EvidenceController(service);
    const req = makeReq({ principal: { organisation_id: 'org-1', hasAction: () => true } });

    const result = await controller.verify(req, 'ev-1', {});

    expect(service.verify).toHaveBeenCalledWith('ev-1', 'org-1', { kind: 'system' });
    expect(result).toEqual({ evidence_id: 'ev-1', verified: true });
  });
});
