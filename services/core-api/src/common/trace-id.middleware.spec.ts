import { describe, expect, it, vi } from 'vitest';
import type { ServerResponse } from 'node:http';
import { TRACE_ID_HEADER, traceIdMiddleware } from './trace-id.middleware';
import type { RequestWithTraceId } from './http-types';

function makeReq(headers: Record<string, string | string[] | undefined>): RequestWithTraceId {
  return { headers } as unknown as RequestWithTraceId;
}

function makeRes(): ServerResponse & { headers: Record<string, string> } {
  const headers: Record<string, string> = {};
  return {
    headers,
    setHeader: vi.fn((name: string, value: string) => {
      headers[name] = value;
    }),
  } as unknown as ServerResponse & { headers: Record<string, string> };
}

describe('traceIdMiddleware', () => {
  it('echoes an inbound x-trace-id header on the request and response', () => {
    const req = makeReq({ [TRACE_ID_HEADER]: 'test-123' });
    const res = makeRes();
    const next = vi.fn();

    traceIdMiddleware(req, res, next);

    expect(req.traceId).toBe('test-123');
    expect(res.headers[TRACE_ID_HEADER]).toBe('test-123');
    expect(next).toHaveBeenCalledOnce();
  });

  it('generates a trace id when none is supplied', () => {
    const req = makeReq({});
    const res = makeRes();
    const next = vi.fn();

    traceIdMiddleware(req, res, next);

    expect(req.traceId).toBeTruthy();
    expect(res.headers[TRACE_ID_HEADER]).toBe(req.traceId);
    expect(next).toHaveBeenCalledOnce();
  });

  it('generates a trace id when the inbound header is blank', () => {
    const req = makeReq({ [TRACE_ID_HEADER]: '   ' });
    const res = makeRes();

    traceIdMiddleware(req, res, vi.fn());

    expect(req.traceId).toBeTruthy();
    expect(req.traceId?.trim()).not.toBe('');
  });

  it('takes the first value when the header is repeated', () => {
    const req = makeReq({ [TRACE_ID_HEADER]: ['first-id', 'second-id'] });
    const res = makeRes();

    traceIdMiddleware(req, res, vi.fn());

    expect(req.traceId).toBe('first-id');
  });
});
