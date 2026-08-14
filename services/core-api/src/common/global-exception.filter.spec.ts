import { ArgumentsHost, BadRequestException, HttpException, HttpStatus, NotFoundException } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import { describe, expect, it, vi } from 'vitest';
import { GlobalExceptionFilter } from './global-exception.filter';
import type { RequestWithTraceId } from './http-types';

interface CapturedResponse {
  statusCode: number;
  body: unknown;
}

function makeHost(traceId: string | undefined): { host: ArgumentsHost; captured: CapturedResponse } {
  const captured: CapturedResponse = { statusCode: 0, body: undefined };

  const res = {
    setHeader: vi.fn(),
    end: vi.fn((chunk: string) => {
      captured.body = JSON.parse(chunk) as unknown;
    }),
  } as unknown as ServerResponse;

  Object.defineProperty(res, 'statusCode', {
    get: () => captured.statusCode,
    set: (value: number) => {
      captured.statusCode = value;
    },
  });

  const req = { traceId, headers: {} } as unknown as RequestWithTraceId;

  const host = {
    switchToHttp: () => ({
      getRequest: () => req,
      getResponse: () => res,
    }),
  } as unknown as ArgumentsHost;

  return { host, captured };
}

describe('GlobalExceptionFilter', () => {
  const filter = new GlobalExceptionFilter();

  it('maps an HttpException to { error, trace_id } with its own status code', () => {
    const { host, captured } = makeHost('trace-abc');

    filter.catch(new NotFoundException('resource missing'), host);

    expect(captured.statusCode).toBe(HttpStatus.NOT_FOUND);
    expect(captured.body).toEqual({ error: 'resource missing', trace_id: 'trace-abc' });
  });

  it('joins array-style validation messages from BadRequestException', () => {
    const { host, captured } = makeHost('trace-val');

    filter.catch(new BadRequestException(['field a is required', 'field b is invalid']), host);

    expect(captured.statusCode).toBe(HttpStatus.BAD_REQUEST);
    expect(captured.body).toEqual({
      error: 'field a is required; field b is invalid',
      trace_id: 'trace-val',
    });
  });

  it('maps unknown errors to a generic 500 without leaking internals', () => {
    const { host, captured } = makeHost('trace-500');

    filter.catch(new Error('leaked secret db password'), host);

    expect(captured.statusCode).toBe(HttpStatus.INTERNAL_SERVER_ERROR);
    expect(captured.body).toEqual({ error: 'Internal server error', trace_id: 'trace-500' });
    expect(JSON.stringify(captured.body)).not.toContain('leaked secret');
    expect(JSON.stringify(captured.body)).not.toContain('stack');
  });

  it('falls back to "unknown" trace_id when none was assigned', () => {
    const { host, captured } = makeHost(undefined);

    filter.catch(new HttpException('boom', HttpStatus.BAD_GATEWAY), host);

    expect(captured.body).toEqual({ error: 'boom', trace_id: 'unknown' });
  });
});
