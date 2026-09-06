import { randomUUID } from 'node:crypto';
import type { ServerResponse } from 'node:http';
import type { RequestWithTraceId } from './http-types';

export const TRACE_ID_HEADER = 'x-trace-id';

/**
 * Registered as raw middleware before pino-http, so it is the single source of
 * truth for the request's trace id by the time anything logs.
 *
 * An inbound `x-trace-id` is honoured deliberately: Edge sits BETWEEN a Field
 * device and central, and a trace that restarts at the site boundary is a trace
 * that cannot answer "where did this operation go" — which is the only question
 * anyone asks of an Edge log.
 */
export function traceIdMiddleware(req: RequestWithTraceId, res: ServerResponse, next: () => void): void {
  const inbound = req.headers[TRACE_ID_HEADER];
  const inboundValue = Array.isArray(inbound) ? inbound[0] : inbound;
  const traceId = inboundValue && inboundValue.trim().length > 0 ? inboundValue : randomUUID();

  req.traceId = traceId;
  res.setHeader(TRACE_ID_HEADER, traceId);
  next();
}
