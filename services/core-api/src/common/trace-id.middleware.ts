import { randomUUID } from 'node:crypto';
import type { ServerResponse } from 'node:http';
import type { RequestWithTraceId } from './http-types';

export const TRACE_ID_HEADER = 'x-trace-id';

/**
 * Registered as raw Express middleware (via `app.use`) before pino-http's
 * own middleware, so it is the single source of truth for the request's
 * trace id: honour an inbound `x-trace-id`, otherwise generate one, stash
 * it on the request for downstream consumers (logger, exception filter),
 * and echo it back as a response header immediately.
 */
export function traceIdMiddleware(req: RequestWithTraceId, res: ServerResponse, next: () => void): void {
  const inbound = req.headers[TRACE_ID_HEADER];
  const inboundValue = Array.isArray(inbound) ? inbound[0] : inbound;
  const traceId = inboundValue && inboundValue.trim().length > 0 ? inboundValue : randomUUID();

  req.traceId = traceId;
  res.setHeader(TRACE_ID_HEADER, traceId);
  next();
}
