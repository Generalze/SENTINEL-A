import type { IncomingMessage } from 'node:http';

/**
 * We deliberately type against Node's built-in `http` types instead of
 * `express.Request`/`express.Response` so the service does not need a
 * `@types/express` devDependency (not on the approved dependency list).
 * The real Express request/response objects satisfy this shape at
 * runtime, so this is purely a compile-time narrowing.
 */
export interface RequestWithTraceId extends IncomingMessage {
  traceId?: string;
}
