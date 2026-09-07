import type { IncomingMessage } from 'node:http';

/**
 * Typed against Node's built-in `http` types rather than `express.Request`, so
 * the service needs no `@types/express` dependency. The real Express objects
 * satisfy this shape at runtime; this is purely a compile-time narrowing.
 */
export interface RequestWithTraceId extends IncomingMessage {
  traceId?: string;
}
