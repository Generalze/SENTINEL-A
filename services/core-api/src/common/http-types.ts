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
  /**
   * The exact request bytes, when the application was created with
   * `rawBody: true`.
   *
   * Present for the Edge ingress, which must digest what the caller SIGNED
   * rather than a re-serialisation of the parsed object. Optional because a
   * request that never had a body has none, and because a test harness may
   * build an application without the flag -- a consumer that finds it absent
   * must refuse, never fall back to re-encoding.
   */
  rawBody?: Buffer;
}
