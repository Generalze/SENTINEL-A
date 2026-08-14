import type { IncomingMessage } from 'node:http';
import type { Principal } from './principal';

/**
 * Like `../common/http-types`'s `RequestWithTraceId`, this types against
 * Node's built-in `http` request instead of `express.Request` so the
 * service does not need a `@types/express` devDependency. Express adds
 * `params`/`query`/`body` at runtime; this interface just declares that
 * shape for compile-time use in guards/controllers.
 */
export interface RequestWithPrincipal extends IncomingMessage {
  params: Record<string, string>;
  query: Record<string, string | string[] | undefined>;
  body: unknown;
  traceId?: string;
  /** Set by DevAuthGuard once the caller is authenticated. */
  principal?: Principal;
}
