import { ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus, Logger } from '@nestjs/common';
import type { ServerResponse } from 'node:http';
import type { RequestWithTraceId } from './http-types';

interface ErrorResponseBody {
  error: string;
  trace_id: string;
}

function extractMessage(exceptionResponse: unknown, fallback: string): string {
  if (typeof exceptionResponse === 'string') {
    return exceptionResponse;
  }
  if (exceptionResponse !== null && typeof exceptionResponse === 'object' && 'message' in exceptionResponse) {
    const { message } = exceptionResponse as { message: unknown };
    if (typeof message === 'string') {
      return message;
    }
    if (Array.isArray(message)) {
      const parts = message.filter((entry): entry is string => typeof entry === 'string');
      if (parts.length > 0) {
        return parts.join('; ');
      }
    }
  }
  return fallback;
}

/**
 * Catches everything (HttpException and unknown errors alike) and always
 * responds with `{ error, trace_id }`. Stack traces / internal error
 * details are logged server-side (via the pino-backed Nest Logger) but
 * never included in the response body.
 */
@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(GlobalExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<ServerResponse>();
    const request = ctx.getRequest<RequestWithTraceId>();
    const traceId = request.traceId ?? 'unknown';

    const status = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
    const message =
      exception instanceof HttpException
        ? extractMessage(exception.getResponse(), exception.message)
        : 'Internal server error';

    if (status >= HttpStatus.INTERNAL_SERVER_ERROR) {
      const error = exception instanceof Error ? exception : new Error(String(exception));
      this.logger.error(`Unhandled exception [trace_id=${traceId}]: ${error.message}`, error.stack);
    }

    const body: ErrorResponseBody = { error: message, trace_id: traceId };
    response.statusCode = status;
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify(body));
  }
}
