import { NormalisedEventSchema, type NormalisedEvent } from '@sentinel/contracts';
import { resolveEventTemplate, type Scenario, type ScenarioContext } from './scenario.js';

export type FetchLike = typeof fetch;

export interface RunScenarioOptions {
  /** Base URL of the ingestion API, e.g. "http://localhost:3000". */
  readonly baseUrl: string;
  readonly orgId: string;
  readonly siteId: string;
  /** Maps a scenario's `{ZONE:name}` tokens to real zone ids. */
  readonly zoneIds?: Readonly<Record<string, string>>;
  /** Extra headers (e.g. Authorization) sent with every POST. */
  readonly apiHeaders?: Readonly<Record<string, string>>;
  /**
   * Playback speed multiplier. 1 = real time, 2 = twice as fast, etc.
   * `Infinity` sends events as fast as possible while still preserving
   * their relative order. Defaults to 1.
   */
  readonly speed?: number;
  /** Shared trace_id for the run. Defaults to a generated value. */
  readonly traceId?: string;
  /** Max retry attempts for a transient (network error / 5xx) delivery failure. Default 3. */
  readonly maxRetries?: number;
  /** Base delay for exponential retry backoff, in ms (scaled by `speed`). Default 200. */
  readonly retryBaseDelayMs?: number;
  /** Injectable fetch implementation, primarily for tests. Defaults to global fetch. */
  readonly fetchImpl?: FetchLike;
  /** Injectable clock, primarily for tests. Defaults to `() => new Date()`. */
  readonly now?: () => Date;
}

export interface EventDeliveryResult {
  readonly step_index: number;
  readonly event_id: string;
  readonly offset_ms: number;
  readonly sent_at: string;
  readonly ok: boolean;
  readonly status?: number;
  readonly attempts: number;
  readonly duplicate?: boolean;
  readonly original_event_id?: string;
  readonly error?: string;
  readonly response?: unknown;
}

export interface ScenarioRunResult {
  readonly scenario_name: string;
  readonly scenario_version: number;
  readonly trace_id: string;
  readonly run_start: string;
  readonly results: EventDeliveryResult[];
}

const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_RETRY_BASE_DELAY_MS = 200;

/**
 * Waits `ms` milliseconds. Any non-positive or non-finite `ms` (including
 * the result of `x / Infinity`, which is always 0 for finite `x`) resolves
 * on the next `setImmediate` tick instead of a timer, so `speed: Infinity`
 * playback is bounded only by event-loop/network throughput while still
 * preserving send order.
 */
export function delay(ms: number): Promise<void> {
  if (!Number.isFinite(ms) || ms <= 0) {
    return new Promise((resolve) => setImmediate(resolve));
  }
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

interface PostOutcome {
  readonly ok: boolean;
  readonly status?: number;
  readonly attempts: number;
  readonly duplicate?: boolean;
  readonly original_event_id?: string;
  readonly error?: string;
  readonly response?: unknown;
}

async function postEventWithRetry(
  url: string,
  event: NormalisedEvent,
  headers: Readonly<Record<string, string>>,
  maxRetries: number,
  retryBaseDelayMs: number,
  speed: number,
  fetchImpl: FetchLike
): Promise<PostOutcome> {
  let attempt = 0;

  for (;;) {
    attempt++;
    try {
      const res = await fetchImpl(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify(event),
      });

      let body: unknown;
      try {
        body = await res.json();
      } catch {
        body = undefined;
      }

      if (res.status >= 500) {
        if (attempt > maxRetries) {
          return {
            ok: false,
            status: res.status,
            attempts: attempt,
            error: `HTTP ${res.status} after ${attempt} attempt(s)`,
            response: body,
          };
        }
        await delay((retryBaseDelayMs * 2 ** (attempt - 1)) / speed);
        continue;
      }

      if (res.status >= 200 && res.status < 300) {
        const duplicate = isRecord(body) && body.duplicate === true;
        const originalEventId =
          isRecord(body) && typeof body.original_event_id === 'string' ? body.original_event_id : undefined;
        return { ok: true, status: res.status, attempts: attempt, duplicate, original_event_id: originalEventId, response: body };
      }

      // 4xx (validation, auth, org-mismatch, ...): terminal, not retried.
      return { ok: false, status: res.status, attempts: attempt, error: `HTTP ${res.status}`, response: body };
    } catch (err) {
      if (attempt > maxRetries) {
        return {
          ok: false,
          attempts: attempt,
          error: err instanceof Error ? err.message : String(err),
        };
      }
      await delay((retryBaseDelayMs * 2 ** (attempt - 1)) / speed);
    }
  }
}

/**
 * Runs a scenario: resolves each step's event template, validates it against
 * the real contracts schema, and POSTs it to `${baseUrl}/api/v1/events` at
 * its scheduled offset (scaled by `speed`), retrying transient failures with
 * backoff. Returns one delivery result per step, in step order.
 */
export async function runScenario(scenario: Scenario, options: RunScenarioOptions): Promise<ScenarioRunResult> {
  const speed = options.speed ?? 1;
  if (!(speed > 0)) {
    throw new RangeError('speed must be a positive number (or Infinity)');
  }

  for (let i = 1; i < scenario.steps.length; i++) {
    if (scenario.steps[i].at_offset_ms < scenario.steps[i - 1].at_offset_ms) {
      throw new Error(
        `Scenario "${scenario.name}" steps must be ordered by non-decreasing at_offset_ms ` +
          `(step ${i} at ${scenario.steps[i].at_offset_ms}ms precedes step ${i - 1} at ${scenario.steps[i - 1].at_offset_ms}ms).`
      );
    }
  }

  const fetchImpl = options.fetchImpl ?? fetch;
  const nowFn = options.now ?? (() => new Date());
  const runStart = nowFn();
  const traceId = options.traceId ?? `trace_${scenario.name}_${runStart.getTime()}`;
  const maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
  const retryBaseDelayMs = options.retryBaseDelayMs ?? DEFAULT_RETRY_BASE_DELAY_MS;
  const headers = options.apiHeaders ?? {};

  const ctx: ScenarioContext = {
    orgId: options.orgId,
    siteId: options.siteId,
    zoneIds: options.zoneIds ?? {},
    traceId,
    runStart,
  };

  const url = new URL('/api/v1/events', options.baseUrl).toString();
  const results: EventDeliveryResult[] = [];
  let previousOffsetMs = 0;

  for (let index = 0; index < scenario.steps.length; index++) {
    const step = scenario.steps[index];
    const offsetDiffMs = index === 0 ? step.at_offset_ms : step.at_offset_ms - previousOffsetMs;
    previousOffsetMs = step.at_offset_ms;

    await delay(offsetDiffMs / speed);

    const resolved = resolveEventTemplate(step.event, ctx);
    const parsed = NormalisedEventSchema.safeParse(resolved);

    if (!parsed.success) {
      const eventId = isRecord(resolved) && typeof resolved.event_id === 'string' ? resolved.event_id : `step-${index}`;
      results.push({
        step_index: index,
        event_id: eventId,
        offset_ms: step.at_offset_ms,
        sent_at: new Date().toISOString(),
        ok: false,
        attempts: 0,
        error: `Resolved event failed contracts validation and was never sent: ${parsed.error.message}`,
      });
      continue;
    }

    const outcome = await postEventWithRetry(url, parsed.data, headers, maxRetries, retryBaseDelayMs, speed, fetchImpl);
    results.push({
      step_index: index,
      event_id: parsed.data.event_id,
      offset_ms: step.at_offset_ms,
      sent_at: new Date().toISOString(),
      ...outcome,
    });
  }

  return {
    scenario_name: scenario.name,
    scenario_version: scenario.version,
    trace_id: traceId,
    run_start: runStart.toISOString(),
    results,
  };
}
