import type { ServerResponse } from 'node:http';
import type { NormalisedEvent } from '@sentinel/contracts';
import { loadConfig, type AppConfig } from '../../config/env.schema';
import type { AppConfigService } from '../../config/config.service';
import { buildPrincipal, type RequestWithPrincipal } from '../../common/security/principal';
import { CORRELATION_WINDOW_MS } from './fusion.constants';

/**
 * Test-only support for this module's specs. Not a `*.spec.ts` file, so
 * vitest does not try to run it.
 *
 * Deliberately self-contained rather than importing the events module's
 * equivalent helper: the two modules are separate work-package lanes, and a
 * shared test helper would make one lane's refactor break the other's suite.
 *
 * Collaborators are constructed by hand — the same approach the rest of this
 * repo's provider tests take (see src/infra/nats.provider.spec.ts) — instead
 * of booting the full Nest container, so a spec exercises exactly the objects
 * it names.
 */
/**
 * Dev-stack environment, as raw strings.
 *
 * Deliberately fed through the real `loadConfig` rather than hand-writing an
 * `AppConfig` literal: several work packages are adding keys to the shared env
 * schema concurrently, and any key they add WITH a default is picked up here
 * automatically instead of breaking this module's build. A key added WITHOUT a
 * default still fails loudly, which is the correct outcome — it means the dev
 * stack genuinely needs a new value.
 */
const BASE_ENV: Record<string, string> = {
  DATABASE_URL: 'postgresql://sentinel:sentinel@localhost:5433/sentinel',
  NATS_URL: 'nats://localhost:4222',
  REDIS_URL: 'redis://localhost:6379',
  S3_ENDPOINT: 'http://localhost:9000',
  S3_ACCESS_KEY: 'sentinel',
  S3_SECRET_KEY: 'sentinel123',
  S3_BUCKET: 'sentinel-dev',
  S3_REGION: 'us-east-1',
  PORT: '3000',
  LOG_LEVEL: 'info',
  DEV_AUTH_ENABLED: 'false',
};

export function makeAppConfig(overrides: Partial<AppConfig> = {}): AppConfigService {
  const values: AppConfig = { ...loadConfig(BASE_ENV), ...overrides };
  return { values } as AppConfigService;
}

let counter = 0;

function nextSuffix(): string {
  counter += 1;
  return `${Date.now().toString(36)}_${process.pid}_${counter}`;
}

/**
 * A fresh organisation id per test. Integration specs in this module all run
 * against the shared live Postgres, and other work packages are writing to it
 * concurrently, so every test invents its own tenant rather than filtering
 * shared fixtures — no test can then see another's rows.
 */
export function uniqueOrgId(label: string): string {
  return `org_wp05_${label}_${nextSuffix()}`;
}

export function uniqueSiteId(label: string): string {
  return `site_wp05_${label}_${nextSuffix()}`;
}

/**
 * Start of a correlation window that comfortably contains every event a
 * scenario emits.
 *
 * Anchored to the CURRENT window's start plus a minute of headroom: all
 * scenario events then share one window regardless of when in real time the
 * suite happens to run, without any test needing to reason about boundaries.
 */
export function scenarioWindowBase(): Date {
  const windowStart = Math.floor(Date.now() / CORRELATION_WINDOW_MS) * CORRELATION_WINDOW_MS;
  return new Date(windowStart + 60_000);
}

export interface EventOverrides extends Partial<Omit<NormalisedEvent, 'metadata'>> {
  metadata?: Record<string, unknown>;
}

let eventCounter = 0;

/**
 * Builds a valid Normalised Event (§40). Every field a scenario cares about
 * is overridable; the defaults are a plain trusted camera detection.
 */
export function makeEvent(overrides: EventOverrides = {}): NormalisedEvent {
  eventCounter += 1;
  const occurredAt = overrides.occurred_at ?? new Date().toISOString();
  return {
    event_id: `evt_wp05_${nextSuffix()}_${eventCounter}`,
    schema_version: 1,
    organisation_id: 'org_default',
    site_id: 'site_default',
    zone_id: 'zone_default',
    source_type: 'camera',
    source_id: 'camera-default',
    source_trust: 'trusted',
    event_type: 'person_detected',
    confidence: 0.5,
    occurred_at: occurredAt,
    // Equal to occurred_at satisfies the contract's ingested_at >= occurred_at
    // rule for scenario timestamps that sit slightly in the future.
    ingested_at: overrides.ingested_at ?? occurredAt,
    location: {},
    track_ids: [],
    evidence_refs: [],
    metadata: {},
    trace_id: `trace_wp05_${eventCounter}`,
    ...overrides,
  } as NormalisedEvent;
}

export function principalRequest(organisationId: string, traceId = 'wp05-trace'): RequestWithPrincipal {
  return {
    traceId,
    principal: buildPrincipal({
      user: { id: `user_${organisationId}`, clearance: 5 },
      organisation_id: organisationId,
      roles: [{ role: 'investigator', site_id: null }],
    }),
  } as unknown as RequestWithPrincipal;
}

/** A request with no principal, exercising the TODO-WIRED dev-bypass path. */
export function anonymousRequest(traceId = 'wp05-trace'): RequestWithPrincipal {
  return { traceId } as unknown as RequestWithPrincipal;
}

export function makeCapturingRes(): ServerResponse & { statusCode: number; body?: string } {
  const res = {
    setHeader: () => undefined,
    end: function end(this: { body?: string }, chunk: string) {
      this.body = chunk;
    },
    statusCode: 0,
  };
  return res as unknown as ServerResponse & { statusCode: number; body?: string };
}

/** Polls `check` until it returns true or `timeoutMs` elapses. */
export async function waitUntil(check: () => Promise<boolean>, timeoutMs: number, intervalMs = 150): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await check()) {
      return true;
    }
    if (Date.now() >= deadline) {
      return false;
    }
    await new Promise((resolve) => {
      globalThis.setTimeout(resolve, intervalMs);
    });
  }
}
