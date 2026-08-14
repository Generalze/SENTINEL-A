import type { NormalisedEvent } from '@sentinel/contracts';

/**
 * A NormalisedEvent template (WP-10 deliverable 1).
 *
 * Structurally identical to `NormalisedEvent`, but string fields MAY hold an
 * unresolved placeholder token instead of a final value:
 *
 *   {ORG}             -> options.orgId
 *   {SITE}             -> options.siteId
 *   {ZONE:name}         -> options.zoneIds[name]
 *   {TRACE}             -> the run's shared trace_id
 *   {NOW+offsetMs}       -> ISO timestamp = run-start + offsetMs (offsetMs may be negative)
 *
 * Placeholders are resolved by `resolveEventTemplate` at run time and the
 * result is validated against `NormalisedEventSchema` BEFORE it is ever
 * posted anywhere — the simulator cannot emit an event that fails contracts
 * validation.
 */
export type EventTemplate = NormalisedEvent;

/** One step in a scenario: an event template fired `at_offset_ms` after run start. */
export interface ScenarioStep {
  readonly at_offset_ms: number;
  readonly event: EventTemplate;
}

/** An ordered, versioned sequence of scenario steps (WP-10 deliverable 1). */
export interface Scenario {
  readonly name: string;
  readonly version: number;
  readonly description: string;
  readonly steps: readonly ScenarioStep[];
}

/** Run-time values used to resolve placeholders embedded in event templates. */
export interface ScenarioContext {
  readonly orgId: string;
  readonly siteId: string;
  readonly zoneIds: Readonly<Record<string, string>>;
  readonly traceId: string;
  readonly runStart: Date;
}

const PLACEHOLDER_RE = /\{ORG\}|\{SITE\}|\{TRACE\}|\{ZONE:([A-Za-z0-9_-]+)\}|\{NOW([+-]\d+)\}/g;

/**
 * Resolves every placeholder token in a single string against `ctx`.
 * Unrecognised `{...}`-shaped text that doesn't match a known token is left
 * untouched (it will simply fail schema validation downstream, which is the
 * intended fail-safe behaviour).
 */
export function resolvePlaceholders(value: string, ctx: ScenarioContext): string {
  return value.replace(PLACEHOLDER_RE, (match, zoneName?: string, nowOffset?: string) => {
    if (match === '{ORG}') {
      return ctx.orgId;
    }
    if (match === '{SITE}') {
      return ctx.siteId;
    }
    if (match === '{TRACE}') {
      return ctx.traceId;
    }
    if (zoneName !== undefined) {
      const zoneId = ctx.zoneIds[zoneName];
      if (zoneId === undefined) {
        throw new Error(
          `Scenario references unknown zone placeholder "{ZONE:${zoneName}}" — pass its id via the zoneIds option.`
        );
      }
      return zoneId;
    }
    if (nowOffset !== undefined) {
      const offsetMs = Number(nowOffset);
      return new Date(ctx.runStart.getTime() + offsetMs).toISOString();
    }
    return match;
  });
}

function resolveDeep(value: unknown, ctx: ScenarioContext): unknown {
  if (typeof value === 'string') {
    return resolvePlaceholders(value, ctx);
  }
  if (Array.isArray(value)) {
    return value.map((item) => resolveDeep(item, ctx));
  }
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = resolveDeep(item, ctx);
    }
    return out;
  }
  return value;
}

/**
 * Resolves every placeholder in an event template against a run context.
 *
 * The return type is intentionally `unknown`, not `NormalisedEvent`: a
 * resolved template is only a *candidate* event. Callers MUST run it through
 * `NormalisedEventSchema.safeParse`/`.parse` before treating it as real or
 * sending it anywhere — that is what makes it structurally impossible for
 * the simulator to emit an invalid event.
 */
export function resolveEventTemplate(template: EventTemplate, ctx: ScenarioContext): unknown {
  return resolveDeep(template, ctx);
}
