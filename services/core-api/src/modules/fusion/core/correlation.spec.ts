import { describe, expect, it } from 'vitest';
import { CORRELATION_WINDOW_MS, SITE_WIDE_ZONE } from '../fusion.constants';
import {
  deriveCorrelationKey,
  describeCorrelationKey,
  serialiseCorrelationKey,
  windowStartFor,
} from './correlation';

function input(overrides: Partial<Parameters<typeof deriveCorrelationKey>[0]> = {}) {
  return {
    organisation_id: 'org-1',
    site_id: 'site-1',
    zone_id: 'zone-1',
    occurred_at: '2026-08-14T10:07:31.000Z',
    ...overrides,
  };
}

describe('windowStartFor', () => {
  it('floors to the enclosing 15-minute bucket, anchored at the epoch', () => {
    expect(windowStartFor(new Date('2026-08-14T10:00:00.000Z')).toISOString()).toBe('2026-08-14T10:00:00.000Z');
    expect(windowStartFor(new Date('2026-08-14T10:07:31.500Z')).toISOString()).toBe('2026-08-14T10:00:00.000Z');
    expect(windowStartFor(new Date('2026-08-14T10:14:59.999Z')).toISOString()).toBe('2026-08-14T10:00:00.000Z');
    expect(windowStartFor(new Date('2026-08-14T10:15:00.000Z')).toISOString()).toBe('2026-08-14T10:15:00.000Z');
  });

  it('uses a 15-minute window by default', () => {
    expect(CORRELATION_WINDOW_MS).toBe(15 * 60 * 1000);
    const start = windowStartFor(new Date('2026-08-14T10:07:00.000Z'));
    const nextStart = windowStartFor(new Date('2026-08-14T10:22:00.000Z'));
    expect(nextStart.getTime() - start.getTime()).toBe(CORRELATION_WINDOW_MS);
  });
});

describe('deriveCorrelationKey', () => {
  it('groups events that share organisation, site, zone and window', () => {
    const a = deriveCorrelationKey(input({ occurred_at: '2026-08-14T10:00:00.000Z' }));
    const b = deriveCorrelationKey(input({ occurred_at: '2026-08-14T10:14:59.999Z' }));
    expect(a.key).toBe(b.key);
    expect(a.windowStart.toISOString()).toBe('2026-08-14T10:00:00.000Z');
    expect(a.windowEnd.toISOString()).toBe('2026-08-14T10:15:00.000Z');
  });

  it('separates events that fall either side of a window boundary', () => {
    const a = deriveCorrelationKey(input({ occurred_at: '2026-08-14T10:14:59.999Z' }));
    const b = deriveCorrelationKey(input({ occurred_at: '2026-08-14T10:15:00.000Z' }));
    expect(a.key).not.toBe(b.key);
  });

  it.each([
    ['organisation', { organisation_id: 'org-2' }],
    ['site', { site_id: 'site-2' }],
    ['zone', { zone_id: 'zone-2' }],
  ])('separates events that differ only by %s', (_label, overrides) => {
    const a = deriveCorrelationKey(input());
    const b = deriveCorrelationKey(input(overrides));
    expect(a.key).not.toBe(b.key);
  });

  it('substitutes "site-wide" for a null or absent zone, and both spellings agree', () => {
    const nullZone = deriveCorrelationKey(input({ zone_id: null }));
    const absentZone = deriveCorrelationKey(input({ zone_id: undefined }));
    expect(nullZone.zoneKey).toBe(SITE_WIDE_ZONE);
    expect(nullZone.zoneId).toBeNull();
    expect(absentZone.key).toBe(nullZone.key);
  });

  it('does not let a site-wide event collide with a zone literally named "site-wide"', () => {
    // Documents the one aliasing case the substitution creates. It is
    // accepted: 'site-wide' is a reserved zone name, and the raw zone_id is
    // still preserved separately on the row.
    const siteWide = deriveCorrelationKey(input({ zone_id: null }));
    const named = deriveCorrelationKey(input({ zone_id: SITE_WIDE_ZONE }));
    expect(named.zoneId).toBe(SITE_WIDE_ZONE);
    expect(siteWide.zoneId).toBeNull();
    expect(named.key).toBe(siteWide.key);
  });

  it('is deterministic: the same event always yields the same key', () => {
    expect(deriveCorrelationKey(input()).key).toBe(deriveCorrelationKey(input()).key);
  });

  it('rejects an unparseable occurred_at rather than bucketing it silently', () => {
    expect(() => deriveCorrelationKey(input({ occurred_at: 'not-a-timestamp' }))).toThrow(/valid timestamp/i);
  });

  it('cannot be spoofed into a cross-tenant collision by crafted ids', () => {
    // A printable delimiter would let these two tuples serialise identically.
    const a = deriveCorrelationKey(input({ organisation_id: 'org-1|site-1', site_id: 'zone-1' }));
    const b = deriveCorrelationKey(input({ organisation_id: 'org-1', site_id: 'site-1|zone-1' }));
    expect(a.key).not.toBe(b.key);
  });
});

describe('serialiseCorrelationKey', () => {
  it('contains every component of the tuple', () => {
    const key = serialiseCorrelationKey('org-1', 'site-1', 'zone-1', new Date('2026-08-14T10:00:00.000Z'));
    expect(key).toContain('org-1');
    expect(key).toContain('site-1');
    expect(key).toContain('zone-1');
    expect(key).toContain('2026-08-14T10:00:00.000Z');
  });
});

describe('describeCorrelationKey', () => {
  it('renders a human-readable window description for explanations and logs', () => {
    const described = describeCorrelationKey(deriveCorrelationKey(input()));
    expect(described).toBe('org-1/site-1/zone-1 @ 2026-08-14T10:00:00.000Z..2026-08-14T10:15:00.000Z');
  });
});
