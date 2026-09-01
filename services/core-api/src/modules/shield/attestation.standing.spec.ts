import { DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS } from '@sentinel/contracts';
import { describe, expect, it } from 'vitest';
import { resolveAttestationStanding, selectAttestationEvidence } from './attestation.standing';

/**
 * WP-24/C16-05 — the effective-attestation resolution, asserted to the
 * millisecond.
 *
 * WHY THIS IS A UNIT SPEC AND THE LIVE SUITE IS NOT
 * ------------------------------------------------
 * The grace boundary is a comparison against the AUTHORITATIVE SERVER CLOCK,
 * and that clock advances between writing a row and reading it. A live test
 * that tried to place an observation at exactly `now - grace` would be racing
 * the database, and an exact-boundary assertion that intermittently passes is
 * worse than no assertion: it reads as precision. So the boundary is asserted
 * HERE, against a pure function with a fixed `now`, and
 * `shield.registry.integration.spec.ts` asserts the BEHAVIOUR the boundary
 * produces — that ageing happens at all, and on the right side of the grace.
 *
 * Nothing below restates a policy. `evaluateAttestationStanding` is still what
 * decides what evidence MEANS; these tests fix which evidence is SELECTED.
 */

const NOW = new Date('2026-09-01T12:00:00.000Z');
const at = (offsetMs: number): Date => new Date(NOW.getTime() + offsetMs);

describe('C16-05 effective attestation resolution', () => {
  it('the grace is INCLUSIVE: exactly as old as the grace is still last-known-good', () => {
    expect(
      resolveAttestationStanding({
        latest: { outcome: 'UNAVAILABLE', evaluatedAt: at(-1) },
        decisive: { outcome: 'VERIFIED', evaluatedAt: at(-DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS) },
        now: NOW,
      }),
    ).toBe('LAST_KNOWN_GOOD');
  });

  it('ONE MILLISECOND past the grace it is EXPIRED, and can no longer carry TRUSTED', () => {
    expect(
      resolveAttestationStanding({
        latest: { outcome: 'UNAVAILABLE', evaluatedAt: at(-1) },
        decisive: { outcome: 'VERIFIED', evaluatedAt: at(-DEVICE_ATTESTATION_UNAVAILABLE_GRACE_MS - 1) },
        now: NOW,
      }),
    ).toBe('EXPIRED');
  });

  it('VERIFIED -> NEGATIVE -> UNAVAILABLE stays NEGATIVE: an outage never resurrects the old positive', () => {
    // The exact history C16-05(b) names. The pre-negative VERIFIED result is
    // still in the table, and it must not be reachable: the newest
    // non-UNAVAILABLE observation is the NEGATIVE one, so that is decisive.
    const evidence = selectAttestationEvidence({
      latest: { outcome: 'UNAVAILABLE', evaluatedAt: at(-1_000) },
      decisive: { outcome: 'NEGATIVE', evaluatedAt: at(-2_000) },
      now: NOW,
    });
    expect(evidence).toEqual({ outcome: 'NEGATIVE', lastVerifiedAt: null, hasPriorVerified: false });
    expect(
      resolveAttestationStanding({
        latest: { outcome: 'UNAVAILABLE', evaluatedAt: at(-1_000) },
        decisive: { outcome: 'NEGATIVE', evaluatedAt: at(-2_000) },
        now: NOW,
      }),
    ).toBe('NEGATIVE');
  });

  it('INVALID and REVOKED are negative evidence too, and an outage does not soften them', () => {
    for (const outcome of ['INVALID', 'REVOKED'] as const) {
      expect(
        resolveAttestationStanding({
          latest: { outcome: 'UNAVAILABLE', evaluatedAt: at(-10) },
          decisive: { outcome, evaluatedAt: at(-20) },
          now: NOW,
        }),
      ).toBe('NEGATIVE');
    }
  });

  it('a NEW verified observation after the negative one restores the positive standing', () => {
    expect(
      resolveAttestationStanding({
        latest: { outcome: 'VERIFIED', evaluatedAt: at(-10) },
        decisive: { outcome: 'VERIFIED', evaluatedAt: at(-10) },
        now: NOW,
      }),
    ).toBe('CURRENT');
  });

  it('a history of nothing but outages is INELIGIBLE, never last-known-good', () => {
    expect(
      resolveAttestationStanding({
        latest: { outcome: 'UNAVAILABLE', evaluatedAt: at(-10) },
        decisive: null,
        now: NOW,
      }),
    ).toBe('INELIGIBLE');
  });

  it('no history at all is INELIGIBLE: an absence of evidence is not evidence', () => {
    expect(resolveAttestationStanding({ latest: null, decisive: null, now: NOW })).toBe('INELIGIBLE');
  });

  it('evidence recorded in the FUTURE fails closed as INCONSISTENT', () => {
    expect(
      resolveAttestationStanding({
        latest: { outcome: 'VERIFIED', evaluatedAt: at(1) },
        decisive: { outcome: 'VERIFIED', evaluatedAt: at(1) },
        now: NOW,
      }),
    ).toBe('INCONSISTENT');

    // Including the case where only the DECISIVE row is impossible.
    expect(
      resolveAttestationStanding({
        latest: { outcome: 'UNAVAILABLE', evaluatedAt: at(-1) },
        decisive: { outcome: 'VERIFIED', evaluatedAt: at(5_000) },
        now: NOW,
      }),
    ).toBe('INCONSISTENT');
  });

  it('a decisive observation NEWER than the latest one is an impossible ordering and fails closed', () => {
    expect(
      resolveAttestationStanding({
        latest: { outcome: 'UNAVAILABLE', evaluatedAt: at(-5_000) },
        decisive: { outcome: 'VERIFIED', evaluatedAt: at(-1_000) },
        now: NOW,
      }),
    ).toBe('INCONSISTENT');
  });

  it('an unparseable instant fails closed rather than being treated as absent', () => {
    expect(
      resolveAttestationStanding({
        latest: { outcome: 'VERIFIED', evaluatedAt: new Date(Number.NaN) },
        decisive: { outcome: 'VERIFIED', evaluatedAt: new Date(Number.NaN) },
        now: NOW,
      }),
    ).toBe('INCONSISTENT');
  });
});
