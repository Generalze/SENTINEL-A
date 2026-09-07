import { describe, expect, it, vi } from 'vitest';
import {
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
  DEVICE_TIME_NOT_AUTHORITATIVE,
  DevicePolicyLeaseSchema,
  EdgeTrustedTimeAnchorStatementSchema,
  type DevicePolicyLease,
  type EdgeTrustedTimeAnchorStatement,
} from '@sentinel/contracts';
import { EdgeTrustedTimeAnchor, type EdgeMonotonicReading } from './edge-trusted-time.anchor';
import { EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS } from '../../edge-runtime.constants';
import { VolatileEdgeTrustedTimeAnchorStore } from './edge-trusted-time.store';

/**
 * WP-29B / EDGE-C Crucible — the trusted-time anchor.
 *
 * There is no clock in this file. Every instant is a literal and every
 * monotonic reading is a number a test chose, which is the property the whole
 * design exists to have: if this suite needed a clock, the anchor would be
 * reading one.
 */

const SERVER_TIME = '2026-08-29T12:00:00.000Z';
const BOOT_ID = 'boot-4f2a';
const HOUR = 3_600_000;
const MINUTE = 60_000;

/**
 * The anchor is now the FROZEN, centrally signed statement. This helper builds
 * one that has already been verified — admitting it is
 * `EdgeTrustedTimeAnchorVerifier`'s job and has its own Crucible. What is under
 * test here is the arithmetic and the boundaries, unchanged from round 1.
 *
 * `holdoverMs` becomes the distance between the two signed instants, so the
 * old `holdover_ms` cases below are expressed as a `server_valid_until`.
 */
function anchorRecord(overrides: Record<string, unknown> = {}): EdgeTrustedTimeAnchorStatement {
  return EdgeTrustedTimeAnchorStatementSchema.parse({
    schema_version: 1,
    anchor_id: '9c4e1f80-1a2b-4c3d-8e5f-6a7b8c9d0e1f',
    edge_id: 'edge-17',
    organisation_id: 'org-1',
    site_id: 'site-1',
    edge_boot_id: BOOT_ID,
    edge_monotonic_at_anchor: 1_000_000,
    server_issued_at: SERVER_TIME,
    server_valid_until: iso(EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS),
    signer_key_id: 'central-tta-2026-01',
    ...overrides,
  });
}

/** Expresses an old `holdover_ms` case as the signed window it now is. */
function holdover(ms: number): Record<string, unknown> {
  return { server_valid_until: iso(ms) };
}

/** A reading `elapsedMs` after the anchor was issued, in the same boot. */
function reading(elapsedMs: number, bootId: string = BOOT_ID): EdgeMonotonicReading {
  return { monotonic_ms: 1_000_000 + elapsedMs, boot_id: bootId };
}

function iso(deltaMs: number): string {
  return new Date(Date.parse(SERVER_TIME) + deltaMs).toISOString();
}

function lease(overrides: Partial<DevicePolicyLease> = {}): DevicePolicyLease {
  return DevicePolicyLeaseSchema.parse({
    schema_version: 1,
    lease_id: 'lease-1',
    organisation_id: 'org-1',
    site_id: 'site-1',
    device_id: 'device-1',
    actor_user_id: 'user-1',
    authority_basis_id: 'grant-1',
    scope: ['FIELD_ASSIGNMENT_START'],
    issued_at: iso(-HOUR),
    expires_at: iso(HOUR),
    ...overrides,
  });
}

// ---------------------------------------------------------------------------

describe('the signed anchor refuses what central may not issue', () => {
  it('accepts the frozen lease ceiling as a lifetime', () => {
    expect(new EdgeTrustedTimeAnchor(anchorRecord()).lifetimeMs).toBe(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS);
  });

  it('refuses a lifetime one millisecond above the ceiling', () => {
    // Refused rather than clamped: silently shortening an over-long anchor
    // would hide a central-side defect behind an Edge that looks healthy. And
    // because central parses before it signs, such an anchor never acquires a
    // signature in the first place.
    const result = EdgeTrustedTimeAnchorStatementSchema.safeParse({
      ...anchorRecord(),
      server_valid_until: iso(EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS + 1),
    });
    expect(result.success).toBe(false);
  });

  it('accepts a SHORTER lifetime, because central may choose one', () => {
    expect(new EdgeTrustedTimeAnchor(anchorRecord(holdover(5 * MINUTE))).lifetimeMs).toBe(5 * MINUTE);
  });

  it('refuses a zero-length or inverted window', () => {
    for (const validUntil of [SERVER_TIME, iso(-1)]) {
      expect(
        EdgeTrustedTimeAnchorStatementSchema.safeParse({ ...anchorRecord(), server_valid_until: validUntil }).success,
      ).toBe(false);
    }
  });

  it('refuses an anchor carrying a field central could use to relax a rule', () => {
    for (const field of ['allow_wall_clock', 'edge_trust', 'trusted', 'override_holdover', 'fallback_time', 'holdover_ms']) {
      expect(EdgeTrustedTimeAnchorStatementSchema.safeParse({ ...anchorRecord(), [field]: true }).success).toBe(false);
    }
  });

  it('reads a bad anchor as no anchor rather than throwing', () => {
    // The caller's correct response to a bad anchor is identical to its
    // response to no anchor. The safe parse is the reader now — there is no
    // local shape left for a hand-rolled one to read.
    expect(EdgeTrustedTimeAnchorStatementSchema.safeParse({ nonsense: true }).success).toBe(false);
    expect(EdgeTrustedTimeAnchorStatementSchema.safeParse(anchorRecord()).success).toBe(true);
  });
});

describe('valid anchor arithmetic', () => {
  it('carries central time forward by the monotonic interval alone', () => {
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    expect(anchor.classify(reading(90 * MINUTE))).toBe('VALID');
    expect(anchor.trustedNow(reading(90 * MINUTE))).toBe(iso(90 * MINUTE));
  });

  it('answers the anchor instant exactly when no time has elapsed', () => {
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    expect(anchor.trustedNow(reading(0))).toBe(SERVER_TIME);
  });

  it('is monotone in the reading: later readings never answer earlier times', () => {
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    let previous = Number.NEGATIVE_INFINITY;
    for (const elapsed of [0, 1, 999, MINUTE, HOUR, 5 * HOUR]) {
      const answer = anchor.trustedNow(reading(elapsed));
      expect(answer).not.toBeNull();
      const ms = Date.parse(answer as string);
      expect(ms).toBeGreaterThan(previous);
      previous = ms;
    }
  });

  it('NEVER reads the host wall clock', () => {
    // The load-bearing behavioural proof. A wall clock on a site appliance is
    // settable; an anchor that consulted one could be moved backwards four
    // hours by anyone with physical access, and would then place today's
    // operations inside yesterday's expired lease.
    const nowSpy = vi.spyOn(Date, 'now');
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    anchor.classify(reading(MINUTE));
    anchor.trustedNow(reading(MINUTE));
    anchor.evaluateOperationWitness(lease(), reading(MINUTE));
    expect(nowSpy).not.toHaveBeenCalled();
    nowSpy.mockRestore();
  });

  it('answers identically however many times it is asked with the same reading', () => {
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    const at = reading(17 * MINUTE);
    expect(anchor.trustedNow(at)).toBe(anchor.trustedNow(at));
  });
});

describe('expiry at exactly the ceiling', () => {
  it('is VALID one millisecond before the holdover elapses', () => {
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    expect(anchor.classify(reading(EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS - 1))).toBe('VALID');
    expect(anchor.trustedNow(reading(EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS - 1))).not.toBeNull();
  });

  it('is EXPIRED at exactly the holdover, because the boundary is exclusive', () => {
    // C15-07's rule, applied here: `elapsed >= holdover` is expired, matching
    // `isExpiredAt` everywhere else. At the boundary the two mistakes are not
    // symmetrical — refusing a millisecond early costs a visible refusal,
    // admitting a millisecond late vouches for time nobody re-established.
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    expect(anchor.classify(reading(EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS))).toBe('ANCHOR_EXPIRED');
    expect(anchor.trustedNow(reading(EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS))).toBeNull();
  });

  it('is EXPIRED past the holdover', () => {
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    expect(anchor.classify(reading(EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS + HOUR))).toBe('ANCHOR_EXPIRED');
  });

  it('honours a SHORTER central-issued holdover at its own exact boundary', () => {
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord(holdover(5 * MINUTE)));
    expect(anchor.classify(reading(5 * MINUTE - 1))).toBe('VALID');
    expect(anchor.classify(reading(5 * MINUTE))).toBe('ANCHOR_EXPIRED');
  });

  it('cannot be carried past the frozen lease ceiling by any admissible anchor', () => {
    // The ceiling IS `DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS`, imported rather
    // than restated, so the two cannot drift apart.
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    expect(anchor.trustedNow(reading(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS))).toBeNull();
  });
});

describe('a boot identity change invalidates the anchor', () => {
  it('classifies BOOT_IDENTITY_CHANGED even well inside the holdover', () => {
    // FW2-10: after a reboot the monotonic counter refers to a counter that no
    // longer exists. Edge keeps its durable queue but must not manufacture
    // trusted time from a new wall clock to go with it.
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    expect(anchor.classify(reading(MINUTE, 'boot-NEW'))).toBe('BOOT_IDENTITY_CHANGED');
  });

  it('emits null trusted time after a reboot', () => {
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    expect(anchor.trustedNow(reading(MINUTE, 'boot-NEW'))).toBeNull();
  });

  it('checks the boot identity BEFORE the interval, so a reset counter cannot look valid', () => {
    // The dangerous case: the new boot's counter is SMALLER than the anchor's,
    // so the interval is negative and would push trusted time BACKWARDS. That
    // must read as a reboot, not as a broken clock and not as a valid anchor.
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    const freshBoot: EdgeMonotonicReading = { monotonic_ms: 12, boot_id: 'boot-NEW' };
    expect(anchor.classify(freshBoot)).toBe('BOOT_IDENTITY_CHANGED');
    expect(anchor.trustedNow(freshBoot)).toBeNull();
  });

  it('refuses to witness an operation after a reboot however live its lease is', () => {
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    const decision = anchor.evaluateOperationWitness(lease(), reading(MINUTE, 'boot-NEW'));
    expect(decision).toEqual({ witnessable: false, reason: 'BOOT_IDENTITY_CHANGED' });
  });

  it('recovers only when central re-establishes an anchor for the NEW boot', () => {
    const reestablished = new EdgeTrustedTimeAnchor(
      anchorRecord({
        edge_boot_id: 'boot-NEW',
        edge_monotonic_at_anchor: 500,
        server_issued_at: iso(2 * HOUR),
        server_valid_until: iso(2 * HOUR + EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS),
      }),
    );
    expect(reestablished.classify({ monotonic_ms: 500 + MINUTE, boot_id: 'boot-NEW' })).toBe('VALID');
    expect(reestablished.trustedNow({ monotonic_ms: 500 + MINUTE, boot_id: 'boot-NEW' })).toBe(iso(2 * HOUR + MINUTE));
  });
});

describe('a monotonic source that goes backwards is not monotonic', () => {
  it('fails closed within the same boot', () => {
    // Within one boot this cannot happen if the source is what it claims to be.
    // Observing it means the caller passed a wall clock after a step, or a
    // suspended VM's broken timer — and failing closed is what stops that
    // mistake becoming a receipt.
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    expect(anchor.classify(reading(-1))).toBe('MONOTONIC_NOT_MONOTONIC');
    expect(anchor.trustedNow(reading(-1))).toBeNull();
  });
});

describe('the null-emission path', () => {
  it('emits null with no anchor at all', () => {
    // A freshly booted Edge that has not reached central is in this state, and
    // it is ordinary rather than exceptional.
    const anchor = new EdgeTrustedTimeAnchor(null);
    expect(anchor.classify(reading(0))).toBe('NO_ANCHOR');
    expect(anchor.trustedNow(reading(0))).toBeNull();
    expect(anchor.lifetimeMs).toBeNull();
    expect(anchor.statement).toBeNull();
  });

  it('emits null rather than substituting the anchor instant when the anchor has expired', () => {
    // The most tempting substitute of all: `server_time` is a real, central,
    // authoritative instant. Using it as though no time had passed would place
    // every subsequent operation at the moment the anchor was issued.
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    const expired = reading(EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS + 1);
    expect(anchor.trustedNow(expired)).toBeNull();
    expect(anchor.trustedNow(expired)).not.toBe(SERVER_TIME);
  });

  it('emits null on an unreadable server_time rather than comparing NaN', () => {
    // C15-07: every comparison against NaN is false, so a bare `Date.parse`
    // comparison would silently answer "not expired".
    const anchor = new EdgeTrustedTimeAnchor({ ...anchorRecord(), server_issued_at: 'not-a-time' });
    expect(anchor.classify(reading(MINUTE))).toBe(DEVICE_TIME_NOT_AUTHORITATIVE);
    expect(anchor.trustedNow(reading(MINUTE))).toBeNull();
  });

  it('every non-VALID standing produces null, with no exceptions', () => {
    const cases: ReadonlyArray<readonly [EdgeTrustedTimeAnchor, EdgeMonotonicReading]> = [
      [new EdgeTrustedTimeAnchor(null), reading(0)],
      [new EdgeTrustedTimeAnchor(anchorRecord()), reading(EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS)],
      [new EdgeTrustedTimeAnchor(anchorRecord()), reading(MINUTE, 'boot-NEW')],
      [new EdgeTrustedTimeAnchor(anchorRecord()), reading(-1)],
      [new EdgeTrustedTimeAnchor({ ...anchorRecord(), server_issued_at: 'nope' }), reading(MINUTE)],
    ];
    for (const [anchor, at] of cases) {
      expect(anchor.classify(at)).not.toBe('VALID');
      expect(anchor.trustedNow(at)).toBeNull();
    }
  });
});

describe('an operation needs BOTH a valid anchor and a live lease', () => {
  it('witnesses when both hold', () => {
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    expect(anchor.evaluateOperationWitness(lease(), reading(30 * MINUTE))).toEqual({
      witnessable: true,
      trusted_now: iso(30 * MINUTE),
    });
  });

  it('refuses a live lease when the anchor has expired', () => {
    // Edge has no trustworthy instant to judge the lease AT, and does not
    // fabricate one to find out.
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord(holdover(5 * MINUTE)));
    const decision = anchor.evaluateOperationWitness(lease(), reading(10 * MINUTE));
    expect(decision).toEqual({ witnessable: false, reason: 'ANCHOR_EXPIRED' });
  });

  it('refuses an expired lease even with a perfectly valid anchor', () => {
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    // The lease expires 30 minutes after the anchor instant; read it at 45.
    const shortLease = lease({ issued_at: iso(-HOUR), expires_at: iso(30 * MINUTE) });
    const decision = anchor.evaluateOperationWitness(shortLease, reading(45 * MINUTE));
    expect(decision).toEqual({ witnessable: false, reason: 'LEASE_NOT_IN_FORCE' });
  });

  it('refuses a lease that is not yet in force', () => {
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    const futureLease = lease({ issued_at: iso(2 * HOUR), expires_at: iso(3 * HOUR) });
    expect(anchor.evaluateOperationWitness(futureLease, reading(MINUTE))).toEqual({
      witnessable: false,
      reason: 'LEASE_NOT_IN_FORCE',
    });
  });

  it('judges the lease at the EXCLUSIVE boundary the frozen classifier uses', () => {
    // Judged with `classifyDevicePolicyLease`, not a local comparison, so Edge
    // and central answer the boundary question with the same code.
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord());
    const boundedLease = lease({ issued_at: iso(-HOUR), expires_at: iso(30 * MINUTE) });
    expect(anchor.evaluateOperationWitness(boundedLease, reading(30 * MINUTE - 1)).witnessable).toBe(true);
    expect(anchor.evaluateOperationWitness(boundedLease, reading(30 * MINUTE)).witnessable).toBe(false);
  });

  it('refuses everything when there is no anchor, whatever the lease says', () => {
    const anchor = new EdgeTrustedTimeAnchor(null);
    expect(anchor.evaluateOperationWitness(lease(), reading(0))).toEqual({ witnessable: false, reason: 'NO_ANCHOR' });
  });

  it('never exposes a trusted_now on a refusal', () => {
    // The conjunction is structural: there is no shape in which an instant is
    // available without the lease having been judged at it.
    const anchor = new EdgeTrustedTimeAnchor(anchorRecord(holdover(MINUTE)));
    const decision = anchor.evaluateOperationWitness(lease(), reading(2 * MINUTE));
    expect(decision.witnessable).toBe(false);
    expect(decision).not.toHaveProperty('trusted_now');
  });
});

describe('FW2-11: anchor persistence is blocked, and blocked loudly', () => {
  it('loads no anchor across a restart', () => {
    // Not a bug. There is no primitive in this repository that can make a
    // persisted anchor independently verifiable after a restart, and an
    // unauthenticated anchor file hands an attacker with file-write access the
    // ability to choose what time Edge believes it is.
    const store = new VolatileEdgeTrustedTimeAnchorStore();
    return expect(store.load()).resolves.toBeNull();
  });

  it('does not persist an anchor it is given, and does not throw about it', () => {
    const store = new VolatileEdgeTrustedTimeAnchorStore();
    return expect(store.save(anchorRecord())).resolves.toBeUndefined();
  });

  it('leaves an Edge resuming from a cold start with no trusted time', async () => {
    // The consequence, asserted rather than described: after a restart Edge
    // emits `edge_trusted_time: null` and central refuses the time-bounded
    // kinds at NO_TRUSTWORTHY_TIME_WITNESS until an anchor is re-established.
    const store = new VolatileEdgeTrustedTimeAnchorStore();
    const resumed = new EdgeTrustedTimeAnchor(await store.load());
    expect(resumed.classify(reading(0))).toBe('NO_ANCHOR');
    expect(resumed.trustedNow(reading(0))).toBeNull();
  });
});
