import { describe, expect, it } from 'vitest';
import {
  DEVICE_GATEWAY_ASSIGNMENT_ACTION,
  DEVICE_GATEWAY_CAPABILITY_ACTIONS,
  DEVICE_GATEWAY_OPERATION_KINDS,
  DEVICE_GATEWAY_REQUIRED_ACTION,
  DEVICE_GATEWAY_TARGET_TYPE_FOR_KIND,
  canonicalDeviceGatewayEnvelope,
  parseOperationEnvelope,
} from './device-gateway.envelope';

/**
 * WP-25/D25-11 — the canonical typed operation envelope, as a unit.
 *
 * These are the properties the live suite then exercises end to end. They are
 * asserted here as well because a digest rule is easiest to break silently: a
 * reordered key, an admitted extra field or a body-supplied kind that overrides
 * instead of refusing all produce a system that still works and no longer binds
 * what it claims to.
 */

const identity = {
  organisationId: 'org-a',
  siteId: 'site-1',
  actorUserId: 'user-1',
  deviceId: '0f3b2a1c-1111-4222-8333-444455556666',
  targetId: 'target-1',
};

describe('WP-25/D25-11 the route chooses the operation kind, never the body', () => {
  it('a body-supplied operation_kind that agrees with the route is admitted', () => {
    const parsed = parseOperationEnvelope('ASSIGNMENT_ACCEPT', identity, {
      operation_kind: 'ASSIGNMENT_ACCEPT',
      payload: { expected_status: 'REQUESTED' },
    });
    expect(parsed.ok).toBe(true);
  });

  it('a body-supplied operation_kind that DISAGREES with the route refuses', () => {
    // The route is the authority. Silently overriding would be
    // indistinguishable, in a log, from the caller having chosen it.
    const parsed = parseOperationEnvelope('ASSIGNMENT_ACCEPT', identity, {
      operation_kind: 'FIELD_STATE_UPDATE',
      payload: { expected_status: 'REQUESTED' },
    });
    expect(parsed).toEqual({ ok: false, refusal: 'OPERATION_KIND_CONFLICT' });
  });

  it('a body-supplied target_type or target_id that disagrees refuses', () => {
    expect(
      parseOperationEnvelope('ASSIGNMENT_ACCEPT', identity, {
        target_type: 'INCIDENT_FIELD_MESSAGE',
        payload: { expected_status: 'REQUESTED' },
      }),
    ).toEqual({ ok: false, refusal: 'OPERATION_KIND_CONFLICT' });
    expect(
      parseOperationEnvelope('ASSIGNMENT_ACCEPT', identity, {
        target_id: 'some-other-assignment',
        payload: { expected_status: 'REQUESTED' },
      }),
    ).toEqual({ ok: false, refusal: 'OPERATION_KIND_CONFLICT' });
  });

  it('C17-06: a body that names its own identity is REFUSED, not silently ignored', () => {
    // This used to parse and drop the fields, which was safe only for as long as
    // nobody read them. At a cryptographic boundary a value that is no part of
    // the signed object is refused: "ignored" and "not accepted" look identical
    // in a log right up until a refactor makes them different.
    for (const unsigned of [
      { organisation_id: 'org-b' },
      { site_id: 'site-99' },
      { actor_user_id: 'someone-else' },
      { device_id: 'another-device' },
      { context_id: 'context-99' },
      { purpose: 'OFFLINE_SYNC' },
      { idempotency_key: 'chosen-by-the-device' },
    ]) {
      expect(
        parseOperationEnvelope('ASSIGNMENT_ACCEPT', identity, { ...unsigned, payload: { expected_status: 'REQUESTED' } }),
        JSON.stringify(unsigned),
      ).toEqual({ ok: false, refusal: 'ENVELOPE_MALFORMED' });
    }
  });

  it('identity is taken from the SERVER, and the body has nowhere to propose one', () => {
    const parsed = parseOperationEnvelope('ASSIGNMENT_ACCEPT', identity, { payload: { expected_status: 'REQUESTED' } });
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    // Every identity field in the signed bytes came from the SERVER.
    expect(parsed.envelope.organisation_id).toBe('org-a');
    expect(parsed.envelope.site_id).toBe('site-1');
    expect(parsed.envelope.actor_user_id).toBe('user-1');
    expect(parsed.envelope.device_id).toBe(identity.deviceId);
    expect(canonicalDeviceGatewayEnvelope(parsed.envelope)).not.toContain('org-b');
    expect(canonicalDeviceGatewayEnvelope(parsed.envelope)).not.toContain('someone-else');
  });
});

describe('WP-25/D25-11 the semantic payload is strict', () => {
  it('an unknown key in a semantic payload refuses', () => {
    // An unknown key is a value the device signed and the server did not
    // understand — the two sides would disagree about what the signature covers.
    expect(
      parseOperationEnvelope('ASSIGNMENT_ACCEPT', identity, { payload: { expected_status: 'REQUESTED', sneak: true } }),
    ).toEqual({ ok: false, refusal: 'ENVELOPE_MALFORMED' });
  });

  it('a field-state payload missing a required field refuses', () => {
    expect(parseOperationEnvelope('FIELD_STATE_UPDATE', identity, { payload: { state: 'PATROL' } })).toEqual({
      ok: false,
      refusal: 'ENVELOPE_MALFORMED',
    });
  });

  it('an acknowledgement carries no semantics of its own', () => {
    const parsed = parseOperationEnvelope('INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE', identity, {});
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.envelope.semantic_payload).toEqual({});
    // §76: the device's claim about when it saw something is telemetry, never
    // authority, so there is nowhere in the signed payload to put one.
    expect(parseOperationEnvelope('INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE', identity, { payload: { seen_at: 'now' } }).ok).toBe(false);
  });
});

describe('WP-25/D25-11 the digest distinguishes what the security decision depends on', () => {
  const accept = parseOperationEnvelope('ASSIGNMENT_ACCEPT', identity, { payload: { expected_status: 'REQUESTED' } });
  const decline = parseOperationEnvelope('ASSIGNMENT_DECLINE', identity, { payload: { expected_status: 'REQUESTED' } });

  it('two operation kinds over identical bodies produce different digests', () => {
    expect(accept.ok && decline.ok).toBe(true);
    if (!accept.ok || !decline.ok) return;
    // This is the whole reason the envelope exists: without it, a proof minted
    // for an accept could be carried to a decline because the two bodies
    // serialise identically.
    expect(accept.digest).not.toBe(decline.digest);
  });

  it('a different target, site, actor or device changes the digest', () => {
    if (!accept.ok) return;
    for (const changed of [
      { ...identity, targetId: 'target-2' },
      { ...identity, siteId: 'site-2' },
      { ...identity, actorUserId: 'user-2' },
      { ...identity, deviceId: '0f3b2a1c-1111-4222-8333-444455556667' },
    ]) {
      const other = parseOperationEnvelope('ASSIGNMENT_ACCEPT', changed, { payload: { expected_status: 'REQUESTED' } });
      expect(other.ok).toBe(true);
      if (!other.ok) return;
      expect(other.digest).not.toBe(accept.digest);
    }
  });

  it('the digest is stable across key order in the semantic payload', () => {
    const a = parseOperationEnvelope('FIELD_STATE_UPDATE', identity, {
      payload: { state: 'PATROL', location: null, source_at: '2026-09-02T10:00:00.000Z', freshness_ms: 5 },
    });
    const b = parseOperationEnvelope('FIELD_STATE_UPDATE', identity, {
      payload: { freshness_ms: 5, source_at: '2026-09-02T10:00:00.000Z', location: null, state: 'PATROL' },
    });
    expect(a.ok && b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    // Canonicalisation is the contract's, and it sorts keys recursively — a
    // conforming device and the server must agree on the bytes without agreeing
    // on a serialiser.
    expect(a.digest).toBe(b.digest);
  });

  it('the canonical form is domain-tagged, so it cannot be confused with another statement', () => {
    if (!accept.ok) return;
    expect(canonicalDeviceGatewayEnvelope(accept.envelope)).toContain('sentinel.wp25.device-gateway.operation-envelope.v1');
  });
});

describe('WP-25/D25-10 the frozen route tables', () => {
  it('there are exactly four operation kinds', () => {
    expect([...DEVICE_GATEWAY_OPERATION_KINDS]).toEqual([
      'FIELD_STATE_UPDATE',
      'ASSIGNMENT_ACCEPT',
      'ASSIGNMENT_DECLINE',
      'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE',
    ]);
  });

  it('assignment reaches exactly accept and decline', () => {
    expect(Object.keys(DEVICE_GATEWAY_ASSIGNMENT_ACTION)).toEqual(['ASSIGNMENT_ACCEPT', 'ASSIGNMENT_DECLINE']);
    expect(Object.values(DEVICE_GATEWAY_ASSIGNMENT_ACTION)).toEqual(['accept', 'decline']);
  });

  it('every kind has a target type and a required §62 action', () => {
    for (const kind of DEVICE_GATEWAY_OPERATION_KINDS) {
      expect(DEVICE_GATEWAY_TARGET_TYPE_FOR_KIND[kind]).toBeTruthy();
      expect(DEVICE_GATEWAY_REQUIRED_ACTION[kind]).toBeTruthy();
    }
    // Quoted from the human routes, never re-decided: widening one would let a
    // device-authenticated path do something the same person cannot do over
    // HTTP.
    expect(DEVICE_GATEWAY_REQUIRED_ACTION.FIELD_STATE_UPDATE).toBe('field.state.write');
    expect(DEVICE_GATEWAY_REQUIRED_ACTION.ASSIGNMENT_ACCEPT).toBe('field.assignment.act');
    expect(DEVICE_GATEWAY_REQUIRED_ACTION.ASSIGNMENT_DECLINE).toBe('field.assignment.act');
    expect(DEVICE_GATEWAY_REQUIRED_ACTION.INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE).toBe('field.message.acknowledge');
    expect([...DEVICE_GATEWAY_CAPABILITY_ACTIONS].sort()).toEqual(
      ['field.assignment.act', 'field.message.acknowledge', 'field.state.write'].sort(),
    );
  });
});
