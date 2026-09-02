import { describe, expect, it } from 'vitest';
import {
  canonicalDeviceGatewayDomainIdempotencyStatement,
  deviceGatewayDomainIdempotencyKey,
  type DeviceGatewayDomainIdempotencyInput,
} from './device-gateway.idempotency';

/**
 * WP-25/D25-16B — the SERVER-derived downstream idempotency identity, as a unit.
 *
 * The live suite proves that the gateway never accepts one from a device. These
 * assertions prove the derivation itself has the two properties the directive
 * names, because a derivation that quietly dropped a field would still produce
 * a plausible-looking key.
 */

const base: DeviceGatewayDomainIdempotencyInput = {
  organisationId: 'org-a',
  contextId: '0f3b2a1c-1111-4222-8333-444455556666',
  actorUserId: 'user-1',
  deviceId: '0f3b2a1c-1111-4222-8333-444455556667',
  keyId: 'key-1',
  keyVersion: 1,
  operationKind: 'ASSIGNMENT_ACCEPT',
  targetType: 'FIELD_ASSIGNMENT',
  targetId: 'assignment-1',
  deviceNonce: 'nonce-aaaaaaaaaaaaaaaaaaaa',
  payloadDigest: 'a'.repeat(64),
};

describe('WP-25/D25-16B the downstream identity', () => {
  it('is lowercase SHA-256 hex, 64 characters — inside every 256-character domain bound', () => {
    const key = deviceGatewayDomainIdempotencyKey(base);
    expect(key).toMatch(/^[0-9a-f]{64}$/u);
    // Truncating a security identity to fit a column is how two identities
    // become one; it fits without truncation, and this asserts that it does.
    expect(key.length).toBeLessThanOrEqual(256);
  });

  it('same signed operation -> same downstream identity', () => {
    // Nothing in the derivation is a clock, a counter or a random value, so a
    // genuine retry of the SAME proof derives the SAME key — which is what lets
    // the domain's own idempotency row be the thing convergence rests on.
    expect(deviceGatewayDomainIdempotencyKey(base)).toBe(deviceGatewayDomainIdempotencyKey({ ...base }));
  });

  it('different signed semantics -> different downstream identity, for every input', () => {
    const key = deviceGatewayDomainIdempotencyKey(base);
    const variants: DeviceGatewayDomainIdempotencyInput[] = [
      { ...base, organisationId: 'org-b' },
      { ...base, contextId: '0f3b2a1c-1111-4222-8333-44445555666a' },
      { ...base, actorUserId: 'user-2' },
      { ...base, deviceId: '0f3b2a1c-1111-4222-8333-44445555666b' },
      { ...base, keyId: 'key-2' },
      { ...base, keyVersion: 2 },
      { ...base, operationKind: 'ASSIGNMENT_DECLINE' },
      { ...base, targetType: 'INCIDENT_FIELD_MESSAGE' },
      { ...base, targetId: 'assignment-2' },
      { ...base, deviceNonce: 'nonce-bbbbbbbbbbbbbbbbbbbb' },
      { ...base, payloadDigest: 'b'.repeat(64) },
    ];
    // EVERY field, individually. A derivation that silently dropped one would
    // let two distinct security identities collide at the domain layer.
    for (const variant of variants) {
      expect(deviceGatewayDomainIdempotencyKey(variant), JSON.stringify(variant)).not.toBe(key);
    }
  });

  it('the nonce is in the identity, so two identical-semantics operations do not collide', () => {
    // Without it, the same operative recording the same state at the same site
    // twice would derive one downstream key and the second would converge on
    // the first — a lost operation that looks like a duplicate.
    expect(deviceGatewayDomainIdempotencyKey({ ...base, deviceNonce: 'other-nonce-cccccccccc' })).not.toBe(
      deviceGatewayDomainIdempotencyKey(base),
    );
  });

  it('is canonical JSON under its own domain separator, never a delimiter join', () => {
    const statement = canonicalDeviceGatewayDomainIdempotencyStatement(base);
    expect(statement).toContain('WP25-GATEWAY-DOMAIN-IDEMPOTENCY-v1');
    // C11-01: a delimiter join would be unsound here, because every field is a
    // caller-visible string that may itself contain the delimiter.
    const shifted = deviceGatewayDomainIdempotencyKey({ ...base, organisationId: 'org', actorUserId: 'a-user-1' });
    const other = deviceGatewayDomainIdempotencyKey({ ...base, organisationId: 'org-a', actorUserId: 'user-1' });
    expect(shifted).not.toBe(other);
  });

  it('the canonical statement carries no signature and no private material', () => {
    const statement = canonicalDeviceGatewayDomainIdempotencyStatement(base);
    for (const forbidden of ['signature', 'private', 'secret', 'token']) {
      expect(statement.includes(forbidden), forbidden).toBe(false);
    }
  });
});
