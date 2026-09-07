import { describe, expect, it } from 'vitest';
import {
  DEVICE_EDGE_TRANSPORT_DESCRIPTOR_FORBIDDEN_FIELDS,
  DeviceEdgeTransportDescriptorSchema,
  DeviceEdgeTransportResponseSchema,
  EdgeHttpsEndpointSchema,
  TlsSpkiSha256Schema,
} from './device-edge-transport.js';

/**
 * The pin these tests defend is the ONLY thing standing between a Field device
 * and whatever answers first on a hostile site LAN. Every case below is a way
 * that protection has been lost in real systems: a plaintext fallback, a
 * widened trust store, a "temporary" escape hatch, or an ambiguity resolved by
 * picking a row.
 */

const validDescriptor = {
  schema_version: 1 as const,
  edge_id: 'edge-1',
  site_id: 'site-1',
  transport_identity_id: 'ti-1',
  transport_key_version: 1,
  https_endpoint: 'https://edge-1.site-1.sentinel.internal:8443',
  tls_spki_sha256: 'a'.repeat(64),
  issued_at: '2026-09-07T00:00:00.000Z',
  expires_at: '2026-09-07T06:00:00.000Z',
};

describe('DeviceEdgeTransportDescriptor', () => {
  it('accepts a well-formed descriptor', () => {
    expect(DeviceEdgeTransportDescriptorSchema.safeParse(validDescriptor).success).toBe(true);
  });

  // Each forbidden field is a specific way of turning a routing lookup into
  // either a credential handout or an instruction to stop checking.
  it.each(DEVICE_EDGE_TRANSPORT_DESCRIPTOR_FORBIDDEN_FIELDS)('refuses a descriptor carrying %s', (field) => {
    const parsed = DeviceEdgeTransportDescriptorSchema.safeParse({ ...validDescriptor, [field]: 'anything' });
    expect(parsed.success).toBe(false);
  });

  it('refuses an unknown field it has never heard of', () => {
    // `.strict()` is what actually enforces the list above; this proves the
    // list is a statement of intent rather than the mechanism.
    const parsed = DeviceEdgeTransportDescriptorSchema.safeParse({ ...validDescriptor, invented_later: true });
    expect(parsed.success).toBe(false);
  });

  it('refuses a descriptor whose window exceeds the offline ceiling', () => {
    const parsed = DeviceEdgeTransportDescriptorSchema.safeParse({
      ...validDescriptor,
      expires_at: '2026-09-08T00:00:00.000Z',
    });
    expect(parsed.success).toBe(false);
  });

  it('refuses a descriptor that expires before it was issued', () => {
    const parsed = DeviceEdgeTransportDescriptorSchema.safeParse({
      ...validDescriptor,
      issued_at: '2026-09-07T06:00:00.000Z',
      expires_at: '2026-09-07T00:00:00.000Z',
    });
    expect(parsed.success).toBe(false);
  });
});

describe('the endpoint a device is allowed to open', () => {
  it('accepts https', () => {
    expect(EdgeHttpsEndpointSchema.safeParse('https://edge.internal:8443').success).toBe(true);
  });

  // The absence of an http alternative is the guarantee. If this ever passes,
  // a central that has been talked into emitting a plaintext endpoint can
  // silently downgrade an entire site's Field traffic.
  it('refuses plaintext http', () => {
    expect(EdgeHttpsEndpointSchema.safeParse('http://edge.internal:8443').success).toBe(false);
  });

  it('refuses a non-URL', () => {
    expect(EdgeHttpsEndpointSchema.safeParse('edge.internal:8443').success).toBe(false);
  });

  // A secret in an address leaks into every log that records a connection.
  it('refuses credentials embedded in the URL', () => {
    expect(EdgeHttpsEndpointSchema.safeParse('https://user:pw@edge.internal:8443').success).toBe(false);
  });

  it('refuses a query string or fragment', () => {
    expect(EdgeHttpsEndpointSchema.safeParse('https://edge.internal/?token=abc').success).toBe(false);
    expect(EdgeHttpsEndpointSchema.safeParse('https://edge.internal/#f').success).toBe(false);
  });
});

describe('the SPKI pin', () => {
  it('accepts 64 lower-case hex characters', () => {
    expect(TlsSpkiSha256Schema.safeParse('0123456789abcdef'.repeat(4)).success).toBe(true);
  });

  // Case and length are both load-bearing: a comparison against a
  // differently-cased or truncated pin is a comparison that can succeed by
  // accident.
  it('refuses upper-case hex', () => {
    expect(TlsSpkiSha256Schema.safeParse('A'.repeat(64)).success).toBe(false);
  });

  it('refuses a short or long digest', () => {
    expect(TlsSpkiSha256Schema.safeParse('a'.repeat(63)).success).toBe(false);
    expect(TlsSpkiSha256Schema.safeParse('a'.repeat(65)).success).toBe(false);
  });

  it('refuses a non-hex character', () => {
    expect(TlsSpkiSha256Schema.safeParse(`${'a'.repeat(63)}z`).success).toBe(false);
  });
});

describe('the response envelope', () => {
  it('carries a descriptor when issued', () => {
    const parsed = DeviceEdgeTransportResponseSchema.safeParse({ outcome: 'ISSUED', descriptor: validDescriptor });
    expect(parsed.success).toBe(true);
  });

  it('carries a coarse refusal reason and no descriptor when refused', () => {
    const parsed = DeviceEdgeTransportResponseSchema.safeParse({
      outcome: 'REFUSED',
      refusal: 'AMBIGUOUS_TRANSPORT_IDENTITY',
    });
    expect(parsed.success).toBe(true);
  });

  // The union is what stops a caller reading `.descriptor` without having
  // handled the refused branch. A nullable field would leave that to review.
  it('refuses a response that is both issued and refused', () => {
    const parsed = DeviceEdgeTransportResponseSchema.safeParse({
      outcome: 'ISSUED',
      descriptor: validDescriptor,
      refusal: 'EDGE_NOT_AVAILABLE',
    });
    expect(parsed.success).toBe(false);
  });

  it('refuses a refusal reason it does not define', () => {
    const parsed = DeviceEdgeTransportResponseSchema.safeParse({ outcome: 'REFUSED', refusal: 'BECAUSE_I_SAID_SO' });
    expect(parsed.success).toBe(false);
  });
});
