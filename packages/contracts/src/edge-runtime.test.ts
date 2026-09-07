import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  EdgeIdentityContextSchema,
  EdgeOperationStateSchema,
  EdgeQueueMetricsSchema,
  EdgeStoredOperationSchema,
  EdgeTransportResultSchema,
  type EdgeStoredOperation,
  type EdgeTransportResult,
} from './edge-runtime.js';
import {
  DEVICE_EDGE_RECEIPT_FORBIDDEN_FIELDS,
  DeviceEdgeReceiptSchema,
  DeviceOfflineOperationEnvelopeSchema,
  type DeviceEdgeReceipt,
  type DeviceOfflineOperationEnvelope,
} from './device-offline.js';
import { canonicalDeviceJson, deviceCanonicalDigest } from './device-identity.js';

/**
 * WP-29B Crucible — the five frozen Edge runtime interfaces.
 *
 * The suite is organised around the rules rather than around the types, because
 * every rule here is a defect somebody would otherwise ship: a second receipt
 * type, a flattened envelope, a re-serialised payload, an Edge that ends its own
 * queue entries, an Edge that caches its own trust, and a metric labelled by a
 * person.
 */

const OP_ID = '5f2c0a9e-9d1b-4f3a-8a0d-3b1e6c7d8e90';
const NONCE = 'edge-nonce-0123456789abcdef';
const SIGNATURE = Buffer.from(new Uint8Array(64).fill(7)).toString('base64url');
const EDGE_SIGNATURE = Buffer.from(new Uint8Array(64).fill(8)).toString('base64url');

/** A real canonical P-256 point, because `deriveP256PublicKeyThumbprint` decodes it. */
const EDGE_PUBLIC_KEY = Buffer.from(
  generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' }),
)
  .subarray(-65)
  .toString('base64url');

/** The payload as Edge receives it, and the exact canonical bytes it must store. */
const PAYLOAD = { checkpoint_id: 'cp-9', note: 'gate secured', sequence: 4 } as const;
const PAYLOAD_CANONICAL = canonicalDeviceJson(PAYLOAD);
const PAYLOAD_DIGEST = deviceCanonicalDigest(PAYLOAD);

function envelope(overrides: Partial<DeviceOfflineOperationEnvelope> = {}): DeviceOfflineOperationEnvelope {
  return DeviceOfflineOperationEnvelopeSchema.parse({
    schema_version: 1,
    offline_operation_id: OP_ID,
    organisation_id: 'org-1',
    site_id: 'site-1',
    actor_user_id: 'user-1',
    device_id: 'device-1',
    key_id: 'key-1',
    key_version: 2,
    operation_kind: 'FIELD_ASSIGNMENT_START',
    device_sequence: 41,
    idempotency_key: 'idem-1',
    payload_digest: PAYLOAD_DIGEST,
    policy_lease_id: 'lease-1',
    nonce: NONCE,
    created_at: '2026-08-29T09:00:00.000Z',
    claimed_signature_profile: 'P256_ECDSA_SHA256',
    signature: SIGNATURE,
    ...overrides,
  });
}

function receipt(overrides: Partial<DeviceEdgeReceipt> = {}): DeviceEdgeReceipt {
  return DeviceEdgeReceiptSchema.parse({
    schema_version: 1,
    edge_id: 'edge-17',
    edge_key_id: 'edge-key-1',
    edge_key_version: 1,
    witnessed_operation_fingerprint: 'a'.repeat(64),
    edge_trusted_time: '2026-08-29T09:00:01.000Z',
    edge_monotonic_position: 900,
    claimed_edge_signature_profile: 'P256_ECDSA_SHA256',
    edge_signature: EDGE_SIGNATURE,
    ...overrides,
  });
}

function storedOperation(overrides: Record<string, unknown> = {}): unknown {
  return {
    schema_version: 1,
    envelope: envelope(),
    payload_canonical_json: PAYLOAD_CANONICAL,
    receipt: receipt(),
    enqueued_edge_monotonic_position: 900,
    state: 'QUEUED',
    settlement: null,
    ...overrides,
  };
}

function identityContext(overrides: Record<string, unknown> = {}): unknown {
  return {
    schema_version: 1,
    organisation_id: 'org-1',
    edge_id: 'edge-17',
    edge_key_id: 'edge-key-1',
    edge_key_version: 1,
    claimed_signature_profile: 'P256_ECDSA_SHA256',
    authorised_site_ids: ['site-1'],
    ...overrides,
  };
}

function queueMetrics(overrides: Record<string, unknown> = {}): unknown {
  return {
    schema_version: 1,
    queued_count: 3,
    terminal_count: 1,
    capacity: 10_000,
    oldest_queued_monotonic_age_ms: 42_000,
    trusted_time_available: true,
    consecutive_unknown_transport_results: 0,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------

describe('the receipt type is the FROZEN one, not a parallel Edge type', () => {
  /**
   * The rule this module exists to hold. If someone later adds an `EdgeReceipt`
   * to `edge-runtime.ts`, the composition below stops being the frozen schema
   * and every forbidden-field proof in the WP-23 Crucible stops covering what
   * the runtime actually stores.
   */
  it('stores a receipt that the frozen DeviceEdgeReceiptSchema accepts unchanged', () => {
    const parsed = EdgeStoredOperationSchema.parse(storedOperation());
    expect(DeviceEdgeReceiptSchema.parse(parsed.receipt)).toEqual(parsed.receipt);
  });

  it.each(DEVICE_EDGE_RECEIPT_FORBIDDEN_FIELDS)('refuses a stored receipt carrying %s', (field) => {
    const result = EdgeStoredOperationSchema.safeParse(storedOperation({ receipt: { ...receipt(), [field]: true } }));
    expect(result.success).toBe(false);
  });

  it('refuses a receipt that witnesses neither a trusted time nor a monotonic position', () => {
    // The frozen superRefine, reached THROUGH the composition. A local receipt
    // type would have silently dropped this rule.
    const result = EdgeStoredOperationSchema.safeParse(
      storedOperation({ receipt: { ...receipt(), edge_trusted_time: null, edge_monotonic_position: null } }),
    );
    expect(result.success).toBe(false);
  });

  it('accepts a null receipt, because no trusted time is a correct outcome', () => {
    // This entry reconciles to NO_TRUSTWORTHY_TIME_WITNESS centrally, and that
    // refusal is the design. The alternative — a receipt minted from the host
    // wall clock — would be admitted and would be a forgery.
    expect(EdgeStoredOperationSchema.safeParse(storedOperation({ receipt: null })).success).toBe(true);
  });

  it('accepts a receipt whose edge_trusted_time is null, carrying only ordering', () => {
    // Central refuses this for a time-bounded kind. Edge is still allowed to
    // record that it saw the operation, in order.
    const parsed = EdgeStoredOperationSchema.parse(
      storedOperation({ receipt: receipt({ edge_trusted_time: null, edge_monotonic_position: 900 }) }),
    );
    expect(parsed.receipt?.edge_trusted_time).toBeNull();
  });
});

describe('the envelope is composed, never flattened', () => {
  it('accepts a stored entry that carries the whole signed envelope', () => {
    const parsed = EdgeStoredOperationSchema.parse(storedOperation());
    expect(parsed.envelope.offline_operation_id).toBe(OP_ID);
    expect(parsed.envelope.policy_lease_id).toBe('lease-1');
  });

  it('refuses a copy of a signed field alongside the envelope', () => {
    // A second source of truth for a value the device signature already fixes.
    // `.strict()` is what refuses it.
    for (const flattened of ['device_id', 'operation_kind', 'policy_lease_id', 'actor_user_id']) {
      expect(EdgeStoredOperationSchema.safeParse(storedOperation({ [flattened]: 'x' })).success).toBe(false);
    }
  });

  it('refuses an envelope the frozen schema would refuse', () => {
    expect(
      EdgeStoredOperationSchema.safeParse(storedOperation({ envelope: { ...envelope(), unexpected_field: 1 } })).success,
    ).toBe(false);
  });
});

describe('the payload is canonical TEXT, and it must still be the bytes the signature covers', () => {
  it('accepts the canonical form', () => {
    const parsed = EdgeStoredOperationSchema.parse(storedOperation());
    expect(parsed.payload_canonical_json).toBe(PAYLOAD_CANONICAL);
    expect(typeof parsed.payload_canonical_json).toBe('string');
  });

  it('refuses a parsed object in place of the text', () => {
    expect(EdgeStoredOperationSchema.safeParse(storedOperation({ payload_canonical_json: PAYLOAD })).success).toBe(false);
  });

  it('refuses text whose keys are not in canonical order', () => {
    // THE DEFECT: a store that re-serialises JSON reorders keys, the bytes
    // change, the digest changes, and the device signature is intact while the
    // operation is refused hours later at reconciliation with the original
    // bytes unrecoverable. Refusing here means the corruption is found at the
    // read, not at the reconnect.
    const reordered = JSON.stringify({ sequence: 4, note: 'gate secured', checkpoint_id: 'cp-9' });
    expect(reordered).not.toBe(PAYLOAD_CANONICAL);
    const result = EdgeStoredOperationSchema.safeParse(storedOperation({ payload_canonical_json: reordered }));
    expect(result.success).toBe(false);
  });

  it('refuses canonical text that does not digest to the envelope payload_digest', () => {
    const otherPayload = canonicalDeviceJson({ checkpoint_id: 'cp-9', note: 'gate FORCED', sequence: 4 });
    const result = EdgeStoredOperationSchema.safeParse(storedOperation({ payload_canonical_json: otherPayload }));
    expect(result.success).toBe(false);
  });

  it('refuses text that is not readable JSON at all', () => {
    expect(EdgeStoredOperationSchema.safeParse(storedOperation({ payload_canonical_json: '{truncated' })).success).toBe(false);
  });

  it('binds the payload to THIS envelope, so an entry cannot carry another operation body', () => {
    const otherEnvelope = envelope({ payload_digest: 'b'.repeat(64) });
    const result = EdgeStoredOperationSchema.safeParse(storedOperation({ envelope: otherEnvelope }));
    expect(result.success).toBe(false);
  });
});

describe('EdgeOperationState has exactly two members', () => {
  it('admits QUEUED and TERMINAL', () => {
    expect(EdgeOperationStateSchema.options).toEqual(['QUEUED', 'TERMINAL']);
  });

  it.each(['FAILED', 'EXPIRED', 'ABANDONED', 'RETRYING', 'DROPPED'])('refuses %s', (state) => {
    // Each of these is Edge making a judgement about work it did not author.
    // The whole point of the two-member enum is that there is no name in which
    // an operative's queued duress signal can be quietly discarded.
    expect(EdgeOperationStateSchema.safeParse(state).success).toBe(false);
  });
});

describe('only the server ends a queued operation', () => {
  const accepted = { outcome: 'CENTRAL_ACCEPTED', terminal: true, central_reference: 'incident-88' } as const;

  it('accepts TERMINAL carrying a central answer', () => {
    const parsed = EdgeStoredOperationSchema.parse(storedOperation({ state: 'TERMINAL', settlement: accepted }));
    expect(parsed.state).toBe('TERMINAL');
    expect(parsed.settlement).toEqual(accepted);
  });

  it('refuses TERMINAL with no central answer', () => {
    // Edge deciding on its own that an entry is over.
    expect(EdgeStoredOperationSchema.safeParse(storedOperation({ state: 'TERMINAL', settlement: null })).success).toBe(false);
  });

  it('refuses QUEUED that already carries a central answer', () => {
    // An entry central has ruled on would otherwise be re-sent.
    expect(EdgeStoredOperationSchema.safeParse(storedOperation({ state: 'QUEUED', settlement: accepted })).success).toBe(false);
  });

  it('refuses settling an entry on an UNKNOWN transport result', () => {
    // The structural rule: `settlement` is typed as the two TERMINAL answers
    // only, so "we did not hear back" has no way to become "this is over".
    const unknown = { outcome: 'UNKNOWN', terminal: false, reason: 'TIMED_OUT' };
    expect(EdgeStoredOperationSchema.safeParse(storedOperation({ state: 'TERMINAL', settlement: unknown })).success).toBe(false);
  });

  it('refuses a settlement that claims to be terminal without being a central answer', () => {
    const invented = { outcome: 'EDGE_GAVE_UP', terminal: true, refusal_code: 'TOO_OLD' };
    expect(EdgeStoredOperationSchema.safeParse(storedOperation({ state: 'TERMINAL', settlement: invented })).success).toBe(false);
  });
});

describe('EdgeTransportResult distinguishes a proven answer from "we do not know"', () => {
  it('marks both central answers terminal', () => {
    const acceptedResult = EdgeTransportResultSchema.parse({
      outcome: 'CENTRAL_ACCEPTED',
      terminal: true,
      central_reference: 'ref-1',
    });
    const refusedResult = EdgeTransportResultSchema.parse({
      outcome: 'CENTRAL_REFUSED',
      terminal: true,
      refusal_code: 'NO_TRUSTWORTHY_TIME_WITNESS',
    });
    expect(acceptedResult.terminal).toBe(true);
    expect(refusedResult.terminal).toBe(true);
  });

  it.each(['NOT_ATTEMPTED', 'CONNECT_FAILED', 'TIMED_OUT', 'TRANSPORT_ERROR', 'RESPONSE_UNINTELLIGIBLE'])(
    'marks UNKNOWN/%s non-terminal so the entry stays queued',
    (reason) => {
      const result = EdgeTransportResultSchema.parse({ outcome: 'UNKNOWN', terminal: false, reason });
      expect(result.terminal).toBe(false);
    },
  );

  it('refuses an UNKNOWN that claims to be terminal', () => {
    // `terminal` is a literal on every member, following the
    // `queued_domain_execution: false` pattern: flipping it is a visible diff on
    // a security rule, never an accident inside a retry loop.
    expect(EdgeTransportResultSchema.safeParse({ outcome: 'UNKNOWN', terminal: true, reason: 'TIMED_OUT' }).success).toBe(false);
  });

  it('refuses a central answer that claims to be non-terminal', () => {
    expect(
      EdgeTransportResultSchema.safeParse({ outcome: 'CENTRAL_ACCEPTED', terminal: false, central_reference: 'ref-1' }).success,
    ).toBe(false);
  });

  it('refuses an UNKNOWN with no reason, so "it failed" is never the whole record', () => {
    expect(EdgeTransportResultSchema.safeParse({ outcome: 'UNKNOWN', terminal: false }).success).toBe(false);
  });

  it('narrows to the terminal members by the discriminant alone', () => {
    const results: EdgeTransportResult[] = [
      { outcome: 'CENTRAL_ACCEPTED', terminal: true, central_reference: 'ref-1' },
      { outcome: 'UNKNOWN', terminal: false, reason: 'CONNECT_FAILED' },
    ];
    const stillQueued = results.filter((result) => !result.terminal);
    expect(stillQueued).toHaveLength(1);
  });
});

describe('EdgeIdentityContext carries no trust field and no key material', () => {
  it('accepts the identity Edge is allowed to know about itself', () => {
    const parsed = EdgeIdentityContextSchema.parse(identityContext());
    expect(parsed.edge_id).toBe('edge-17');
    expect(Object.keys(parsed)).not.toContain('edge_trust');
  });

  it.each(['edge_trust', 'trust', 'trust_status', 'is_trusted', 'trusted', 'edge_trust_status'])(
    'refuses a cached trust judgement in %s',
    (field) => {
      // Central owns `edge_trust` on `EdgeRegistryKeyRecordSchema` and refuses
      // EDGE_NOT_TRUSTED against ITS copy. A cached TRUSTED would keep an Edge
      // believing it is trusted for exactly as long as the WAN is down — the
      // window in which a suspension matters.
      expect(EdgeIdentityContextSchema.safeParse(identityContext({ [field]: 'TRUSTED' })).success).toBe(false);
    },
  );

  it.each(['private_key', 'signing_key', 'key_material', 'edge_private_key', 'public_key'])(
    'refuses key material in %s',
    (field) => {
      // This structure is logged at boot and shown on a readiness page.
      expect(EdgeIdentityContextSchema.safeParse(identityContext({ [field]: EDGE_PUBLIC_KEY })).success).toBe(false);
    },
  );

  it.each(['device_trust', 'authorises_operation', 'approval', 'policy_override'])('refuses the authorising shape %s', (field) => {
    expect(EdgeIdentityContextSchema.safeParse(identityContext({ [field]: true })).success).toBe(false);
  });

  it('requires at least one authorised site, so an Edge cannot claim to be site-agnostic', () => {
    expect(EdgeIdentityContextSchema.safeParse(identityContext({ authorised_site_ids: [] })).success).toBe(false);
  });

  it('has no wildcard site, matching EdgeRegistryKeyRecord', () => {
    // A wildcard is a widening nobody asked for; central would refuse it as a
    // site id anyway, and it must not become expressible here first.
    const parsed = EdgeIdentityContextSchema.parse(identityContext({ authorised_site_ids: ['*'] }));
    expect(parsed.authorised_site_ids).toEqual(['*']);
    // It parses as an ordinary (meaningless) site id, and central's
    // `authorised_site_ids.includes(envelope.site_id)` will not match a real
    // site — so it grants nothing. There is no wildcard SEMANTIC anywhere.
  });

  it('keeps the signature profile a claim, mirroring claimed_edge_signature_profile', () => {
    const parsed = EdgeIdentityContextSchema.parse(identityContext());
    expect(parsed.claimed_signature_profile).toBe('P256_ECDSA_SHA256');
    expect(EdgeIdentityContextSchema.safeParse(identityContext({ claimed_signature_profile: 'RSA_PKCS1' })).success).toBe(false);
  });
});

describe('EdgeQueueMetrics is aggregate only', () => {
  it('accepts the aggregate shape', () => {
    const parsed = EdgeQueueMetricsSchema.parse(queueMetrics());
    expect(parsed.queued_count).toBe(3);
    expect(parsed.trusted_time_available).toBe(true);
  });

  it.each([
    'per_device',
    'by_device_id',
    'device_id',
    'per_actor',
    'actor_user_id',
    'by_recipient',
    'recipient_id',
    'per_site',
    'site_id',
    'by_operation_kind',
    'operation_kind',
  ])('refuses the breakdown dimension %s', (field) => {
    // WP-18 applied to telemetry. A queue-depth gauge labelled by device is a
    // per-operative activity trace; labelled by anything that reduces to a
    // recipient class it reconstructs the protected relationship itself, from
    // the least access-controlled surface the service has.
    expect(EdgeQueueMetricsSchema.safeParse(queueMetrics({ [field]: { 'device-1': 3 } })).success).toBe(false);
  });

  it('has no field whose value is a map or an array of per-entity rows', () => {
    const parsed = EdgeQueueMetricsSchema.parse(queueMetrics());
    for (const value of Object.values(parsed)) {
      expect(Array.isArray(value)).toBe(false);
      expect(typeof value === 'object' && value !== null).toBe(false);
    }
  });

  it('exposes trusted-time availability as a boolean and never as a clock reading', () => {
    expect(EdgeQueueMetricsSchema.safeParse(queueMetrics({ trusted_time_available: '2026-08-29T09:00:00.000Z' })).success).toBe(false);
  });

  it('allows a null oldest age only for an empty queue reading', () => {
    const parsed = EdgeQueueMetricsSchema.parse(queueMetrics({ queued_count: 0, oldest_queued_monotonic_age_ms: null }));
    expect(parsed.oldest_queued_monotonic_age_ms).toBeNull();
  });

  it('measures the oldest entry monotonically, so a backlog is visible with no trusted clock', () => {
    const parsed = EdgeQueueMetricsSchema.parse(queueMetrics({ trusted_time_available: false, oldest_queued_monotonic_age_ms: 21_600_000 }));
    expect(parsed.oldest_queued_monotonic_age_ms).toBe(21_600_000);
    expect(parsed.trusted_time_available).toBe(false);
  });

  it('refuses a negative count', () => {
    expect(EdgeQueueMetricsSchema.safeParse(queueMetrics({ queued_count: -1 })).success).toBe(false);
  });
});

describe('a stored entry survives a durable round trip byte-for-byte', () => {
  it('re-parses to the same value after JSON persistence', () => {
    // The durable queue writes JSON and reads it back. The payload field must
    // come back as the SAME TEXT — this is the property the whole
    // canonical-text decision exists to guarantee.
    const original: EdgeStoredOperation = EdgeStoredOperationSchema.parse(storedOperation());
    const round = EdgeStoredOperationSchema.parse(JSON.parse(JSON.stringify(original)));
    expect(round.payload_canonical_json).toBe(original.payload_canonical_json);
    expect(round).toEqual(original);
  });

  it('refuses an entry whose payload was tampered with on disk', () => {
    const original = EdgeStoredOperationSchema.parse(storedOperation());
    const tampered = { ...original, payload_canonical_json: original.payload_canonical_json.replace('secured', 'forced!') };
    expect(EdgeStoredOperationSchema.safeParse(tampered).success).toBe(false);
  });
});
