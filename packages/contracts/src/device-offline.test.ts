import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  canonicalDeviceEdgeReceiptStatement,
  canonicalDeviceOfflineOperationStatement,
  classifyDevicePolicyLease,
  DEVICE_AUDIT_FORBIDDEN_FIELDS,
  DEVICE_COMMITTED_EVIDENCE_FORBIDDEN_FIELDS,
  DEVICE_EDGE_RECEIPT_DOMAIN,
  DEVICE_EDGE_RECEIPT_FORBIDDEN_FIELDS,
  DEVICE_OFFLINE_OPERATION_DOMAIN,
  DEVICE_OFFLINE_STALE_TOLERANT_OPERATION_KINDS,
  DEVICE_REVOCATION_RESPONSES,
  DeviceAuditPayloadSchema,
  DeviceCommittedEffectEvidenceSchema,
  DeviceEdgeReceiptSchema,
  DeviceOfflineOperationEnvelopeSchema,
  DevicePolicyLeaseSchema,
  DeviceEdgeTrustStatusSchema,
  EdgeRegistryKeyRecordSchema,
  deviceEdgeReceiptFingerprint,
  deviceEdgeReceiptStatementInput,
  deviceOfflineOperationFingerprint,
  deviceOfflineOperationReplayIdentity,
  deviceOfflineOperationReplayKey,
  deviceOfflineOperationRequiresTimeWitness,
  deviceOfflineOperationStatementInput,
  evaluateOfflineOperationAdmissibility,
  resolveRevokedDeviceOperation,
  type DeviceEdgeReceipt,
  type DeviceOfflineAdmissibilityInput,
  type DeviceOfflineOperationEnvelope,
  type DeviceOfflineOperationStatementInput,
  type DeviceOfflineWitness,
  type DevicePolicyLease,
  type EdgeRegistryKeyRecord,
} from './device-offline.js';
import {
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
  DEVICE_TIME_NOT_AUTHORITATIVE,
  DeviceNonceConsumptionSchema,
  DeviceRegistryKeyRecordSchema,
  DeviceRevocationDispositionSchema,
  deviceKeyStatePermitsHistoricalVerification,
  deviceKeyStatePermitsNewOperations,
  type DeviceNonceConsumption,
  type DeviceRegistryKeyRecord,
} from './device-identity.js';
import { deriveP256PublicKeyThumbprint } from './device-signature.js';
import { DEVICE_REQUEST_PROOF_DOMAIN } from './device-context.js';

/** WP-23 Crucible — offline envelope, Edge provenance, revocation and audit. */

const NOW = '2026-08-29T12:00:00.000Z';
const HOUR = 3_600_000;
const OP_ID = 'a3bb1a10-2c3d-4e5f-8a9b-0c1d2e3f4a5b';
const PAYLOAD_DIGEST = 'e'.repeat(64);
const OTHER_DIGEST = 'f'.repeat(64);
const SIGNATURE = Buffer.from(new Uint8Array(64).fill(11)).toString('base64url');
const EDGE_SIGNATURE = Buffer.from(new Uint8Array(64).fill(12)).toString('base64url');
const NONCE = 'nonce-0123456789abcdef';

/** C15-02: a real canonical P-256 point, because the Edge key schema decodes it. */
const EDGE_PUBLIC_KEY = Buffer.from(
  generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' }),
)
  .subarray(-65)
  .toString('base64url');
const EDGE_THUMBPRINT = deriveP256PublicKeyThumbprint(EDGE_PUBLIC_KEY);

/** C15-R4: the DEVICE's registry key record is an input now, so it needs a real point too. */
const DEVICE_PUBLIC_KEY = Buffer.from(
  generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ type: 'spki', format: 'der' }),
)
  .subarray(-65)
  .toString('base64url');
const DEVICE_THUMBPRINT = deriveP256PublicKeyThumbprint(DEVICE_PUBLIC_KEY);

function iso(deltaMs: number): string {
  return new Date(Date.parse(NOW) + deltaMs).toISOString();
}

/**
 * C15-01: the signed bytes carry the SERVER's profile. A test cannot hand an
 * envelope straight to the statement builder any more, which is the point.
 */
function offlineStatement(target: DeviceOfflineOperationEnvelope): DeviceOfflineOperationStatementInput {
  return deviceOfflineOperationStatementInput(target, 'P256_ECDSA_SHA256');
}

function edgeStatement(receipt: DeviceEdgeReceipt): ReturnType<typeof deviceEdgeReceiptStatementInput> {
  return deviceEdgeReceiptStatementInput(receipt, 'P256_ECDSA_SHA256');
}

function lease(overrides: Record<string, unknown> = {}): DevicePolicyLease {
  return DevicePolicyLeaseSchema.parse({
    schema_version: 1,
    lease_id: 'lease-1',
    organisation_id: 'org-1',
    site_id: 'site-1',
    device_id: 'device-1',
    actor_user_id: 'user-1',
    authority_basis_id: 'authority-basis-1',
    scope: ['FIELD_ASSIGNMENT_ACCEPT', 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE'],
    issued_at: iso(-HOUR),
    expires_at: iso(HOUR),
    ...overrides,
  });
}

/** A lease that was in force two hours ago and has since expired. */
function expiredLease(overrides: Record<string, unknown> = {}): DevicePolicyLease {
  return lease({ issued_at: iso(-3 * HOUR), expires_at: iso(-HOUR), ...overrides });
}

function envelope(overrides: Record<string, unknown> = {}): DeviceOfflineOperationEnvelope {
  return DeviceOfflineOperationEnvelopeSchema.parse({
    schema_version: 1,
    offline_operation_id: OP_ID,
    organisation_id: 'org-1',
    site_id: 'site-1',
    actor_user_id: 'user-1',
    device_id: 'device-1',
    key_id: 'key-1',
    key_version: 4,
    operation_kind: 'FIELD_ASSIGNMENT_ACCEPT',
    device_sequence: 7,
    idempotency_key: 'client-key-1',
    payload_digest: PAYLOAD_DIGEST,
    policy_lease_id: 'lease-1',
    nonce: NONCE,
    created_at: iso(-2 * HOUR),
    claimed_signature_profile: 'P256_ECDSA_SHA256',
    signature: SIGNATURE,
    ...overrides,
  });
}

function receiptFor(target: DeviceOfflineOperationEnvelope, overrides: Record<string, unknown> = {}): DeviceEdgeReceipt {
  return DeviceEdgeReceiptSchema.parse({
    schema_version: 1,
    edge_id: 'edge-17',
    edge_key_id: 'edge-key-1',
    edge_key_version: 1,
    witnessed_operation_fingerprint: deviceOfflineOperationFingerprint(offlineStatement(target)),
    edge_trusted_time: iso(-2 * HOUR),
    edge_monotonic_position: 4_211,
    claimed_edge_signature_profile: 'P256_ECDSA_SHA256',
    edge_signature: EDGE_SIGNATURE,
    ...overrides,
  });
}

/** C15-02: the Edge registry record that makes `edgeSignatureVerified` mean something. */
function edgeKeyRecord(overrides: Record<string, unknown> = {}): EdgeRegistryKeyRecord {
  return EdgeRegistryKeyRecordSchema.parse({
    schema_version: 1,
    organisation_id: 'org-1',
    edge_id: 'edge-17',
    edge_key_id: 'edge-key-1',
    edge_key_version: 1,
    public_key: EDGE_PUBLIC_KEY,
    public_key_thumbprint: EDGE_THUMBPRINT,
    signature_profile: 'P256_ECDSA_SHA256',
    status: 'CURRENT',
    edge_trust: 'TRUSTED',
    /** C15-R4: an Edge witnesses for named sites, never for the estate. */
    authorised_site_ids: ['site-1', 'site-2'],
    registered_at: iso(-100 * HOUR),
    revoked_at: null,
    ...overrides,
  });
}

/** C15-R4: the SERVER's registry record for the device key the envelope names. */
function deviceKeyRecord(overrides: Record<string, unknown> = {}): DeviceRegistryKeyRecord {
  return DeviceRegistryKeyRecordSchema.parse({
    schema_version: 1,
    organisation_id: 'org-1',
    device_id: 'device-1',
    key_id: 'key-1',
    key_version: 4,
    public_key: DEVICE_PUBLIC_KEY,
    public_key_thumbprint: DEVICE_THUMBPRINT,
    signature_profile: 'P256_ECDSA_SHA256',
    key_storage: 'HARDWARE_BACKED',
    status: 'CURRENT',
    registered_at: iso(-100 * HOUR),
    rotated_at: null,
    revoked_at: null,
    revocation_disposition: null,
    ...overrides,
  });
}

/** An Edge witness with its registry record, the shape C15-02 requires. */
function edgeWitness(
  target: DeviceOfflineOperationEnvelope,
  overrides: { receipt?: DeviceEdgeReceipt; registeredEdgeKey?: EdgeRegistryKeyRecord; edgeSignatureVerified?: boolean } = {},
): DeviceOfflineWitness {
  return {
    kind: 'EDGE',
    receipt: overrides.receipt ?? receiptFor(target),
    registeredEdgeKey: overrides.registeredEdgeKey ?? edgeKeyRecord(),
    edgeSignatureVerified: overrides.edgeSignatureVerified ?? true,
  };
}

/** C15-05: a store report shaped for the envelope actually being presented. */
function consumptionFor(target: DeviceOfflineOperationEnvelope, overrides: Record<string, unknown> = {}): DeviceNonceConsumption {
  // C15-R1: parsed, so every fixture built here is provably a consistent fact.
  // The malformed ones the guard exists to catch are built inline and cast.
  return DeviceNonceConsumptionSchema.parse({
    source: 'SENTINEL_NONCE_STORE',
    outcome: 'FIRST_SEEN',
    replay_key: deviceOfflineOperationReplayKey(target),
    statement_fingerprint: deviceOfflineOperationFingerprint(offlineStatement(target)),
    stored_outcome_ref: null,
    ...overrides,
  });
}

function admissibility(overrides: Partial<DeviceOfflineAdmissibilityInput> = {}): DeviceOfflineAdmissibilityInput {
  const target = overrides.envelope ?? envelope();
  return {
    envelope: target,
    lease: lease(),
    witness: edgeWitness(target),
    now: NOW,
    expectedPayloadDigest: PAYLOAD_DIGEST,
    deviceRevokedAt: null,
    signatureVerified: true,
    registeredKey: deviceKeyRecord(),
    consumption: consumptionFor(target),
    ...overrides,
  };
}

// ---------------------------------------------------------------------------

describe('the policy / authority lease (D23-11)', () => {
  it('accepts a lifetime exactly at DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS and refuses one millisecond past it', () => {
    expect(() => lease({ issued_at: NOW, expires_at: iso(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS) })).not.toThrow();
    expect(() => lease({ issued_at: NOW, expires_at: iso(DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS + 1) })).toThrow();
  });

  it('expires rather than assuming, and refuses before it is in force', () => {
    expect(classifyDevicePolicyLease(lease(), NOW)).toBe('VALID');
    expect(classifyDevicePolicyLease(lease(), iso(HOUR + 1))).toBe('EXPIRED');
    expect(classifyDevicePolicyLease(lease(), iso(-HOUR - 1))).toBe('NOT_YET_VALID');
  });

  it('draws its scope from the WP-20 allowlist, so an offline lease cannot authorise what the online contract refuses', () => {
    expect(() => lease({ scope: ['PATROL_CHECKPOINT_VERIFY'] })).toThrow();
    expect(() => lease({ scope: [] })).toThrow();
    expect(() => lease({ scope: ['FIELD_ASSIGNMENT_ACCEPT', 'FIELD_ASSIGNMENT_ACCEPT'] })).toThrow();
  });
});

describe('the canonical device-signed offline envelope (C14-04)', () => {
  it('refuses an operation missing its lease identity: the field is required and signed', () => {
    const withoutLease: Record<string, unknown> = { ...envelope() };
    delete withoutLease.policy_lease_id;
    expect(() => DeviceOfflineOperationEnvelopeSchema.parse(withoutLease)).toThrow();
    expect(() => envelope({ policy_lease_id: null })).toThrow();
  });

  it('uses domain tags distinct from the request-proof and Whisper statements', () => {
    expect(DEVICE_OFFLINE_OPERATION_DOMAIN).toBe('sentinel.device.offline-operation.v1');
    expect(DEVICE_OFFLINE_OPERATION_DOMAIN).not.toBe(DEVICE_REQUEST_PROOF_DOMAIN);
    expect(canonicalDeviceOfflineOperationStatement(offlineStatement(envelope()))).toContain(DEVICE_OFFLINE_OPERATION_DOMAIN);
  });

  it('excludes the signature from the bytes it signs', () => {
    expect(canonicalDeviceOfflineOperationStatement(offlineStatement(envelope()))).not.toContain(SIGNATURE);
  });

  it('changes the fingerprint for every individually mutated bound component, and never converges on the original', () => {
    const baseline = deviceOfflineOperationFingerprint(offlineStatement(envelope()));
    const mutations: Array<[string, DeviceOfflineOperationEnvelope]> = [
      ['offline_operation_id', envelope({ offline_operation_id: 'b4cc2b21-3d4e-4f60-9aab-1d2e3f4a5b6c' })],
      ['organisation_id', envelope({ organisation_id: 'org-2' })],
      ['site_id', envelope({ site_id: 'site-2' })],
      ['actor_user_id', envelope({ actor_user_id: 'user-2' })],
      ['device_id', envelope({ device_id: 'device-2' })],
      ['key_id', envelope({ key_id: 'key-2' })],
      ['key_version', envelope({ key_version: 5 })],
      ['operation_kind', envelope({ operation_kind: 'FIELD_ASSIGNMENT_DECLINE' })],
      ['device_sequence', envelope({ device_sequence: 8 })],
      ['idempotency_key', envelope({ idempotency_key: 'client-key-2' })],
      ['payload_digest', envelope({ payload_digest: OTHER_DIGEST })],
      ['policy_lease_id', envelope({ policy_lease_id: 'lease-2' })],
      ['nonce', envelope({ nonce: 'nonce-fedcba9876543210' })],
      ['created_at', envelope({ created_at: iso(-2 * HOUR - 1) })],
    ];
    const digests = new Set<string>([baseline]);
    for (const [label, mutated] of mutations) {
      const digest = deviceOfflineOperationFingerprint(offlineStatement(mutated));
      expect(digest, `${label} must move the fingerprint`).not.toBe(baseline);
      digests.add(digest);
    }
    expect(digests.size).toBe(mutations.length + 1);
  });

  it('carries a payload digest rather than the payload, so an envelope in an audit trail discloses nothing (D23-14)', () => {
    expect(() => envelope({ payload: { assignment_id: OP_ID } })).toThrow();
  });
});

describe('the Edge receipt witnesses time and never confers authority (D23-10 / C14-04)', () => {
  it('accepts a receipt that carries only time, and one that carries only a monotonic position', () => {
    const target = envelope();
    expect(() => receiptFor(target, { edge_monotonic_position: null })).not.toThrow();
    expect(() => receiptFor(target, { edge_trusted_time: null })).not.toThrow();
    expect(() => receiptFor(target, { edge_trusted_time: null, edge_monotonic_position: null })).toThrow();
  });

  it('LOCKED: has no field capable of conferring or claiming domain authority', () => {
    const target = envelope();
    for (const field of DEVICE_EDGE_RECEIPT_FORBIDDEN_FIELDS) {
      expect(() => receiptFor(target, { [field]: true }), `${field} must be structurally impossible`).toThrow();
    }
  });

  it('says only what it saw and when, never what it permits', () => {
    const statement = canonicalDeviceEdgeReceiptStatement(edgeStatement(receiptFor(envelope())));
    expect(statement).toContain(DEVICE_EDGE_RECEIPT_DOMAIN);
    for (const authorityWord of ['authoris', 'authoriz', 'approv', 'permit', 'decision', 'device_trust']) {
      expect(statement).not.toContain(authorityWord);
    }
  });

  it('binds the exact operation it witnessed, so a receipt cannot be moved onto another operation', () => {
    const a = receiptFor(envelope());
    const b = receiptFor(envelope({ device_sequence: 8 }));
    expect(a.witnessed_operation_fingerprint).not.toBe(b.witnessed_operation_fingerprint);
    expect(deviceEdgeReceiptFingerprint(edgeStatement(a))).not.toBe(deviceEdgeReceiptFingerprint(edgeStatement(b)));
  });
});

describe('offline admissibility (C14-04 / D23-11 / D23-12)', () => {
  it('admits a time-bounded operation an independently trusted Edge witnessed inside the lease window', () => {
    const decision = evaluateOfflineOperationAdmissibility(admissibility({ lease: expiredLease() }));
    expect(decision).toEqual({
      admitted: true,
      effect: 'PROCEED',
      time_basis: 'EDGE_WITNESS',
      established_at: iso(-2 * HOUR),
      operation_fingerprint: deviceOfflineOperationFingerprint(offlineStatement(envelope())),
    });
  });

  it('LOCKED: refuses a time-bounded operation with no trustworthy witness at all', () => {
    expect(evaluateOfflineOperationAdmissibility(admissibility({ witness: { kind: 'NONE' } }))).toEqual({
      admitted: false,
      refusal: 'NO_TRUSTWORTHY_TIME_WITNESS',
    });
  });

  it('refuses when the Edge itself has lost trust', () => {
    const target = envelope();
    for (const edgeTrust of ['SUSPENDED', 'REVOKED'] as const) {
      expect(
        evaluateOfflineOperationAdmissibility(
          admissibility({ witness: edgeWitness(target, { registeredEdgeKey: edgeKeyRecord({ edge_trust: edgeTrust, revoked_at: edgeTrust === 'REVOKED' ? NOW : null }) }) }),
        ),
      ).toEqual({ admitted: false, refusal: 'EDGE_NOT_TRUSTED' });
    }
  });

  it('refuses an Edge receipt whose own signature does not verify', () => {
    const target = envelope();
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({ witness: edgeWitness(target, { edgeSignatureVerified: false }) }),
      ),
    ).toEqual({ admitted: false, refusal: 'EDGE_SIGNATURE_NOT_VERIFIED' });
  });

  it('refuses a receipt that witnessed a different operation', () => {
    const target = envelope();
    const other = receiptFor(envelope({ device_sequence: 99 }));
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({ witness: edgeWitness(target, { receipt: other }) }),
      ),
    ).toEqual({ admitted: false, refusal: 'WITNESS_FINGERPRINT_MISMATCH' });
  });

  it('refuses a receipt carrying only a monotonic position, because ordering is not a clock', () => {
    const target = envelope();
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({
          witness: edgeWitness(target, { receipt: receiptFor(target, { edge_trusted_time: null }) }),
        }),
      ),
    ).toEqual({ admitted: false, refusal: 'NO_TRUSTWORTHY_TIME_WITNESS' });
  });

  it('LOCKED: a backdated client timestamp cannot revive an expired lease (C14-04)', () => {
    // The device swears it acted two hours ago, inside the lease. Nobody
    // independent saw it. `created_at` is never read, so the claim buys nothing.
    const backdated = admissibility({
      envelope: envelope({ created_at: iso(-2 * HOUR) }),
      lease: expiredLease(),
      witness: { kind: 'NONE' },
    });
    expect(evaluateOfflineOperationAdmissibility(backdated)).toEqual({ admitted: false, refusal: 'NO_TRUSTWORTHY_TIME_WITNESS' });

    // And with a witness that places it AFTER the lease expired, the device's
    // own earlier claim still does not rescue it.
    const target = envelope({ created_at: iso(-2 * HOUR) });
    const witnessedLate = admissibility({
      envelope: target,
      lease: expiredLease(),
      witness: edgeWitness(target, { receipt: receiptFor(target, { edge_trusted_time: iso(-1_800_000) }) }),
    });
    expect(evaluateOfflineOperationAdmissibility(witnessedLate)).toEqual({ admitted: false, refusal: 'LEASE_NOT_IN_FORCE' });
  });

  it('refuses a missing, misidentified or out-of-scope lease', () => {
    expect(evaluateOfflineOperationAdmissibility(admissibility({ lease: null }))).toEqual({ admitted: false, refusal: 'LEASE_MISSING' });
    expect(evaluateOfflineOperationAdmissibility(admissibility({ lease: lease({ lease_id: 'lease-9' }) }))).toEqual({
      admitted: false,
      refusal: 'LEASE_IDENTITY_MISMATCH',
    });
    expect(evaluateOfflineOperationAdmissibility(admissibility({ lease: lease({ device_id: 'device-9' }) }))).toEqual({
      admitted: false,
      refusal: 'LEASE_IDENTITY_MISMATCH',
    });
    expect(evaluateOfflineOperationAdmissibility(admissibility({ lease: lease({ site_id: 'site-9' }) }))).toEqual({
      admitted: false,
      refusal: 'LEASE_IDENTITY_MISMATCH',
    });
    expect(
      evaluateOfflineOperationAdmissibility(admissibility({ lease: lease({ scope: ['INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE'] }) })),
    ).toEqual({ admitted: false, refusal: 'LEASE_SCOPE_MISMATCH' });
  });

  it('refuses before any time reasoning when the device signature does not verify', () => {
    expect(evaluateOfflineOperationAdmissibility(admissibility({ signatureVerified: false }))).toEqual({
      admitted: false,
      refusal: 'SIGNATURE_NOT_VERIFIED',
    });
  });

  it('refuses when the arriving payload is not the payload the signature covers', () => {
    expect(evaluateOfflineOperationAdmissibility(admissibility({ expectedPayloadDigest: OTHER_DIGEST }))).toEqual({
      admitted: false,
      refusal: 'PAYLOAD_DIGEST_MISMATCH',
    });
  });

  it('judges a stale-tolerant operation against the server receipt clock, without an Edge (D23-12)', () => {
    expect(DEVICE_OFFLINE_STALE_TOLERANT_OPERATION_KINDS).toEqual(['INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE']);
    expect(deviceOfflineOperationRequiresTimeWitness('INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE')).toBe(false);
    expect(deviceOfflineOperationRequiresTimeWitness('FIELD_ASSIGNMENT_ACCEPT')).toBe(true);

    const ack = envelope({ operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE' });
    const decision = evaluateOfflineOperationAdmissibility(admissibility({ envelope: ack, witness: { kind: 'NONE' } }));
    expect(decision).toEqual({
      admitted: true,
      effect: 'PROCEED',
      time_basis: 'SERVER_RECEIPT',
      established_at: NOW,
      operation_fingerprint: deviceOfflineOperationFingerprint(offlineStatement(ack)),
    });
  });

  it('still refuses a stale-tolerant operation whose lease has expired by the server receipt clock', () => {
    const ack = envelope({ operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE' });
    expect(
      evaluateOfflineOperationAdmissibility(admissibility({ envelope: ack, lease: expiredLease(), witness: { kind: 'NONE' } })),
    ).toEqual({ admitted: false, refusal: 'LEASE_NOT_IN_FORCE' });
  });
});

describe('revocation is judged on server-known time (D23-08)', () => {
  it('refuses a queued operation from a revoked device wholesale, witness and lease notwithstanding', () => {
    expect(evaluateOfflineOperationAdmissibility(admissibility({ deviceRevokedAt: iso(-HOUR) }))).toEqual({
      admitted: false,
      refusal: 'CREDENTIAL_REVOKED',
    });
  });

  it('refuses even when the device claims the operation predates the revocation', () => {
    const claimedEarlier = admissibility({
      envelope: envelope({ created_at: iso(-5 * HOUR) }),
      deviceRevokedAt: iso(-HOUR),
      lease: expiredLease(),
    });
    expect(evaluateOfflineOperationAdmissibility(claimedEarlier)).toEqual({ admitted: false, refusal: 'CREDENTIAL_REVOKED' });
  });
});

describe('lost, stolen and compromised are three responses (D23-15 / C14-06)', () => {
  it('names exactly three dispositions', () => {
    expect(DeviceRevocationDispositionSchema.options).toEqual(['LOST', 'STOLEN', 'COMPROMISED_KEY']);
  });

  it('never permits queued domain execution under any disposition', () => {
    for (const disposition of DeviceRevocationDispositionSchema.options) {
      expect(DEVICE_REVOCATION_RESPONSES[disposition].queued_domain_execution).toBe(false);
      expect(DEVICE_REVOCATION_RESPONSES[disposition].invalidates_issued_contexts).toBe(true);
    }
  });

  it('quarantines a lost device but compromises a stolen one or a copied key', () => {
    expect(DEVICE_REVOCATION_RESPONSES.LOST.trust).toBe('QUARANTINED');
    expect(DEVICE_REVOCATION_RESPONSES.LOST.identity_restorable).toBe(true);
    expect(DEVICE_REVOCATION_RESPONSES.STOLEN.trust).toBe('COMPROMISED');
    expect(DEVICE_REVOCATION_RESPONSES.STOLEN.identity_restorable).toBe(false);
    expect(DEVICE_REVOCATION_RESPONSES.COMPROMISED_KEY.trust).toBe('COMPROMISED');
    expect(DEVICE_REVOCATION_RESPONSES.COMPROMISED_KEY.identity_restorable).toBe(false);
    expect(DEVICE_REVOCATION_RESPONSES.STOLEN.discards_edge_buffer).toBe(true);
  });
});

describe('recovery resolves committed effects and never admits unapplied work (C14-06)', () => {
  const OPERATION_FINGERPRINT = deviceOfflineOperationFingerprint(offlineStatement(envelope()));

  /** C15-06: evidence now names the exact bytes and the tenant scope. */
  const evidence = DeviceCommittedEffectEvidenceSchema.parse({
    source: 'SENTINEL_DOMAIN_RECORD',
    offline_operation_id: OP_ID,
    operation_fingerprint: OPERATION_FINGERPRINT,
    organisation_id: 'org-1',
    site_id: 'site-1',
    committed_at: iso(-4 * HOUR),
    domain_record_ref: 'assignment-42',
  });

  function resolution(overrides: Record<string, unknown> = {}) {
    return resolveRevokedDeviceOperation({
      disposition: 'STOLEN',
      offline_operation_id: OP_ID,
      operation_fingerprint: OPERATION_FINGERPRINT,
      organisation_id: 'org-1',
      site_id: 'site-1',
      priorCommittedEvidence: evidence,
      ...overrides,
    });
  }

  it('resolves an already-committed effect from the platform authoritative domain record, under every disposition', () => {
    for (const disposition of DeviceRevocationDispositionSchema.options) {
      expect(resolution({ disposition }).resolution).toBe('RESOLVE_AS_COMMITTED');
    }
  });

  it('refuses a new effect for a stolen device or a copied key when the work was never applied', () => {
    for (const disposition of ['STOLEN', 'COMPROMISED_KEY'] as const) {
      expect(resolution({ disposition, priorCommittedEvidence: null }).resolution).toBe('REFUSE_NEW_EFFECT');
    }
  });

  it('routes unapplied work from a merely lost device to human-attested re-entry', () => {
    expect(resolution({ disposition: 'LOST', priorCommittedEvidence: null }).resolution).toBe('REQUIRES_HUMAN_REENTRY');
  });

  it('does not let evidence about a different operation resolve this one', () => {
    const otherEvidence = DeviceCommittedEffectEvidenceSchema.parse({
      ...evidence,
      offline_operation_id: 'b4cc2b21-3d4e-4f60-9aab-1d2e3f4a5b6c',
    });
    expect(resolution({ priorCommittedEvidence: otherEvidence }).resolution).toBe('REFUSE_NEW_EFFECT');
  });

  it('LOCKED: the committed-effect evidence has no device-supplied field at all', () => {
    for (const field of DEVICE_COMMITTED_EVIDENCE_FORBIDDEN_FIELDS) {
      expect(
        () => DeviceCommittedEffectEvidenceSchema.parse({ ...evidence, [field]: 'device-said-so' }),
        `${field} must be structurally impossible`,
      ).toThrow();
    }
  });

  it('admits only a Sentinel domain record as a provenance source', () => {
    expect(() => DeviceCommittedEffectEvidenceSchema.parse({ ...evidence, source: 'DEVICE_QUEUE' })).toThrow();
    expect(() => DeviceCommittedEffectEvidenceSchema.parse({ ...evidence, source: 'EDGE_BUFFER' })).toThrow();
  });
});

describe('audit records the decision, never the secret (D23-14)', () => {
  const auditPayload = {
    schema_version: 1,
    event_type: 'ENROLLMENT_COMMITTED',
    organisation_id: 'org-1',
    site_id: 'site-1',
    device_id: 'device-1',
    actor_user_id: 'user-1',
    key_id: 'key-1',
    key_version: 1,
    from_trust: null,
    to_trust: 'TRUSTED',
    from_enrollment_state: 'POSSESSION_PROVEN',
    to_enrollment_state: 'ENROLLED',
    enrollment_request_fingerprint: PAYLOAD_DIGEST,
    operation_fingerprint: null,
    attestation_outcome: 'VERIFIED',
    attestation_standing: 'CURRENT',
    outcome: 'ACCEPTED',
    refusal_code: null,
    decided_by_user_id: 'commander-1',
    occurred_at: NOW,
    trace_id: 'trace-1',
  };

  it('reconstructs who did what, when, under which key, with which outcome', () => {
    expect(() => DeviceAuditPayloadSchema.parse(auditPayload)).not.toThrow();
  });

  it('LOCKED: refuses a private key, bootstrap token, attestation blob, nonce, challenge or context in the payload', () => {
    for (const field of DEVICE_AUDIT_FORBIDDEN_FIELDS) {
      expect(() => DeviceAuditPayloadSchema.parse({ ...auditPayload, [field]: 'leak' }), `${field} must be refused`).toThrow();
    }
  });

  it('carries digests and labels where a secret would otherwise sit', () => {
    const parsed = DeviceAuditPayloadSchema.parse(auditPayload);
    expect(parsed.enrollment_request_fingerprint).toMatch(/^[0-9a-f]{64}$/u);
    expect(parsed.attestation_outcome).toBe('VERIFIED');
    expect(Object.keys(parsed)).not.toContain('attestation_blob');
  });
});

// ---------------------------------------------------------------------------
// C15 corrections
// ---------------------------------------------------------------------------

describe('C15-01 the offline envelope and Edge receipt do not choose their profile', () => {
  it('names both profile fields as CLAIMS, and refuses the old authoritative names', () => {
    expect(envelope().claimed_signature_profile).toBe('P256_ECDSA_SHA256');
    expect(() => envelope({ signature_profile: 'P256_ECDSA_SHA256' })).toThrow();
    expect(receiptFor(envelope()).claimed_edge_signature_profile).toBe('P256_ECDSA_SHA256');
    expect(() => receiptFor(envelope(), { edge_signature_profile: 'P256_ECDSA_SHA256' })).toThrow();
  });

  it('LOCKED: an envelope claiming a profile the registry did not select refuses', () => {
    // C15-R4: the profile is read out of the registry KEY RECORD now, so the
    // mismatch is staged there — the record schema itself will not store an
    // unapproved profile, which is why it is built by hand past the parse.
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({ registeredKey: { ...deviceKeyRecord(), signature_profile: 'Ed25519' as never } }),
      ),
    ).toEqual({
      admitted: false,
      refusal: 'SIGNATURE_PROFILE_CLAIM_MISMATCH',
    });
  });

  it('LOCKED: a receipt claiming a profile the Edge registry did not select refuses', () => {
    const target = envelope();
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({
          envelope: target,
          // Built by hand: the Edge REGISTRY schema will not itself store an
          // unapproved profile, so the mismatch has to be staged past it.
          witness: edgeWitness(target, {
            registeredEdgeKey: { ...edgeKeyRecord(), signature_profile: 'Ed25519' as never },
          }),
        }),
      ),
    ).toEqual({ admitted: false, refusal: 'EDGE_SIGNATURE_PROFILE_CLAIM_MISMATCH' });
  });

  it('COMPOUND: a whole envelope or receipt carrying a non-canonical signature fails to PARSE', () => {
    const highS = Buffer.concat([Buffer.alloc(32, 1), Buffer.alloc(32, 0xff)]).toString('base64url');
    const zeroS = Buffer.concat([Buffer.alloc(32, 1), Buffer.alloc(32)]).toString('base64url');
    const shortSig = Buffer.alloc(48).toString('base64url');
    const shapeOnly = 'A'.repeat(86);
    for (const [label, signature] of [
      ['high s', highS],
      ['zero s', zeroS],
      ['wrong length', shortSig],
      ['non-canonical 86 chars', shapeOnly],
    ] as Array<[string, string]>) {
      expect(DeviceOfflineOperationEnvelopeSchema.safeParse({ ...envelope(), signature }).success, label).toBe(false);
      expect(
        DeviceEdgeReceiptSchema.safeParse({ ...receiptFor(envelope()), edge_signature: signature }).success,
        `receipt ${label}`,
      ).toBe(false);
    }
  });

  it('the canonical statements bind the SERVER profile, never the claim', () => {
    const built = offlineStatement(envelope());
    expect(built).not.toHaveProperty('claimed_signature_profile');
    expect(built.signature_profile).toBe('P256_ECDSA_SHA256');
    const edgeBuilt = edgeStatement(receiptFor(envelope()));
    expect(edgeBuilt).not.toHaveProperty('claimed_edge_signature_profile');
    expect(edgeBuilt.edge_signature_profile).toBe('P256_ECDSA_SHA256');
  });
});

describe('C15-02 the Edge registry seam makes an Edge signature verifiable', () => {
  it('carries the actual Edge key, and refuses an undelivered thumbprint', () => {
    expect(edgeKeyRecord().public_key).toBe(EDGE_PUBLIC_KEY);
    expect(() => edgeKeyRecord({ public_key_thumbprint: 'a'.repeat(64) })).toThrow();
    expect(() => edgeKeyRecord({ public_key: 'not-a-point' })).toThrow();
    expect(() => edgeKeyRecord({ status: 'REVOKED' })).toThrow();
    expect(() => edgeKeyRecord({ status: 'REVOKED', revoked_at: NOW })).not.toThrow();
  });

  it('separates the KEY lifecycle from the EDGE principal trust', () => {
    expect([...DeviceEdgeTrustStatusSchema.options]).toEqual(['TRUSTED', 'SUSPENDED', 'REVOKED']);
    // A perfectly valid key belonging to a suspended Edge witnesses nothing.
    const target = envelope();
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({ envelope: target, witness: edgeWitness(target, { registeredEdgeKey: edgeKeyRecord({ edge_trust: 'SUSPENDED' }) }) }),
      ),
    ).toEqual({ admitted: false, refusal: 'EDGE_NOT_TRUSTED' });
  });

  it('LOCKED: an Edge key record for a DIFFERENT key, or one that can no longer verify, refuses', () => {
    const target = envelope();
    const cases: Array<[string, EdgeRegistryKeyRecord]> = [
      ['another edge', edgeKeyRecord({ edge_id: 'edge-99' })],
      ['another key id', edgeKeyRecord({ edge_key_id: 'edge-key-9' })],
      ['another key version', edgeKeyRecord({ edge_key_version: 2 })],
      ['revoked key', edgeKeyRecord({ status: 'REVOKED', revoked_at: NOW })],
      ['compromised key', edgeKeyRecord({ status: 'COMPROMISED', revoked_at: NOW })],
    ];
    for (const [label, registeredEdgeKey] of cases) {
      expect(
        evaluateOfflineOperationAdmissibility(admissibility({ envelope: target, witness: edgeWitness(target, { registeredEdgeKey }) })),
        label,
      ).toEqual({ admitted: false, refusal: 'EDGE_KEY_NOT_USABLE' });
    }
    // A ROTATED Edge key may still verify what it legitimately signed. (The
    // lease is the expired one, because the witnessed instant is two hours old.)
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({
          envelope: target,
          lease: expiredLease(),
          witness: edgeWitness(target, { registeredEdgeKey: edgeKeyRecord({ status: 'ROTATED' }) }),
        }),
      ).admitted,
    ).toBe(true);
  });
});

describe('C15-06 the lease binds the actor whose authority justified it', () => {
  it('records the actor and the authority basis', () => {
    expect(lease().actor_user_id).toBe('user-1');
    expect(lease().authority_basis_id).toBe('authority-basis-1');
  });

  it('LOCKED: on a CONTROLLED_SHARED device, actor B cannot ride actor A lease', () => {
    // Operative A holds the capability and caused the lease to be issued.
    // The device passes to operative B at shift change. B signs a perfectly
    // valid envelope naming the same device and the same lease.
    const shiftTwo = envelope({ actor_user_id: 'user-2' });
    const decision = evaluateOfflineOperationAdmissibility(
      admissibility({ envelope: shiftTwo, lease: lease({ actor_user_id: 'user-1' }) }),
    );
    expect(decision).toEqual({ admitted: false, refusal: 'LEASE_ACTOR_MISMATCH' });

    // B's own lease, for B, is admitted — the device is legitimately shared.
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({ envelope: shiftTwo, lease: expiredLease({ actor_user_id: 'user-2' }) }),
      ).admitted,
    ).toBe(true);
  });
});

describe('C15-06 committed-effect evidence binds the operation and its tenant', () => {
  const OPERATION_FINGERPRINT = deviceOfflineOperationFingerprint(offlineStatement(envelope()));

  function evidenceRecord(overrides: Record<string, unknown> = {}) {
    return DeviceCommittedEffectEvidenceSchema.parse({
      source: 'SENTINEL_DOMAIN_RECORD',
      offline_operation_id: OP_ID,
      operation_fingerprint: OPERATION_FINGERPRINT,
      organisation_id: 'org-1',
      site_id: 'site-1',
      committed_at: iso(-4 * HOUR),
      domain_record_ref: 'assignment-42',
      ...overrides,
    });
  }

  function resolve(overrides: Record<string, unknown> = {}) {
    return resolveRevokedDeviceOperation({
      disposition: 'STOLEN',
      offline_operation_id: OP_ID,
      operation_fingerprint: OPERATION_FINGERPRINT,
      organisation_id: 'org-1',
      site_id: 'site-1',
      priorCommittedEvidence: evidenceRecord(),
      ...overrides,
    });
  }

  it('resolves as committed only when the fingerprint AND tenant scope both match', () => {
    expect(resolve().resolution).toBe('RESOLVE_AS_COMMITTED');
  });

  it('LOCKED: a reused operation id carrying DIFFERENT bytes is a CONFLICT, never resolved as committed', () => {
    // The WP-20 request-bound idempotency rule. An id is a value the device
    // chooses; without the fingerprint, "already committed" could be claimed
    // about an operation Sentinel never saw.
    const rewritten = deviceOfflineOperationFingerprint(offlineStatement(envelope({ payload_digest: OTHER_DIGEST })));
    expect(rewritten).not.toBe(OPERATION_FINGERPRINT);
    expect(resolve({ operation_fingerprint: rewritten })).toMatchObject({ resolution: 'CONFLICT' });
    // And the mirror image: evidence about other bytes under this id.
    expect(resolve({ priorCommittedEvidence: evidenceRecord({ operation_fingerprint: rewritten }) })).toMatchObject({
      resolution: 'CONFLICT',
    });
  });

  it('LOCKED: evidence from another organisation or site cannot resolve this operation', () => {
    expect(resolve({ priorCommittedEvidence: evidenceRecord({ organisation_id: 'org-9' }) })).toMatchObject({ resolution: 'CONFLICT' });
    expect(resolve({ priorCommittedEvidence: evidenceRecord({ site_id: 'site-9' }) })).toMatchObject({ resolution: 'CONFLICT' });
  });

  it('a CONFLICT causes no effect at all, under every disposition', () => {
    const rewritten = 'a'.repeat(64);
    for (const disposition of DeviceRevocationDispositionSchema.options) {
      expect(resolve({ disposition, operation_fingerprint: rewritten }).resolution, disposition).toBe('CONFLICT');
    }
  });
});

describe('C15-05 the offline envelope nonce is one-shot through a contract seam', () => {
  it('scopes the replay identity to org, site, actor, device, key version and nonce', () => {
    expect(deviceOfflineOperationReplayIdentity(envelope())).toEqual({
      organisation_id: 'org-1',
      site_id: 'site-1',
      actor_user_id: 'user-1',
      device_id: 'device-1',
      key_version: 4,
      nonce: NONCE,
    });
    expect(deviceOfflineOperationReplayKey(envelope())).not.toBe(deviceOfflineOperationReplayKey(envelope({ actor_user_id: 'user-2' })));
    // C11-01: canonical JSON, so a delimiter inside a value cannot forge a tuple.
    expect(deviceOfflineOperationReplayKey(envelope({ organisation_id: 'a:b', site_id: 'c' }))).not.toBe(
      deviceOfflineOperationReplayKey(envelope({ organisation_id: 'a', site_id: 'b:c' })),
    );
  });

  it('is DISTINCT from the operation fingerprint, which is what separates a retry from a rewrite', () => {
    const target = envelope();
    const rewritten = envelope({ payload_digest: OTHER_DIGEST });
    expect(deviceOfflineOperationReplayKey(rewritten)).toBe(deviceOfflineOperationReplayKey(target));
    expect(deviceOfflineOperationFingerprint(offlineStatement(rewritten))).not.toBe(
      deviceOfflineOperationFingerprint(offlineStatement(target)),
    );
  });

  it('a reconnecting queue that re-sends CONVERGES rather than committing twice', () => {
    const target = envelope();
    const decision = evaluateOfflineOperationAdmissibility(
      admissibility({
        envelope: target,
        lease: expiredLease(),
        consumption: consumptionFor(target, { outcome: 'EXACT_DUPLICATE', stored_outcome_ref: 'assignment-42' }),
      }),
    );
    expect(decision).toEqual({
      admitted: true,
      effect: 'CONVERGE_ON_STORED_OUTCOME',
      time_basis: 'EDGE_WITNESS',
      established_at: iso(-2 * HOUR),
      operation_fingerprint: deviceOfflineOperationFingerprint(offlineStatement(target)),
      stored_outcome_ref: 'assignment-42',
    });
  });

  it('LOCKED: the same slot carrying CHANGED semantics conflicts and causes nothing', () => {
    const target = envelope();
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({ envelope: target, consumption: consumptionFor(target, { outcome: 'REUSED_WITH_CHANGED_SEMANTICS' }) }),
      ),
    ).toEqual({ admitted: false, refusal: 'NONCE_REUSED_WITH_CHANGED_SEMANTICS' });
  });

  it('LOCKED: a consumption fact about ANOTHER operation cannot stand in for this one', () => {
    const target = envelope();
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({ envelope: target, consumption: consumptionFor(envelope({ nonce: 'nonce-fedcba9876543210' })) }),
      ),
    ).toEqual({ admitted: false, refusal: 'NONCE_CONSUMPTION_MISBOUND' });
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({ envelope: target, consumption: consumptionFor(target, { statement_fingerprint: 'b'.repeat(64) }) }),
      ),
    ).toEqual({ admitted: false, refusal: 'NONCE_CONSUMPTION_MISBOUND' });
  });

  it('the consumption fact cannot be defaulted away: it is a required input', () => {
    const { consumption, ...withoutFact } = admissibility();
    expect(consumption).toBeDefined();
    expect(Object.keys(withoutFact)).not.toContain('consumption');
    // C15-R1: an absent fact used to crash on a property access. It is now a
    // NAMED refusal — auditable rather than a 500, and still no effect.
    expect(evaluateOfflineOperationAdmissibility(withoutFact as unknown as DeviceOfflineAdmissibilityInput)).toEqual({
      admitted: false,
      refusal: 'NONCE_CONSUMPTION_INCONSISTENT',
    });
  });
});

describe('C15-R4 reconciliation is bound to exact tenant, site and key authority', () => {
  it('LOCKED: a FOREIGN TENANT Edge is not evidence about this operation at all', () => {
    const target = envelope();
    // `organisation_id` had been on the Edge record since C15-02 and was never
    // compared to anything, so any registered Edge in the estate could witness
    // any tenant's work into a lease window.
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({
          envelope: target,
          witness: edgeWitness(target, { registeredEdgeKey: edgeKeyRecord({ organisation_id: 'org-9' }) }),
        }),
      ),
    ).toEqual({ admitted: false, refusal: 'EDGE_ORGANISATION_MISMATCH' });
  });

  it('LOCKED: an Edge with no presence at the operation’s site witnessed nothing', () => {
    const target = envelope();
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({
          envelope: target,
          witness: edgeWitness(target, { registeredEdgeKey: edgeKeyRecord({ authorised_site_ids: ['site-7'] }) }),
        }),
      ),
    ).toEqual({ admitted: false, refusal: 'EDGE_SITE_NOT_AUTHORISED' });
  });

  it('the tenant and site checks run FIRST in the Edge branch, ahead of any question about its key', () => {
    const target = envelope();
    // A foreign Edge whose key is ALSO unusable still reports the tenant
    // mismatch: asking whether its key verifies would concede it might have
    // been evidence.
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({
          envelope: target,
          witness: edgeWitness(target, {
            registeredEdgeKey: edgeKeyRecord({ organisation_id: 'org-9', status: 'REVOKED', revoked_at: iso(-HOUR), edge_trust: 'REVOKED' }),
          }),
        }),
      ),
    ).toEqual({ admitted: false, refusal: 'EDGE_ORGANISATION_MISMATCH' });
  });

  it('an Edge record must name the sites it may witness for, with no org-wide wildcard', () => {
    expect(edgeKeyRecord().authorised_site_ids).toEqual(['site-1', 'site-2']);
    // Empty is not "all sites" — it is a record that authorises nothing, and
    // the schema refuses it rather than letting it read as a wildcard.
    expect(() => edgeKeyRecord({ authorised_site_ids: [] })).toThrow();
    expect(() => edgeKeyRecord({ authorised_site_ids: undefined })).toThrow();
  });

  it('LOCKED: a device key record about another organisation or another device is not evidence here', () => {
    for (const overrides of [{ organisation_id: 'org-9' }, { device_id: 'device-9' }]) {
      expect(evaluateOfflineOperationAdmissibility(admissibility({ registeredKey: deviceKeyRecord(overrides) })), JSON.stringify(overrides)).toEqual({
        admitted: false,
        refusal: 'REGISTRY_IDENTITY_MISMATCH',
      });
    }
  });

  it('LOCKED: a record about a different key or key VERSION refuses (D23-09: a rotation is a new credential)', () => {
    expect(evaluateOfflineOperationAdmissibility(admissibility({ registeredKey: deviceKeyRecord({ key_id: 'key-9' }) }))).toEqual({
      admitted: false,
      refusal: 'REGISTRY_KEY_MISMATCH',
    });
    expect(evaluateOfflineOperationAdmissibility(admissibility({ registeredKey: deviceKeyRecord({ key_version: 9 }) }))).toEqual({
      admitted: false,
      refusal: 'REGISTRY_KEY_MISMATCH',
    });
  });

  it('LOCKED: REVOKED, COMPROMISED and ROTATED keys cannot cause a new offline effect', () => {
    const states: Array<[string, Record<string, unknown>]> = [
      ['REVOKED', { status: 'REVOKED', revoked_at: iso(-HOUR), revocation_disposition: 'STOLEN' }],
      ['COMPROMISED', { status: 'COMPROMISED', revoked_at: iso(-HOUR), revocation_disposition: 'COMPROMISED_KEY' }],
      ['ROTATED', { status: 'ROTATED', rotated_at: iso(-HOUR) }],
    ];
    for (const [label, overrides] of states) {
      expect(evaluateOfflineOperationAdmissibility(admissibility({ registeredKey: deviceKeyRecord(overrides) })), label).toEqual({
        admitted: false,
        refusal: 'DEVICE_KEY_NOT_USABLE',
      });
    }
  });

  it('ROTATED specifically: a key may still VERIFY history and still not AUTHORISE fresh work', () => {
    // This is the distinction the two lifecycle predicates exist to keep apart.
    // An offline operation being reconciled has NOT been applied yet, so
    // admitting it creates its effect NOW, under a key we already replaced.
    expect(deviceKeyStatePermitsHistoricalVerification('ROTATED')).toBe(true);
    expect(deviceKeyStatePermitsNewOperations('ROTATED')).toBe(false);
    expect(evaluateOfflineOperationAdmissibility(admissibility({ registeredKey: deviceKeyRecord({ status: 'ROTATED', rotated_at: iso(-HOUR) }) }))).toEqual({
      admitted: false,
      refusal: 'DEVICE_KEY_NOT_USABLE',
    });
  });

  it('LOCKED: the NON-ATOMIC case — the key registry says revoked while deviceRevokedAt is still null', () => {
    // The two sources are separate writes to separate places and the window in
    // which one has landed and the other has not is ordinary. Either one
    // saying "revoked" is sufficient; they are never required to agree.
    //
    // Built by hand past the parse for the same reason as the profile-mismatch
    // case above: the record schema will not itself pair CURRENT with a
    // revocation instant, so a store that assembles the record from a row is
    // where this shape actually arises.
    const nonAtomic = { ...deviceKeyRecord(), revoked_at: iso(-HOUR) };
    expect(evaluateOfflineOperationAdmissibility(admissibility({ registeredKey: nonAtomic, deviceRevokedAt: null }))).toEqual({
      admitted: false,
      refusal: 'CREDENTIAL_REVOKED',
    });
    // And the original check is untouched, in its original place.
    expect(evaluateOfflineOperationAdmissibility(admissibility({ deviceRevokedAt: iso(-HOUR) }))).toEqual({
      admitted: false,
      refusal: 'CREDENTIAL_REVOKED',
    });
  });

  it('the happy path still admits: a CURRENT, correctly-bound key and a correctly-scoped Edge', () => {
    const target = envelope();
    // The lease that was in force at the moment the Edge witnessed the work —
    // which is the whole point of having an independent time witness.
    expect(evaluateOfflineOperationAdmissibility(admissibility({ envelope: target, lease: expiredLease() }))).toEqual({
      admitted: true,
      effect: 'PROCEED',
      time_basis: 'EDGE_WITNESS',
      established_at: iso(-2 * HOUR),
      operation_fingerprint: deviceOfflineOperationFingerprint(offlineStatement(target)),
    });
  });
});

describe('C15-R1 a malformed duplicate can never reach PROCEED', () => {
  function malformed(target: DeviceOfflineOperationEnvelope): Array<[string, DeviceNonceConsumption]> {
    const wellFormed = consumptionFor(target);
    const base = {
      source: 'SENTINEL_NONCE_STORE',
      replay_key: wellFormed.replay_key,
      statement_fingerprint: wellFormed.statement_fingerprint,
    };
    return (
      [
        ['EXACT_DUPLICATE with a null ref', { ...base, outcome: 'EXACT_DUPLICATE', stored_outcome_ref: null }],
        ['EXACT_DUPLICATE with an empty ref', { ...base, outcome: 'EXACT_DUPLICATE', stored_outcome_ref: '' }],
        ['EXACT_DUPLICATE with a blank ref', { ...base, outcome: 'EXACT_DUPLICATE', stored_outcome_ref: '   ' }],
        ['FIRST_SEEN carrying a stored ref', { ...base, outcome: 'FIRST_SEEN', stored_outcome_ref: 'assignment-42' }],
        ['a foreign source', { ...base, source: 'EDGE_CLAIM', outcome: 'FIRST_SEEN', stored_outcome_ref: null }],
        ['a missing outcome', { ...base, stored_outcome_ref: null }],
        ['a missing stored_outcome_ref', { ...base, outcome: 'EXACT_DUPLICATE' }],
      ] as Array<[string, unknown]>
    ).map(([label, fact]) => [label, fact as DeviceNonceConsumption]);
  }

  it('LOCKED: every malformed fact refuses, on both the Edge-witness and server-receipt exits', () => {
    // THE DEFECT: `storedOutcomeRef = outcome === 'EXACT_DUPLICATE' ? ref : null`
    // and then `if (storedOutcomeRef !== null) converge` — else PROCEED, at
    // BOTH exits. A reconnecting queue re-sends by design, so this evaluator
    // saw more duplicates than any other, and a duplicate with a missing
    // pointer APPLIED THE QUEUED OPERATION A SECOND TIME.
    const timeBound = envelope();
    const staleTolerant = envelope({ operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE' });
    for (const target of [timeBound, staleTolerant]) {
      for (const [label, fact] of malformed(target)) {
        expect(
          evaluateOfflineOperationAdmissibility(admissibility({ envelope: target, witness: edgeWitness(target), consumption: fact })),
          `${target.operation_kind} / ${label}`,
        ).toEqual({ admitted: false, refusal: 'NONCE_CONSUMPTION_INCONSISTENT' });
      }
    }
  });

  it('a well-formed EXACT_DUPLICATE still converges at both exits', () => {
    const target = envelope();
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({
          envelope: target,
          lease: expiredLease(),
          consumption: consumptionFor(target, { outcome: 'EXACT_DUPLICATE', stored_outcome_ref: 'assignment-42' }),
        }),
      ),
    ).toMatchObject({ admitted: true, effect: 'CONVERGE_ON_STORED_OUTCOME', time_basis: 'EDGE_WITNESS', stored_outcome_ref: 'assignment-42' });

    const stale = envelope({ operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE' });
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({
          envelope: stale,
          witness: { kind: 'NONE' },
          consumption: consumptionFor(stale, { outcome: 'EXACT_DUPLICATE', stored_outcome_ref: 'ack-7' }),
        }),
      ),
    ).toMatchObject({ admitted: true, effect: 'CONVERGE_ON_STORED_OUTCOME', time_basis: 'SERVER_RECEIPT', stored_outcome_ref: 'ack-7' });
  });
});

describe('C15-07 the offline evaluator fails closed on time', () => {
  it('treats the lease expiry as an EXCLUSIVE boundary, asserted exactly at the instant', () => {
    const l = lease({ issued_at: iso(-HOUR), expires_at: NOW });
    expect(classifyDevicePolicyLease(l, iso(-1))).toBe('VALID');
    expect(classifyDevicePolicyLease(l, NOW)).toBe('EXPIRED');
    // And it is valid at exactly the issuance instant.
    expect(classifyDevicePolicyLease(l, iso(-HOUR))).toBe('VALID');
    expect(classifyDevicePolicyLease(l, iso(-HOUR - 1))).toBe('NOT_YET_VALID');
  });

  it('answers TIME_NOT_AUTHORITATIVE rather than VALID for an unreadable instant', () => {
    expect(classifyDevicePolicyLease(lease(), 'not-a-time')).toBe(DEVICE_TIME_NOT_AUTHORITATIVE);
  });

  it('LOCKED: an unreadable server receipt clock refuses a stale-tolerant operation', () => {
    const ack = envelope({ operation_kind: 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE' });
    expect(
      evaluateOfflineOperationAdmissibility(admissibility({ envelope: ack, witness: { kind: 'NONE' }, now: 'not-a-time' })),
    ).toEqual({ admitted: false, refusal: DEVICE_TIME_NOT_AUTHORITATIVE });
  });

  it('LOCKED: an unreadable Edge-witnessed instant is not a witness at all', () => {
    const target = envelope();
    // Defence in depth: the receipt SCHEMA already refuses a non-datetime, so
    // this is staged past the parse to prove the evaluator would not admit on a
    // NaN comparison if the value ever reached it by another route.
    expect(() => receiptFor(target, { edge_trusted_time: 'whenever' })).toThrow();
    const staged = { ...receiptFor(target), edge_trusted_time: 'whenever' } as DeviceEdgeReceipt;
    expect(
      evaluateOfflineOperationAdmissibility(admissibility({ envelope: target, witness: edgeWitness(target, { receipt: staged }) })),
    ).toEqual({ admitted: false, refusal: DEVICE_TIME_NOT_AUTHORITATIVE });
  });

  it('refuses an impossible lease window through the one shared refinement', () => {
    expect(() => lease({ issued_at: NOW, expires_at: NOW })).toThrow(/after issued_at/u);
    expect(() => lease({ issued_at: NOW, expires_at: iso(-1) })).toThrow(/after issued_at/u);
  });
});
