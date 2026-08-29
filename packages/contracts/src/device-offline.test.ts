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
  DeviceRevocationDispositionSchema,
  deviceEdgeReceiptFingerprint,
  deviceOfflineOperationFingerprint,
  deviceOfflineOperationRequiresTimeWitness,
  evaluateOfflineOperationAdmissibility,
  resolveRevokedDeviceOperation,
  type DeviceEdgeReceipt,
  type DeviceOfflineAdmissibilityInput,
  type DeviceOfflineOperationEnvelope,
  type DeviceOfflineOperationStatementInput,
  type DevicePolicyLease,
} from './device-offline.js';
import { DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS } from './device-identity.js';
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

function iso(deltaMs: number): string {
  return new Date(Date.parse(NOW) + deltaMs).toISOString();
}

function lease(overrides: Record<string, unknown> = {}): DevicePolicyLease {
  return DevicePolicyLeaseSchema.parse({
    schema_version: 1,
    lease_id: 'lease-1',
    organisation_id: 'org-1',
    site_id: 'site-1',
    device_id: 'device-1',
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
    signature_profile: 'P256_ECDSA_SHA256',
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
    witnessed_operation_fingerprint: deviceOfflineOperationFingerprint(target),
    edge_trusted_time: iso(-2 * HOUR),
    edge_monotonic_position: 4_211,
    edge_signature_profile: 'P256_ECDSA_SHA256',
    edge_signature: EDGE_SIGNATURE,
    ...overrides,
  });
}

function admissibility(overrides: Partial<DeviceOfflineAdmissibilityInput> = {}): DeviceOfflineAdmissibilityInput {
  const target = overrides.envelope ?? envelope();
  return {
    envelope: target,
    lease: lease(),
    witness: { kind: 'EDGE', receipt: receiptFor(target), edgeTrust: 'TRUSTED', edgeSignatureVerified: true },
    now: NOW,
    expectedPayloadDigest: PAYLOAD_DIGEST,
    deviceRevokedAt: null,
    signatureVerified: true,
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
    expect(canonicalDeviceOfflineOperationStatement(envelope())).toContain(DEVICE_OFFLINE_OPERATION_DOMAIN);
  });

  it('excludes the signature from the bytes it signs', () => {
    expect(canonicalDeviceOfflineOperationStatement(envelope())).not.toContain(SIGNATURE);
  });

  it('changes the fingerprint for every individually mutated bound component, and never converges on the original', () => {
    const baseline = deviceOfflineOperationFingerprint(envelope());
    const mutations: Array<[string, DeviceOfflineOperationStatementInput]> = [
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
      const digest = deviceOfflineOperationFingerprint(mutated);
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
    const statement = canonicalDeviceEdgeReceiptStatement(receiptFor(envelope()));
    expect(statement).toContain(DEVICE_EDGE_RECEIPT_DOMAIN);
    for (const authorityWord of ['authoris', 'authoriz', 'approv', 'permit', 'decision', 'device_trust']) {
      expect(statement).not.toContain(authorityWord);
    }
  });

  it('binds the exact operation it witnessed, so a receipt cannot be moved onto another operation', () => {
    const a = receiptFor(envelope());
    const b = receiptFor(envelope({ device_sequence: 8 }));
    expect(a.witnessed_operation_fingerprint).not.toBe(b.witnessed_operation_fingerprint);
    expect(deviceEdgeReceiptFingerprint(a)).not.toBe(deviceEdgeReceiptFingerprint(b));
  });
});

describe('offline admissibility (C14-04 / D23-11 / D23-12)', () => {
  it('admits a time-bounded operation an independently trusted Edge witnessed inside the lease window', () => {
    const decision = evaluateOfflineOperationAdmissibility(admissibility({ lease: expiredLease() }));
    expect(decision).toEqual({
      admitted: true,
      time_basis: 'EDGE_WITNESS',
      established_at: iso(-2 * HOUR),
      operation_fingerprint: deviceOfflineOperationFingerprint(envelope()),
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
    for (const edgeTrust of ['DEGRADED', 'SUSPICIOUS', 'QUARANTINED', 'COMPROMISED', 'OFFLINE'] as const) {
      expect(
        evaluateOfflineOperationAdmissibility(
          admissibility({ witness: { kind: 'EDGE', receipt: receiptFor(target), edgeTrust, edgeSignatureVerified: true } }),
        ),
      ).toEqual({ admitted: false, refusal: 'EDGE_NOT_TRUSTED' });
    }
  });

  it('refuses an Edge receipt whose own signature does not verify', () => {
    const target = envelope();
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({ witness: { kind: 'EDGE', receipt: receiptFor(target), edgeTrust: 'TRUSTED', edgeSignatureVerified: false } }),
      ),
    ).toEqual({ admitted: false, refusal: 'EDGE_SIGNATURE_NOT_VERIFIED' });
  });

  it('refuses a receipt that witnessed a different operation', () => {
    const other = receiptFor(envelope({ device_sequence: 99 }));
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({ witness: { kind: 'EDGE', receipt: other, edgeTrust: 'TRUSTED', edgeSignatureVerified: true } }),
      ),
    ).toEqual({ admitted: false, refusal: 'WITNESS_FINGERPRINT_MISMATCH' });
  });

  it('refuses a receipt carrying only a monotonic position, because ordering is not a clock', () => {
    const target = envelope();
    expect(
      evaluateOfflineOperationAdmissibility(
        admissibility({
          witness: {
            kind: 'EDGE',
            receipt: receiptFor(target, { edge_trusted_time: null }),
            edgeTrust: 'TRUSTED',
            edgeSignatureVerified: true,
          },
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
      witness: {
        kind: 'EDGE',
        receipt: receiptFor(target, { edge_trusted_time: iso(-1_800_000) }),
        edgeTrust: 'TRUSTED',
        edgeSignatureVerified: true,
      },
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
      time_basis: 'SERVER_RECEIPT',
      established_at: NOW,
      operation_fingerprint: deviceOfflineOperationFingerprint(ack),
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
  const evidence = DeviceCommittedEffectEvidenceSchema.parse({
    source: 'SENTINEL_DOMAIN_RECORD',
    offline_operation_id: OP_ID,
    committed_at: iso(-4 * HOUR),
    domain_record_ref: 'assignment-42',
  });

  it('resolves an already-committed effect from the platform authoritative domain record, under every disposition', () => {
    for (const disposition of DeviceRevocationDispositionSchema.options) {
      expect(
        resolveRevokedDeviceOperation({ disposition, offline_operation_id: OP_ID, priorCommittedEvidence: evidence }).resolution,
      ).toBe('RESOLVE_AS_COMMITTED');
    }
  });

  it('refuses a new effect for a stolen device or a copied key when the work was never applied', () => {
    for (const disposition of ['STOLEN', 'COMPROMISED_KEY'] as const) {
      expect(resolveRevokedDeviceOperation({ disposition, offline_operation_id: OP_ID, priorCommittedEvidence: null }).resolution).toBe(
        'REFUSE_NEW_EFFECT',
      );
    }
  });

  it('routes unapplied work from a merely lost device to human-attested re-entry', () => {
    expect(resolveRevokedDeviceOperation({ disposition: 'LOST', offline_operation_id: OP_ID, priorCommittedEvidence: null }).resolution).toBe(
      'REQUIRES_HUMAN_REENTRY',
    );
  });

  it('does not let evidence about a different operation resolve this one', () => {
    const otherEvidence = DeviceCommittedEffectEvidenceSchema.parse({
      ...evidence,
      offline_operation_id: 'b4cc2b21-3d4e-4f60-9aab-1d2e3f4a5b6c',
    });
    expect(
      resolveRevokedDeviceOperation({ disposition: 'STOLEN', offline_operation_id: OP_ID, priorCommittedEvidence: otherEvidence }).resolution,
    ).toBe('REFUSE_NEW_EFFECT');
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
