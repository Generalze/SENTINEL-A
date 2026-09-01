import type {
  DeviceCustody,
  DeviceEnrollmentRefusal,
  DeviceKeyLifecycleState,
  DeviceKeyRotationRefusal,
  DeviceKeyStorage,
  DeviceRevocationDisposition,
  DeviceSignatureProfile,
  DeviceTrust,
  DeviceTrustTransitionRefusal,
} from '@sentinel/contracts';

/**
 * WP-24 Shield internal result types.
 *
 * EVERY SERVICE METHOD RETURNS A REFUSAL AS DATA, NEVER AS AN EXCEPTION.
 *
 * That is the WP-20 executor's discipline applied to a security registry, and
 * for a sharper reason. A thrown error carries a message, a message reaches a
 * log, and the refusal vocabulary below is deliberately granular enough to be
 * an ORACLE if it were ever handed to a device: `APPROVAL_FINGERPRINT_MISMATCH`
 * and `ENROLLMENT_REQUEST_MISSING` tell an attacker two very different things.
 * Keeping refusals as typed data means the eventual gateway (WP-25) decides
 * what a device is allowed to learn, and the registry never accidentally
 * decides it by throwing.
 *
 * The contract refusal vocabularies are UNIONED IN rather than re-declared:
 * when `evaluateDeviceEnrollmentCommit` refuses, the exact contract refusal is
 * what the caller receives. Translating it into a module-local code would lose
 * the one piece of information the contract was written to produce.
 */

/**
 * The refusals this MODULE owns — the ones that exist because there is a
 * database, a session and a role table, none of which a contract can see.
 *
 * ISOLATION IS A DESIGN PROPERTY OF THIS LIST. There is no
 * `..._IN_ANOTHER_ORGANISATION` member and there never will be: a foreign
 * tenant's real enrollment request and an id that has never existed must both
 * answer `ENROLLMENT_REQUEST_NOT_FOUND`, because any distinction between them
 * is a cross-tenant existence oracle. The same holds for devices, keys, grants
 * and rotation requests.
 */
export const SHIELD_REFUSALS = [
  /** The principal's §62 roles do not grant the required device.* action. */
  'NOT_AUTHORISED',
  /** The action is granted, but not for the site this operation touches. */
  'SITE_NOT_IN_SCOPE',
  /** The site does not exist IN THIS ORGANISATION. Indistinguishable from absent. */
  'SITE_NOT_FOUND',
  /** The user does not exist IN THIS ORGANISATION. Indistinguishable from absent. */
  'USER_NOT_FOUND',
  /** No bootstrap grant matches. Covers absent, foreign-tenant and wrong-secret. */
  'BOOTSTRAP_GRANT_NOT_FOUND',
  /**
   * D24-03a: the grant was presented in an organisation, site or user context
   * it was not issued for. The grant is BURNED before this is returned — a
   * probe is not a typo.
   */
  'BOOTSTRAP_CONTEXT_MISMATCH',
  'ENROLLMENT_REQUEST_NOT_FOUND',
  /** The ceremony is not at the step this call belongs to (the WP-23 state machine). */
  'ENROLLMENT_STATE_INVALID',
  /** D24-03: the human who issued the bootstrap grant may not approve the request. */
  'ISSUER_MAY_NOT_APPROVE',
  /** D24-03: the intended user may not approve their own enrollment. */
  'INTENDED_USER_MAY_NOT_APPROVE',
  /** The approval names a fingerprint that is not this request's exact one. */
  'APPROVAL_FINGERPRINT_MISMATCH',
  /** The request has already been approved; a second approval is not a decision. */
  'ALREADY_APPROVED',
  /** D24-05: the platform crypto provider refused to import the public key. */
  'PUBLIC_KEY_NOT_RUNTIME_VALID',
  'POSSESSION_CHALLENGE_NOT_FOUND',
  /** The challenge belongs to a different enrollment request. */
  'POSSESSION_CHALLENGE_MISBOUND',
  'POSSESSION_VERIFICATION_NOT_FOUND',
  'DEVICE_NOT_FOUND',
  'DEVICE_KEY_NOT_FOUND',
  /** The registry holds no CURRENT key for this device: nothing to rotate from. */
  'DEVICE_HAS_NO_CURRENT_KEY',
  'ROTATION_REQUEST_NOT_FOUND',
  'ROTATION_CHALLENGE_NOT_FOUND',
  'ROTATION_STATE_INVALID',
  /**
   * D24-10A: the current key's continuity proof did not verify, is not about
   * this device/key, or does not carry the DEVICE_KEY_ROTATION purpose.
   */
  'CONTINUITY_PROOF_INVALID',
  /** A submitted structure did not parse against its frozen contract schema. */
  'MALFORMED_CONTRACT_STRUCTURE',
  /**
   * D24-08: trust was asked to move somewhere `evaluateDeviceTrustTransition`
   * has no opinion about because the device is already gone (revoked or
   * COMPROMISED). Distinct from the contract's own refusals, which describe a
   * transition that was actually evaluated.
   */
  'DEVICE_CREDENTIAL_WITHDRAWN',
] as const;

export type ShieldRefusal = (typeof SHIELD_REFUSALS)[number];

/**
 * Everything a Shield operation may refuse with: this module's own reasons and
 * the frozen contracts' verdicts, side by side and never merged.
 */
export type ShieldRefusalCode =
  | ShieldRefusal
  | DeviceEnrollmentRefusal
  | DeviceKeyRotationRefusal
  | DeviceTrustTransitionRefusal;

/** The refused arm every Shield outcome shares. */
export interface ShieldRefused {
  readonly outcome: 'REFUSED';
  readonly refusal: ShieldRefusalCode;
}

// ---------------------------------------------------------------------------
// Bootstrap (D24-03a)
// ---------------------------------------------------------------------------

/**
 * The ONLY structure in this module that carries the bootstrap secret, and it
 * is a return value that is never persisted, never logged and never audited.
 *
 * D24-03a: >= 256 bits of entropy, returned ONCE to the authorised issuing
 * caller, persisted only as `tokenDigest`. There is no read path that can
 * produce this shape a second time — the digest is one-way, so a lost token is
 * a re-issued grant, not a recovered one.
 */
export type IssueBootstrapGrantOutcome =
  | {
      readonly outcome: 'ISSUED';
      readonly grantId: string;
      /** Base64url. In transit only. Not stored anywhere on the server. */
      readonly token: string;
      readonly siteId: string;
      readonly intendedUserId: string;
      readonly expiresAt: Date;
    }
  | ShieldRefused;

export type RevokeBootstrapGrantOutcome = { readonly outcome: 'REVOKED'; readonly grantId: string } | ShieldRefused;

// ---------------------------------------------------------------------------
// Enrollment (D24-03 / D24-06)
// ---------------------------------------------------------------------------

/**
 * What a device presents to open an enrollment.
 *
 * NOTE WHAT IS ABSENT. There is no `trust` field (D24-08: trust is concluded
 * by the server from server-owned evidence, and a field a client could set
 * would make the whole model decorative), no `sequence_namespace_id` (D24-04:
 * always recomputed via `deviceSequenceNamespaceId`), no `signature_profile`
 * that selects anything (C15-01: `claimedSignatureProfile` is equality-bound
 * to the server's, never consulted), no private-key field and no attestation
 * blob. None of these is filtered out; none of them can be expressed.
 */
export interface EnrollmentRequestSubmission {
  /** The organisation the grant is being presented IN. Compared, never trusted. */
  readonly organisationId: string;
  readonly siteId: string;
  readonly intendedUserId: string;
  /** The one-time secret, as issued. Digested immediately and never stored. */
  readonly bootstrapToken: string;
  readonly custody: DeviceCustody;
  /** Canonical base64url uncompressed SEC1 point (C15-02). */
  readonly publicKey: string;
  readonly keyStorage: DeviceKeyStorage;
  /** C15-01: A CLAIM. Bound to the server's resolved profile before any use. */
  readonly claimedSignatureProfile: DeviceSignatureProfile;
  /** CONTROLLED_SHARED only: the named régime governing hand-over (C15-08). */
  readonly custodyRegimeId: string | null;
  readonly traceId: string;
}

export type CreateEnrollmentRequestOutcome =
  | {
      readonly outcome: 'REQUESTED';
      readonly enrollmentRequestId: string;
      readonly requestFingerprint: string;
      readonly serverSelectedSignatureProfile: DeviceSignatureProfile;
      readonly attestationOutcome: string;
    }
  | ShieldRefused;

export type ApproveEnrollmentOutcome =
  | { readonly outcome: 'APPROVED'; readonly approvalId: string; readonly approvedRequestFingerprint: string }
  | ShieldRefused;

export type IssuePossessionChallengeOutcome =
  | { readonly outcome: 'ISSUED'; readonly challengeId: string; readonly nonce: string; readonly expiresAt: Date }
  | ShieldRefused;

/**
 * C15-03: THERE IS NO NAKED BOOLEAN ANYWHERE ON THIS PATH.
 *
 * `verified: false` is a real, recorded server verdict — the row exists and
 * says the check failed — and it is reported as its own outcome rather than as
 * a refusal, because a refusal means the check did not happen.
 */
export type VerifyPossessionOutcome =
  | {
      readonly outcome: 'VERIFIED' | 'NOT_VERIFIED';
      readonly verificationId: string;
      readonly possessionStatementFingerprint: string;
    }
  | ShieldRefused;

export type CommitEnrollmentOutcome =
  | {
      readonly outcome: 'COMMITTED';
      readonly deviceId: string;
      readonly sequenceNamespaceId: string;
      readonly keyId: string;
      readonly keyVersion: number;
      readonly trust: DeviceTrust;
    }
  /** D24-06: a byte-identical retry. The SAME device identity, never a second. */
  | { readonly outcome: 'CONVERGED'; readonly deviceId: string }
  | ShieldRefused;

// ---------------------------------------------------------------------------
// Key rotation (D24-10 / D24-10A)
// ---------------------------------------------------------------------------

export type RequestKeyRotationOutcome =
  | {
      readonly outcome: 'REQUESTED';
      readonly rotationRequestId: string;
      readonly rotationRequestFingerprint: string;
      readonly proposedKeyId: string;
      readonly proposedKeyVersion: number;
    }
  | ShieldRefused;

export type IssueRotationChallengeOutcome =
  | { readonly outcome: 'ISSUED'; readonly challengeId: string; readonly nonce: string; readonly expiresAt: Date }
  | ShieldRefused;

export type VerifyRotationPossessionOutcome =
  | {
      readonly outcome: 'VERIFIED' | 'NOT_VERIFIED';
      readonly verificationId: string;
      readonly canonicalStatementFingerprint: string;
    }
  | ShieldRefused;

export type CommitKeyRotationOutcome =
  | {
      readonly outcome: 'ROTATED';
      readonly deviceId: string;
      /** D24-10: unchanged by rotation. Asserted by the caller, not hoped for. */
      readonly sequenceNamespaceId: string;
      readonly fromKeyId: string;
      readonly fromKeyVersion: number;
      readonly toKeyId: string;
      readonly toKeyVersion: number;
    }
  | { readonly outcome: 'CONVERGED'; readonly deviceId: string; readonly storedOutcomeRef: string }
  | ShieldRefused;

// ---------------------------------------------------------------------------
// Trust, revocation and standing (D24-08 / D24-09)
// ---------------------------------------------------------------------------

export type ChangeDeviceTrustOutcome =
  | { readonly outcome: 'CHANGED'; readonly previousTrust: DeviceTrust; readonly newTrust: DeviceTrust }
  | ShieldRefused;

export type DeclareDeviceDispositionOutcome =
  | {
      readonly outcome: 'DECLARED';
      readonly disposition: DeviceRevocationDisposition;
      readonly previousTrust: DeviceTrust;
      readonly newTrust: DeviceTrust;
      /** The key lifecycle state after the declaration. `null` when no key moved. */
      readonly keyStatus: DeviceKeyLifecycleState | null;
      /** D24-09: whether a controlled restoration path still exists. */
      readonly restorationPathRemains: boolean;
    }
  | ShieldRefused;

/**
 * The registry's answer to "what is this device, and may it do new work?".
 *
 * D24-09: `deviceAdmitsNewOperations` consults the DEVICE row and the KEY row
 * INDEPENDENTLY and requires both. Either one saying the credential is gone is
 * sufficient on its own, and no caller may assume the two moved together — a
 * key declared COMPROMISED before the device row has caught up must already
 * block, and a revoked device with an untouched CURRENT key must block too.
 */
export interface DeviceStanding {
  readonly deviceId: string;
  readonly organisationId: string;
  readonly custody: DeviceCustody;
  readonly trust: DeviceTrust;
  readonly revocationDisposition: DeviceRevocationDisposition | null;
  readonly revokedAt: Date | null;
  readonly sequenceNamespaceId: string;
  readonly currentKeyId: string | null;
  readonly currentKeyVersion: number | null;
  readonly currentKeyStatus: DeviceKeyLifecycleState | null;
  readonly currentKeyStorage: DeviceKeyStorage | null;
  readonly currentKeyRevokedAt: Date | null;
  readonly siteIds: readonly string[];
  /** DEVICE-level only. Never the whole answer on its own. */
  readonly deviceLevelWithdrawn: boolean;
  /** KEY-level only. Never the whole answer on its own. */
  readonly keyLevelWithdrawn: boolean;
  /** Both checks, ANDed. The only value a caller should gate new work on. */
  readonly admitsNewOperations: boolean;
}

export type ReadDeviceStandingOutcome = { readonly outcome: 'FOUND'; readonly standing: DeviceStanding } | ShieldRefused;

export type ListDevicesOutcome = { readonly outcome: 'FOUND'; readonly devices: readonly DeviceStanding[] } | ShieldRefused;

/** D24-07: one append-only observation, as recorded. */
export type RecordAttestationOutcome =
  | { readonly outcome: 'RECORDED'; readonly observationId: string; readonly attestationOutcome: string }
  | ShieldRefused;
