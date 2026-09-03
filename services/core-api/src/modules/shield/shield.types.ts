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

  // -------------------------------------------------------------------------
  // C16-01 — the custody regime is approval-bound
  // -------------------------------------------------------------------------

  /** CONTROLLED_SHARED custody was requested with no regime. C15-08 requires one. */
  'CUSTODY_REGIME_REQUIRED',
  /** PERSONAL custody named a regime. A personal device under a shared regime is an accountability gap. */
  'CUSTODY_REGIME_NOT_PERMITTED',
  /**
   * No regime matches IN THIS ORGANISATION AND AT THIS SITE. Covers absent,
   * foreign-tenant and right-tenant-wrong-site alike: the isolation rule this
   * list opens with applies to the regime catalogue too.
   */
  'CUSTODY_REGIME_NOT_FOUND',
  /**
   * The regime exists at this organisation and site but has been retired.
   * Reported distinctly from absent because it is NOT an oracle: the presenter
   * has already proved, by holding a usable bootstrap grant, that they are
   * operating inside this exact tenant and site.
   */
  'CUSTODY_REGIME_RETIRED',
  /**
   * C16-01: the approved-semantics digest recomputed from the (locked) request
   * does not equal the one the approval bound. The custody regime — or the
   * custody mode, or the request bytes — moved after the human decided.
   */
  'APPROVED_SEMANTICS_MISMATCH',
  /**
   * C16-R1: the APPROVAL's own regime record and the (locked) REQUEST's regime
   * disagree.
   *
   * `approved_custody_regime_id` is the approval's INDEPENDENT record — it is
   * stored exactly like `approved_site_id`, precisely so the commit can see a
   * disagreement rather than inherit one. Nothing in the approved-semantics
   * digest recomputed from the REQUEST can detect a rewrite of the APPROVAL, so
   * the two records are compared directly and the disagreement is reported as
   * ITSELF rather than as a digest mismatch: an operator reading this refusal
   * learns which of the two rows moved.
   */
  'APPROVED_CUSTODY_REGIME_MISMATCH',
  /**
   * C16-R1: the approval row does not agree with ITS OWN digest.
   *
   * The digest is recomputed from the approval's own approved fingerprint,
   * approved custody and approved regime and required to equal the
   * `approved_semantics_digest` the approval stored. A mismatch means the
   * approval record was rewritten after the human decided — the one thing a
   * recomputation from the REQUEST can never see, because it never reads the
   * approval's own fields.
   */
  'APPROVAL_RECORD_INCONSISTENT',

  // -------------------------------------------------------------------------
  // C16-02 — a replay row may never outlive the effect it claims
  // -------------------------------------------------------------------------

  /**
   * A consumption row classified EXACT_DUPLICATE, but its stored outcome
   * reference does not resolve, BY AUTHORITATIVE DATABASE READ, to a committed
   * effect belonging to this exact ceremony. Convergence is never manufactured:
   * the honest answer is that the registry cannot say what the identity was
   * spent on, and that fails closed.
   */
  'REPLAY_OUTCOME_UNRESOLVABLE',
  /**
   * The two enrollment replay identities resolve to DIFFERENT committed
   * outcomes. One ceremony has exactly one outcome; two is an integrity fault,
   * not a race to arbitrate.
   */
  'REPLAY_OUTCOME_DIVERGED',
  /**
   * C16-02: a materially different enrollment request was submitted under a
   * bootstrap grant that already has one. A grant is provenance for ONE
   * ceremony; two requests behind it would be two approval candidates racing
   * for a single replay identity.
   */
  'ENROLLMENT_REQUEST_CONFLICT',

  // -------------------------------------------------------------------------
  // C16-03 / C16-04 — rotation convergence and partial-write refusal
  // -------------------------------------------------------------------------

  /**
   * The rotation replay identity is an exact duplicate, but the stored outcome
   * reference does not resolve to the exact committed rotation it claims — the
   * key row is missing, is not CURRENT, sits at the wrong version, belongs to
   * another device or tenant, or the device pointer disagrees. Fail closed.
   */
  'ROTATION_OUTCOME_UNRESOLVABLE',
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

/**
 * WP-26/D26-04A: the answer to "is this presented token usable RIGHT NOW, for
 * exactly this organisation, site and intended user?".
 *
 * IT CARRIES NO SECRET. The token went in; what comes back is the grant's
 * server-owned identity and its expiry, which is what the enrollment ingress
 * needs in order to CLAMP an attestation challenge so it can never outlive the
 * grant it belongs to. There is no path back from this shape to the token, and
 * nothing here is a credential: the grant still creates ZERO device authority
 * (D24-03).
 */
export type PresentBootstrapGrantOutcome =
  | {
      readonly outcome: 'USABLE';
      readonly grantId: string;
      /** The grant's OWN site, not the presented one. They were proved equal. */
      readonly siteId: string;
      readonly intendedUserId: string;
      readonly expiresAt: Date;
    }
  | ShieldRefused;

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
  /**
   * CONTROLLED_SHARED only, and REQUIRED there (C15-08 / C16-01).
   *
   * An id from the SERVER-ISSUED `DeviceCustodyRegime` catalogue, never free
   * text. It is resolved against this organisation AND this site, and a
   * retired regime refuses. It arrives HERE, on the request, rather than at
   * commit, because only a value present at request time can be covered by the
   * approved-semantics digest the human approval binds.
   */
  readonly custodyRegimeId: string | null;
  /**
   * WP-26/D26-04B — THE SERVER'S OWN ATTESTATION ARTIFACT REFERENCE, OR NULL.
   *
   * NOT A CLIENT FIELD, AND STRUCTURALLY NOT ONE. There is no HTTP body member,
   * no contract field and no device-reachable path that produces it: the WP-26
   * ingress verifies an Android Key Attestation chain ITSELF, persists what it
   * concluded as a restricted server-owned record, and passes the handle here.
   * The device supplies the EVIDENCE (a public key and a certificate chain); the
   * server supplies the VERDICT, which is the D24-08 rule that a field a client
   * could set would make the whole model decorative, applied one level up.
   *
   * It is handed to the injected `DeviceAttestationEvaluator` and to nothing
   * else. This service takes no decision from it, stores no copy of it beyond
   * what the evaluator's own evidence carries, and every pre-WP-26 caller passes
   * `null` — which the evaluator answers exactly as it did before the field
   * existed.
   */
  readonly attestationArtifactRef: string | null;
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
  /**
   * C16-02: an IDENTICAL repeat submission under a grant that already opened a
   * request. One grant, one ceremony: the retry converges on the request that
   * exists rather than opening a second candidate behind the same provenance.
   * A materially different submission gets `ENROLLMENT_REQUEST_CONFLICT`.
   */
  | {
      readonly outcome: 'CONVERGED';
      readonly enrollmentRequestId: string;
      readonly requestFingerprint: string;
      readonly serverSelectedSignatureProfile: DeviceSignatureProfile;
      readonly attestationOutcome: string;
    }
  | ShieldRefused;

export type ApproveEnrollmentOutcome =
  | { readonly outcome: 'APPROVED'; readonly approvalId: string; readonly approvedRequestFingerprint: string }
  | ShieldRefused;

/**
 * WP-26/D26-09: what the INTENDED USER of a ceremony may be told about it.
 *
 * The narrowest read in this module, and deliberately so. It exists because the
 * enrollment ingress must equality-bind the authenticated session to the
 * request's intended user before the possession step (C17-01), and it cannot do
 * that without asking Shield — the ingress never reads a Shield table itself.
 *
 * IT IS NOT A REGISTRY READ. There is no device here, no key, no trust value
 * and no attestation reference. `state` and the fingerprint are exactly what a
 * client already learns from creating the request; nothing new is disclosed by
 * being able to ask again.
 *
 * ISOLATION: a request in another tenant, a request belonging to another
 * intended user and an id that never existed all answer
 * `ENROLLMENT_REQUEST_NOT_FOUND` — the same rule `issuePossessionChallenge`
 * follows, because any distinction between them is an existence oracle.
 */
export type ReadIntendedUserEnrollmentOutcome =
  | {
      readonly outcome: 'FOUND';
      readonly enrollmentRequestId: string;
      readonly siteId: string;
      readonly state: string;
      readonly requestFingerprint: string;
      readonly publicKeyThumbprint: string;
      readonly attestationOutcome: string;
    }
  | ShieldRefused;

/**
 * WP-26/D26-09: the COMMANDER's view of enrollments awaiting a decision.
 *
 * Gated by `device.registry.read` and projected to the sites the reader's
 * granting assignments actually cover — the C16-06 rule that holding one site
 * is not a way to enumerate another. An organisation-wide assignment sees the
 * tenant; a site-scoped commander sees their sites; a reader holding the action
 * at no site sees nothing, which is deliberately NOT the same as seeing
 * everything.
 *
 * `requestFingerprint` is here because it is the thing the approver must name
 * back (C14-02: a human approves a specific set of bytes, not an id). The
 * attestation OUTCOME is here for the same reason — it is part of what the
 * approver is approving — and the raw certificate chain is NOT, and could not
 * be: no read path in this module can load it.
 */
export interface PendingEnrollmentSummary {
  readonly enrollmentRequestId: string;
  readonly siteId: string;
  readonly intendedUserId: string;
  readonly custody: DeviceCustody;
  readonly custodyRegimeId: string | null;
  readonly keyStorage: DeviceKeyStorage;
  readonly publicKeyThumbprint: string;
  readonly requestFingerprint: string;
  readonly attestationOutcome: string;
  readonly state: string;
  readonly requestedAt: Date;
}

export type ListPendingEnrollmentsOutcome =
  | { readonly outcome: 'FOUND'; readonly requests: readonly PendingEnrollmentSummary[] }
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
  /**
   * C16-03 / C16-R4: an EXACT retry of a rotation that already landed.
   *
   * THIS OUTCOME IS A HISTORICAL FACT AND CONFERS NO CURRENT KEY AUTHORITY.
   *
   * It answers "did THIS rotation commit?", not "is that key live now?". A
   * later rotation may already have superseded it — R1 rotates v1->v2, R2
   * rotates v2->v3, an exact retry of R1 arrives and CONVERGES on v2 while the
   * registry's current key is v3 — and `committedKeyLifecycleState` will then
   * read `ROTATED`. It may equally read `REVOKED` or `COMPROMISED`.
   *
   * So NOTHING may treat `toKeyId`/`toKeyVersion` as the credential to verify
   * against. `DeviceRegistryService.resolveRegistryKeyRecord` and
   * `deviceMayAct` are the only answers to "which credential is live, and may
   * this device act?", and they read the registry rather than a replay row.
   *
   * The identity, version and lifecycle state are all read back FROM THE
   * REGISTRY, not echoed from the request: the runtime resolves the stored
   * outcome reference to the committed key row and refuses — never converges —
   * if it does not resolve to this device, this tenant, this proposed key id
   * and this proposed version.
   */
  | {
      readonly outcome: 'CONVERGED';
      readonly deviceId: string;
      readonly storedOutcomeRef: string;
      readonly toKeyId: string;
      readonly toKeyVersion: number;
      /**
       * The committed key's lifecycle state AS IT STANDS NOW. Present precisely
       * so a reader cannot mistake this outcome for a statement that the key is
       * still current — it frequently is not.
       */
      readonly committedKeyLifecycleState: DeviceKeyLifecycleState;
    }
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
 * D24-09: `credentialAdmitsNewOperations` consults the DEVICE row and the KEY
 * row INDEPENDENTLY and requires both. Either one saying the credential is gone is
 * sufficient on its own, and no caller may assume the two moved together — a
 * key declared COMPROMISED before the device row has caught up must already
 * block, and a revoked device with an untouched CURRENT key must block too.
 */
export interface DeviceStanding {
  readonly deviceId: string;
  readonly organisationId: string;
  readonly custody: DeviceCustody;
  /**
   * C16-R5: THE EFFECTIVE TRUST — the persisted conclusion reconciled with the
   * attestation evidence it rests on, against authoritative server time.
   *
   * A device that reached TRUSTED and then went dark keeps a persisted
   * `TRUSTED` for ever, because the durable `TRUSTED -> DEGRADED` move only
   * happens when an observation ARRIVES and no observation ever does. This
   * field reports what the registry would ACT on, so the read surface can never
   * advertise a TRUSTED that `deviceMayAct` would refuse.
   */
  readonly trust: DeviceTrust;
  /**
   * C16-R5: the raw `device.trust` column, exposed beside the effective value
   * so an operator can see when the durable row has not caught up with expired
   * evidence yet. NOTHING may authorise on this field.
   */
  readonly persistedTrust: DeviceTrust;
  readonly revocationDisposition: DeviceRevocationDisposition | null;
  readonly revokedAt: Date | null;
  readonly sequenceNamespaceId: string;
  readonly currentKeyId: string | null;
  readonly currentKeyVersion: number | null;
  readonly currentKeyStatus: DeviceKeyLifecycleState | null;
  readonly currentKeyStorage: DeviceKeyStorage | null;
  readonly currentKeyRevokedAt: Date | null;
  /**
   * C16-06: THE SITES THE READER IS ENTITLED TO SEE, not the device's full
   * list. A site-scoped reader receives the intersection of their granted
   * scope with the device's active associations; only genuine
   * organisation-wide authority receives the whole list. Holding one site is
   * not a way to enumerate the others a device is deployed at.
   */
  readonly siteIds: readonly string[];
  /** DEVICE-level only. Never the whole answer on its own. */
  readonly deviceLevelWithdrawn: boolean;
  /** KEY-level only. Never the whole answer on its own. */
  readonly keyLevelWithdrawn: boolean;
  /**
   * Both CREDENTIAL checks, ANDed — and nothing else (C16-07).
   *
   * The name says `credential` because that is all it covers. It is NOT
   * operational authorisation: a QUARANTINED device with a perfectly healthy
   * key satisfies it. `DeviceRegistryService.deviceMayAct` is the
   * purpose-aware question, and even that is not complete authorisation.
   */
  readonly credentialAdmitsNewOperations: boolean;
}

export type ReadDeviceStandingOutcome = { readonly outcome: 'FOUND'; readonly standing: DeviceStanding } | ShieldRefused;

export type ListDevicesOutcome = { readonly outcome: 'FOUND'; readonly devices: readonly DeviceStanding[] } | ShieldRefused;

/**
 * C16-01: one server-issued custody regime, as defined. The id in the payload
 * is the SERVER's; nothing a caller sent chose it.
 */
export type DefineCustodyRegimeOutcome =
  | { readonly outcome: 'DEFINED'; readonly custodyRegimeId: string; readonly siteId: string; readonly name: string }
  | ShieldRefused;

/** D24-07: one append-only observation, as recorded. */
export type RecordAttestationOutcome =
  | { readonly outcome: 'RECORDED'; readonly observationId: string; readonly attestationOutcome: string }
  | ShieldRefused;
