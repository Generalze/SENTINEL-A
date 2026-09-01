import { Inject, Injectable } from '@nestjs/common';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import {
  canTransitionDeviceEnrollment,
  canonicalDevicePossessionStatement,
  classifyDeviceBootstrapGrant,
  DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS,
  DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS,
  DeviceCustodyAssociationSchema,
  DeviceEnrollmentApprovalSchema,
  DeviceEnrollmentBootstrapGrantSchema,
  DeviceEnrollmentRequestSchema,
  DevicePossessionChallengeSchema,
  DevicePossessionResponseSchema,
  DevicePossessionVerificationResultSchema,
  deviceBootstrapGrantReplayKey,
  deviceEnrollmentRequestFingerprint,
  devicePossessionChallengeReplayKey,
  devicePossessionStatementFingerprint,
  deriveP256PublicKeyThumbprint,
  deviceSequenceNamespaceId,
  evaluateAttestationStanding,
  evaluateDeviceEnrollmentCommit,
  initialDeviceTrustOnEnrollment,
  type DeviceCustody,
  type DeviceCustodyAssociation,
  type DeviceEnrollmentApproval,
  type DeviceEnrollmentBootstrapGrant,
  type DeviceEnrollmentRequest,
  type DevicePossessionChallenge,
  type DevicePossessionVerificationResult,
} from '@sentinel/contracts';
import type { Principal } from '../../common/security/principal';
import { DEVICE_ATTESTATION_EVALUATOR, type DeviceAttestationEvaluator } from './attestation.evaluator';
import { DeviceReplayService } from './device-replay.service';
import { DeviceSecurityAudit } from './device-security-audit';
import { P256KeyImporter } from './p256-key.importer';
import { checkDeviceAuthority } from './shield.authority';
import { ShieldTransactionRollback, isShieldTransactionRollback } from './shield.rollback';
import { approvedEnrollmentSemanticsDigest } from './shield.semantics';
import {
  ACTION_DEVICE_ENROLLMENT_APPROVE,
  ACTION_DEVICE_ENROLLMENT_ISSUE,
  BOOTSTRAP_TOKEN_DIGEST_ALGORITHM,
  BOOTSTRAP_TOKEN_ENTROPY_BYTES,
  CEREMONY_BOOTSTRAP_GRANT,
  CEREMONY_POSSESSION_CHALLENGE,
  CHALLENGE_NONCE_ENTROPY_BYTES,
  DEVICE_TRUST_PREVIOUS_NONE,
  SERVER_SELECTED_SIGNATURE_PROFILE,
  TRUST_REASON_ENROLLMENT_INITIAL,
} from './shield.constants';
import {
  isUniqueConstraintViolation,
  ShieldRepository,
  type BootstrapGrantRow,
  type EnrollmentApprovalRow,
  type EnrollmentRequestRow,
  type Tx,
} from './shield.repository';
import type {
  ApproveEnrollmentOutcome,
  CommitEnrollmentOutcome,
  CreateEnrollmentRequestOutcome,
  DefineCustodyRegimeOutcome,
  EnrollmentRequestSubmission,
  IssueBootstrapGrantOutcome,
  IssuePossessionChallengeOutcome,
  RevokeBootstrapGrantOutcome,
  ShieldRefusalCode,
  VerifyPossessionOutcome,
} from './shield.types';

/**
 * WP-24/D24-03, D24-03a, D24-06 — THE ENROLLMENT CEREMONY.
 *
 * THE ATTACK THIS SERVICE EXISTS TO LOSE (C14-02, restated by the contract it
 * calls rather than by this class):
 *
 *     steal an unused bootstrap grant
 *       + generate an attacker keypair
 *       + prove possession of the ATTACKER's private key
 *       = attacker wins the enrollment
 *
 * Proof of possession proves possession of THE KEY BEING ENROLLED. It says
 * nothing about whether that is the hardware the issuer intended. So the
 * ceremony has four independent server facts, and every one of them is checked
 * by `evaluateDeviceEnrollmentCommit` — not here:
 *
 *     issue grant -> create request -> approve THAT EXACT fingerprint
 *       -> intended user authenticates -> fresh challenge
 *       -> device proves possession -> ONE transaction commits
 *
 * WHAT THIS SERVICE OWNS, AND WHAT IT REFUSES TO OWN
 * -------------------------------------------------
 * It owns SECRETS (the bootstrap token and the challenge nonce), PERSISTENCE,
 * LOCKING, the two human separations that need a session to evaluate, and the
 * runtime crypto calls. It owns NO admissibility rule: grant standing, scope
 * matching, fingerprint binding, the whole C15-R3 chronology chain, possession
 * verdict binding, replay classification and convergence are all
 * `evaluateDeviceEnrollmentCommit`'s, and initial trust is
 * `initialDeviceTrustOnEnrollment`'s. Wherever this file has an `if`, it is
 * about something a contract cannot see: a database row, a session, or a key
 * the platform crypto provider has to import.
 *
 * WHY A SUCCESSFUL COMMIT DOES NOT SET `consumed_at` (a judgement call, stated
 * openly)
 * ---------------------------------------------------------------------------
 * D24-03a calls the grant single-use and D24-06 requires that an exact retry of
 * a committed ceremony CONVERGES ON THE SAME DEVICE IDENTITY. Those two are in
 * tension in the frozen contract, and the contract settles it:
 * `classifyDeviceBootstrapGrant` reports a grant carrying `consumed_at` as
 * CONSUMED, and `evaluateDeviceEnrollmentCommit` refuses a non-USABLE grant at
 * step 1 — long before its own CONVERGE arm at step 9. So a commit that stamped
 * `consumed_at` would make convergence structurally unreachable and turn every
 * honest retry into `BOOTSTRAP_GRANT_UNUSABLE`.
 *
 * C16-02 — THE TRANSACTIONAL DOCTRINE THIS SERVICE NOW OBEYS
 * -------------------------------------------------------------
 *
 *     NO `FIRST_SEEN` CONSUMPTION RECORD MAY SURVIVE A TRANSACTION IN WHICH
 *     ITS CORRESPONDING EFFECT DID NOT COMMIT.
 *
 * The commit used to consume BOTH one-shot identities before the admissibility
 * gate ran, storing a PRE-GENERATED device id as the outcome reference. When
 * the gate then refused, the callback RETURNED — and a normal return from a
 * Prisma interactive transaction COMMITS. So a refused enrollment left behind a
 * consumption row naming a device that was never created, and the next exact
 * retry classified as EXACT_DUPLICATE and converged toward an identity that
 * does not exist. The registry would have reported success for hardware it had
 * never registered.
 *
 * Three changes close it, and they are visible in `commitEnrollment` below:
 *
 *  1. EVERY fallible condition is PREVALIDATED before the first consumption
 *     write. What remains after that point can only be a refusal the contract
 *     produces from facts already in hand.
 *  2. Any refusal reached after the first consumption write `throw`s
 *     `ShieldTransactionRollback`, so Postgres aborts the whole transaction;
 *     the external refusal — and its D24-12 audit event — are produced
 *     afterwards, outside it. A refusal audit written before the first
 *     consumption write may still be returned normally: it is the refusal's own
 *     record, not the effect, and it is the only thing that transaction commits.
 *  3. The two enrollment replay identities are resolved to ONE canonical
 *     committed outcome BEFORE either is spent, by an authoritative read of the
 *     device table. A stored reference that does not resolve to a real device
 *     belonging to THIS request fails closed (`REPLAY_OUTCOME_UNRESOLVABLE`);
 *     two references that disagree fail closed (`REPLAY_OUTCOME_DIVERGED`).
 *     Convergence is never manufactured.
 *
 * C16-02 also binds a grant to ONE request at creation
 * (`enrollment_request_grant_key`): a grant that could open two requests could
 * collect two independent human approvals, and the two would then race for the
 * single replay identity the grant carries.
 *
 * C16-01 — THE CUSTODY REGIME IS NOW APPROVAL-BOUND
 * -------------------------------------------------
 * `custodyRegimeId` used to arrive as a `commitEnrollment` parameter. The human
 * approval binds `deviceEnrollmentRequestFingerprint`, and the frozen schema
 * behind that fingerprint has NO REGIME FIELD — so a request approved for
 * CONTROLLED_SHARED custody could be committed under a regime the approver
 * never saw. The regime is now a row in a server-issued catalogue, it is named
 * on the REQUEST, and `approvedSemanticsDigest` (see `shield.semantics.ts`)
 * covers fingerprint + custody + regime together. The commit reads the regime
 * from the APPROVAL row and recomputes the digest from the request; a
 * disagreement refuses. There is no longer a commit parameter to disagree with.
 *
 * Single use on the success path is therefore enforced where D24-11 says it is:
 * by the durable `DeviceNonceConsumption` row over the grant's own replay
 * identity. A second ceremony under the same grant presents the same replay
 * identity with a DIFFERENT statement fingerprint and is refused
 * `BOOTSTRAP_GRANT_REUSED`; a byte-identical retry converges on the device the
 * first attempt created. `consumed_at` is reserved for the two cases where it
 * means "burned without an enrollment": D24-03a's probe, and explicit
 * revocation.
 */

/** The secret and its digest, together for exactly as long as it takes to store one. */
interface MintedBootstrapToken {
  readonly token: string;
  readonly digest: string;
}

/** Everything the commit transaction re-read under lock, before any judgement. */
interface LockedCommitState {
  readonly request: EnrollmentRequestRow;
  readonly approval: EnrollmentApprovalRow;
  readonly grant: BootstrapGrantRow;
  readonly contractRequest: DeviceEnrollmentRequest;
  readonly contractGrant: DeviceEnrollmentBootstrapGrant;
  readonly contractApproval: DeviceEnrollmentApproval;
  readonly contractChallenge: DevicePossessionChallenge;
  readonly contractVerification: DevicePossessionVerificationResult;
  readonly approverUserId: string;
  readonly fingerprint: string;
}

@Injectable()
export class DeviceEnrollmentService {
  constructor(
    @Inject(ShieldRepository) private readonly repository: ShieldRepository,
    @Inject(DeviceReplayService) private readonly replay: DeviceReplayService,
    @Inject(DeviceSecurityAudit) private readonly audit: DeviceSecurityAudit,
    @Inject(P256KeyImporter) private readonly keys: P256KeyImporter,
    @Inject(DEVICE_ATTESTATION_EVALUATOR) private readonly attestation: DeviceAttestationEvaluator,
  ) {}

  // -------------------------------------------------------------------------
  // Step 0 — the custody regime catalogue (C16-01)
  // -------------------------------------------------------------------------

  /**
   * Defines ONE named custody regime, at one site, in one tenant.
   *
   * THE ID IS SERVER-GENERATED. There is no parameter here through which a
   * caller could supply one, which is the same construction D24-04 uses for the
   * sequence namespace and D24-10A uses for a proposed key identity: a value a
   * client can choose is a value a client can shape history with. A caller
   * names the regime; the server names the row.
   *
   * The authority is `device.enrollment.issue` and it is scoped to the site the
   * regime governs. A regime is not an organisation-wide policy object, because
   * custody — who may hold this hardware and under what hand-over discipline —
   * is a site fact. A commander who may not issue a bootstrap grant at a site
   * may not define the custody discipline devices there will be enrolled under.
   *
   * Retirement, not deletion, ends a regime's life: `retired_at` stops NEW
   * enrollments and rewrites no history, so a device enrolled under a regime
   * that is later withdrawn stays traceable to the regime that actually
   * governed it.
   */
  async defineCustodyRegime(
    principal: Principal,
    input: { organisationId: string; siteId: string; name: string; traceId: string },
  ): Promise<DefineCustodyRegimeOutcome> {
    const refusal = checkDeviceAuthority(principal, ACTION_DEVICE_ENROLLMENT_ISSUE, input.organisationId, input.siteId);
    if (refusal !== null) return { outcome: 'REFUSED', refusal };

    // Proven before the write so a cross-tenant pairing answers with a refusal
    // rather than surfacing the composite foreign key as a driver fault. The
    // constraint remains the real defence (D24-04a).
    if (!(await this.repository.siteExistsInOrganisation(input.organisationId, input.siteId))) {
      return { outcome: 'REFUSED', refusal: 'SITE_NOT_FOUND' };
    }

    return this.repository.transaction(async (tx) => {
      const regime = await this.repository.createCustodyRegime(tx, {
        organisationId: input.organisationId,
        siteId: input.siteId,
        name: input.name,
        definedByUserId: principal.user.id,
      });
      return { outcome: 'DEFINED', custodyRegimeId: regime.id, siteId: regime.siteId, name: regime.name };
    });
  }

  // -------------------------------------------------------------------------
  // Step 1 — the bootstrap grant (D24-03a)
  // -------------------------------------------------------------------------

  /**
   * Issues one bootstrap grant and returns its secret EXACTLY ONCE.
   *
   * D24-03a in full: at least 256 bits of cryptographic randomness, handed
   * back to the authorised issuing caller and persisted only as a SHA-256
   * digest. The raw value is never written to a column, never logged, and
   * cannot enter a security event — `device-security-audit.ts` has no builder
   * with a field for it, which is a stronger guarantee than remembering not to
   * pass it.
   *
   * A grant creates ZERO device authority (D24-03). It is provenance for a
   * ceremony, bound to one organisation, one site, one intended user and one
   * issuing human, and on its own it can enrol nothing at all.
   */
  async issueBootstrapGrant(
    principal: Principal,
    input: { organisationId: string; siteId: string; intendedUserId: string; traceId: string },
  ): Promise<IssueBootstrapGrantOutcome> {
    const refusal = checkDeviceAuthority(principal, ACTION_DEVICE_ENROLLMENT_ISSUE, input.organisationId, input.siteId);
    if (refusal !== null) return { outcome: 'REFUSED', refusal };

    // Proven before the write so a cross-tenant pairing answers with a refusal
    // rather than surfacing the composite foreign key as a driver fault. The
    // database constraint remains the real defence (D24-04a); this is the
    // safe, non-leaking way to report it.
    if (!(await this.repository.siteExistsInOrganisation(input.organisationId, input.siteId))) {
      return { outcome: 'REFUSED', refusal: 'SITE_NOT_FOUND' };
    }
    if (!(await this.repository.userExistsInOrganisation(input.organisationId, input.intendedUserId))) {
      return { outcome: 'REFUSED', refusal: 'USER_NOT_FOUND' };
    }

    const minted = this.mintBootstrapToken();

    // ONE transaction. The grant row and the security event that attributes it
    // to a human commit together or not at all: a grant that exists with no
    // BOOTSTRAP_ISSUED event is an unattributable credential-in-waiting, and
    // an event naming a grant that was never written is a record of something
    // that did not happen.
    return this.repository.transaction(async (tx) => {
      const issuedAt = await this.repository.dbNow(tx);
      // The ceiling is the CONTRACT's, imported rather than chosen. A window
      // this service picked would be a security bound nobody reviews.
      const expiresAt = new Date(issuedAt.getTime() + DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS);

      const grant = await this.repository.createBootstrapGrant(tx, {
        organisationId: input.organisationId,
        siteId: input.siteId,
        intendedUserId: input.intendedUserId,
        issuedByUserId: principal.user.id,
        tokenDigest: minted.digest,
        issuedAt,
        expiresAt,
      });

      await this.audit.record(
        tx,
        { organisationId: input.organisationId, deviceId: null, actorUserId: principal.user.id, occurredAt: issuedAt, traceId: input.traceId },
        {
          type: 'BOOTSTRAP_ISSUED',
          grantId: grant.id,
          siteId: input.siteId,
          intendedUserId: input.intendedUserId,
          issuedByUserId: principal.user.id,
          expiresAt: expiresAt.toISOString(),
        },
      );

      return {
        outcome: 'ISSUED',
        grantId: grant.id,
        // In transit only, and only to this caller. Nothing persisted above
        // holds it and nothing below can be asked for it again.
        token: minted.token,
        siteId: input.siteId,
        intendedUserId: input.intendedUserId,
        expiresAt,
      };
    });
  }

  /** D24-03a: a grant is revocable before use. Revocation is a burn, not a delete. */
  async revokeBootstrapGrant(
    principal: Principal,
    input: { organisationId: string; grantId: string; traceId: string },
  ): Promise<RevokeBootstrapGrantOutcome> {
    const grant = await this.repository.findBootstrapGrant(input.organisationId, input.grantId);
    // Read first, authorise against the row's own site: a caller must not be
    // able to learn that a grant exists at a site they cannot reach. Absent and
    // foreign-tenant therefore give the same answer.
    if (grant === null) return { outcome: 'REFUSED', refusal: 'BOOTSTRAP_GRANT_NOT_FOUND' };
    const refusal = checkDeviceAuthority(principal, ACTION_DEVICE_ENROLLMENT_ISSUE, input.organisationId, grant.siteId);
    if (refusal !== null) return { outcome: 'REFUSED', refusal: 'BOOTSTRAP_GRANT_NOT_FOUND' };

    return this.repository.transaction(async (tx) => {
      const now = await this.repository.dbNow(tx);
      await this.repository.revokeBootstrapGrant(tx, input.organisationId, input.grantId, now);
      await this.audit.record(
        tx,
        { organisationId: input.organisationId, deviceId: null, actorUserId: principal.user.id, occurredAt: now, traceId: input.traceId },
        { type: 'BOOTSTRAP_REVOKED', grantId: grant.id, siteId: grant.siteId, revokedByUserId: principal.user.id },
      );
      return { outcome: 'REVOKED', grantId: grant.id };
    });
  }

  // -------------------------------------------------------------------------
  // Step 2 — the enrollment request (D24-03)
  // -------------------------------------------------------------------------

  /**
   * Opens an enrollment against a presented bootstrap grant.
   *
   * There is no `Principal` parameter, deliberately. This is the DEVICE
   * speaking, and D24-02's third rule is that a device presenting a grant is
   * not a human performing a §62 action. The grant is provenance; the human
   * authority in this ceremony is the SEPARATE approval in step 3, which is
   * exactly the separation C14-02 exists to create. (There is still no
   * transport for this: D24-13 forbids one, and WP-25 owns it.)
   *
   * D24-03a's PROBE RULE is enforced here. A grant presented in an
   * organisation, site or intended-user context it was not issued for BURNS —
   * `consumed_at` is stamped and `BOOTSTRAP_REPLAY_REFUSED` is written —
   * because a probe is not a typo, and a grant that survives being probed is a
   * grant an attacker may keep trying against every tenant in turn.
   */
  async createEnrollmentRequest(submission: EnrollmentRequestSubmission): Promise<CreateEnrollmentRequestOutcome> {
    const digest = this.digestBootstrapToken(submission.bootstrapToken);

    // Looked up by DIGEST ALONE, across organisations, and the repository
    // explains why: scoping the lookup to the presented organisation would
    // make the probe undetectable rather than impossible.
    const grant = await this.repository.findBootstrapGrantByTokenDigest(digest);
    if (grant === null) return { outcome: 'REFUSED', refusal: 'BOOTSTRAP_GRANT_NOT_FOUND' };

    const contextMatches =
      grant.organisationId === submission.organisationId &&
      grant.siteId === submission.siteId &&
      grant.intendedUserId === submission.intendedUserId;

    if (!contextMatches) {
      await this.repository.transaction(async (tx) => {
        const now = await this.repository.dbNow(tx);
        await this.repository.burnBootstrapGrant(tx, grant.organisationId, grant.id, now);
        await this.audit.record(
          tx,
          // The event is filed under the grant's OWN organisation, not the one
          // it was presented in. An attacker must not be able to write rows
          // into a tenant they merely named.
          { organisationId: grant.organisationId, deviceId: null, actorUserId: null, occurredAt: now, traceId: submission.traceId },
          {
            type: 'BOOTSTRAP_REPLAY_REFUSED',
            grantId: grant.id,
            refusal: 'BOOTSTRAP_CONTEXT_MISMATCH',
            presentedOrganisationId: submission.organisationId,
            presentedSiteId: submission.siteId,
            presentedIntendedUserId: submission.intendedUserId,
          },
        );
      });
      return { outcome: 'REFUSED', refusal: 'BOOTSTRAP_CONTEXT_MISMATCH' };
    }

    // The grant's own standing, decided by the CONTRACT. Revoked, consumed,
    // expired, not-yet-valid and an unreadable clock all collapse to "not
    // USABLE" here exactly as they do at commit, so a dead grant cannot even
    // open a request. `classifyDeviceBootstrapGrant` is called rather than
    // re-derived: the near-end check (C15-R3's NOT_YET_VALID) and the
    // exclusive expiry boundary (C15-07) are both rules this service must not
    // hold a second opinion about.
    const contractGrant = DeviceEnrollmentBootstrapGrantSchema.safeParse({
      schema_version: 1,
      grant_id: grant.id,
      organisation_id: grant.organisationId,
      site_id: grant.siteId,
      intended_user_id: grant.intendedUserId,
      issued_by_user_id: grant.issuedByUserId,
      issued_at: grant.issuedAt.toISOString(),
      expires_at: grant.expiresAt.toISOString(),
      single_use: true,
      consumed_at: grant.consumedAt === null ? null : grant.consumedAt.toISOString(),
      revoked_at: grant.revokedAt === null ? null : grant.revokedAt.toISOString(),
    });
    if (!contractGrant.success) return { outcome: 'REFUSED', refusal: 'MALFORMED_CONTRACT_STRUCTURE' };
    const standingNow = await this.repository.now();
    if (classifyDeviceBootstrapGrant(contractGrant.data, standingNow.toISOString()) !== 'USABLE') {
      return { outcome: 'REFUSED', refusal: 'BOOTSTRAP_GRANT_UNUSABLE' };
    }

    // D24-05: the runtime crypto boundary, BEFORE anything is persisted. A
    // structurally perfect off-curve point parses at every contract boundary in
    // WP-23 and dies here, so it can never reach the registry. The check is
    // repeated inside the commit transaction — this one keeps garbage out of
    // the request table, that one is the gate that matters.
    if (!this.keys.isRuntimeValidPublicKey(submission.publicKey)) {
      return { outcome: 'REFUSED', refusal: 'PUBLIC_KEY_NOT_RUNTIME_VALID' };
    }

    // C15-02: the thumbprint is COMPUTED, never believed. Nothing the submitter
    // sends names the key; the digest is derived from the key itself.
    const thumbprint = deriveP256PublicKeyThumbprint(submission.publicKey);

    // C16-01: the custody régime, resolved against the SERVER's catalogue
    // before anything is written. CONTROLLED_SHARED must name one, PERSONAL
    // must not, and the named one must exist, be live, and belong to this
    // organisation AND this site.
    const regimeRefusal = await this.resolveSubmittedCustodyRegime(submission);
    if (regimeRefusal !== null) return { outcome: 'REFUSED', refusal: regimeRefusal };

    // C16-02: ONE GRANT, ONE CEREMONY.
    //
    // `enrollment_request_grant_key` makes a second request under this grant
    // impossible at the database level. That leaves the service one honest
    // question: is this the SAME submission arriving twice, or a different one?
    // An identical repeat is a retry — a dropped response, a re-driven client —
    // and converges on the request that already exists rather than being told
    // its own earlier success was a conflict. A materially different submission
    // is the thing the constraint exists to stop, and refuses.
    //
    // Convergence is judged on the SUBMISSION's material content, not on the
    // request fingerprint: the fingerprint commits to `requested_at` and to the
    // attestation instant, so no two submissions could ever share one, and a
    // fingerprint comparison here would make every retry a conflict.
    const existing = await this.repository.findEnrollmentRequestByGrant(grant.organisationId, grant.id);
    if (existing !== null) {
      if (!this.submissionMatchesRequest(submission, existing)) {
        return { outcome: 'REFUSED', refusal: 'ENROLLMENT_REQUEST_CONFLICT' };
      }
      return {
        outcome: 'CONVERGED',
        enrollmentRequestId: existing.id,
        requestFingerprint: existing.requestFingerprint,
        serverSelectedSignatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
        attestationOutcome: existing.attestationOutcome,
      };
    }

    const requestedAt = await this.repository.now();
    const evidence = await this.attestation.evaluate({
      organisationId: submission.organisationId,
      deviceId: null,
      enrollmentRequestId: null,
      publicKeyThumbprint: thumbprint,
      now: requestedAt.toISOString(),
    });

    const enrollmentRequestId = randomUUID();
    const draft = {
      schema_version: 1 as const,
      enrollment_request_id: enrollmentRequestId,
      organisation_id: submission.organisationId,
      site_id: submission.siteId,
      intended_user_id: submission.intendedUserId,
      bootstrap_grant_id: grant.id,
      custody: submission.custody,
      // C15-01: recorded as the CLAIM it is. It is equality-bound to the
      // server's selected profile by the commit gate and never selects a
      // verifier here or anywhere else.
      claimed_signature_profile: submission.claimedSignatureProfile,
      key_storage: submission.keyStorage,
      public_key: submission.publicKey,
      public_key_thumbprint: thumbprint,
      attestation: evidence,
      requested_at: requestedAt.toISOString(),
    };

    const parsed = DeviceEnrollmentRequestSchema.safeParse(draft);
    if (!parsed.success) return { outcome: 'REFUSED', refusal: 'MALFORMED_CONTRACT_STRUCTURE' };
    const fingerprint = deviceEnrollmentRequestFingerprint(parsed.data);

    // C16-01: the WP-24-owned digest that covers what the frozen fingerprint
    // cannot — the custody régime. Persisted here so the approval can bind it
    // and the commit can detect a régime that moved after the human decided.
    const approvedSemanticsDigest = approvedEnrollmentSemanticsDigest({
      enrollmentRequestFingerprint: fingerprint,
      custody: submission.custody,
      custodyRegimeId: submission.custodyRegimeId,
    });

    // ONE transaction for the request row, its attestation observation and its
    // security event. A request persisted without the observation that judged
    // it would leave the commit gate reading evidence with no append-only
    // record behind it.
    //
    // C16-R2 — THE FIRST-USE RACE IS RESOLVED HERE, NOT HOPED AWAY.
    //
    // The read-before-write above answers "has this grant already opened a
    // request?" — and two simultaneous FIRST submissions can both be answered
    // "no". One then wins `enrollment_request_grant_key` and the other collides
    // with it. Before this change the loser received a raw
    // `PrismaClientKnownRequestError` (P2002) instead of the convergence or the
    // named conflict the surface promises, and a driver exception escaping a
    // security ceremony is a refusal nobody classified.
    //
    // The collision is caught, the transaction is rewound TO A SAVEPOINT (a
    // uniqueness violation aborts the whole Postgres transaction otherwise —
    // every later statement would fail 25P02), the ONE authoritative request is
    // re-read under `FOR UPDATE` in the same transaction, and the SAME semantic
    // comparison the read-before-write path uses decides the answer. Identical
    // submission -> CONVERGED on the request that exists; materially different
    // -> ENROLLMENT_REQUEST_CONFLICT.
    //
    // Note WHY the winner's row is guaranteed visible to that re-read: Postgres
    // makes the second inserter WAIT on the unique index until the first
    // transaction ends. A P2002 is therefore proof that the winner COMMITTED.
    return this.repository.transaction(async (tx) => {
      await this.repository.openEnrollmentRequestSavepoint(tx);
      try {
        await this.repository.createEnrollmentRequest(tx, {
        id: enrollmentRequestId,
        organisationId: submission.organisationId,
        siteId: submission.siteId,
        intendedUserId: submission.intendedUserId,
        bootstrapGrantId: grant.id,
        custody: submission.custody,
        custodyRegimeId: submission.custodyRegimeId,
        publicKey: submission.publicKey,
        publicKeyThumbprint: thumbprint,
        keyStorage: submission.keyStorage,
        claimedSignatureProfile: submission.claimedSignatureProfile,
        // THE SERVER'S ANSWER, persisted beside the claim so a later
        // verification reads the registry's profile, never the device's
        // (C15-01).
        serverSelectedSignatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
        requestFingerprint: fingerprint,
        approvedSemanticsDigest,
        attestationOutcome: evidence.outcome,
        attestationEvaluatedAt: new Date(evidence.evaluated_at),
        attestationReference: evidence.attestation_reference,
        requestedAt,
        state: 'REQUESTED',
        });
      } catch (error) {
        // Anything that is not a uniqueness violation is a real fault and is
        // re-thrown untouched. A P2002 that does NOT turn out to be this
        // grant's row is re-thrown too — the answer below is only honest when
        // an authoritative request genuinely exists.
        if (!isUniqueConstraintViolation(error)) throw error;
        await this.repository.rollbackEnrollmentRequestSavepoint(tx);
        const authoritative = await this.repository.lockEnrollmentRequestByGrant(tx, grant.organisationId, grant.id);
        if (authoritative === null) throw error;
        if (!this.submissionMatchesRequest(submission, authoritative)) {
          return { outcome: 'REFUSED' as const, refusal: 'ENROLLMENT_REQUEST_CONFLICT' as const };
        }
        // The loser writes NOTHING: not the request (it lost), not a second
        // attestation observation, not a second ENROLLMENT_REQUESTED event. The
        // winner already recorded all three for this one ceremony.
        return {
          outcome: 'CONVERGED' as const,
          enrollmentRequestId: authoritative.id,
          requestFingerprint: authoritative.requestFingerprint,
          serverSelectedSignatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
          attestationOutcome: authoritative.attestationOutcome,
        };
      }

      // D24-07: every observation is persisted, append-only, whatever it said.
      await this.repository.appendAttestationObservation(tx, {
        organisationId: submission.organisationId,
        deviceId: null,
        enrollmentRequestId,
        outcome: evidence.outcome,
        attestationReference: evidence.attestation_reference,
        evaluatedAt: new Date(evidence.evaluated_at),
        observedAt: requestedAt,
        traceId: submission.traceId,
      });
      await this.audit.record(
        tx,
        { organisationId: submission.organisationId, deviceId: null, actorUserId: null, occurredAt: requestedAt, traceId: submission.traceId },
        {
          type: 'ENROLLMENT_REQUESTED',
          enrollmentRequestId,
          requestFingerprint: fingerprint,
          siteId: submission.siteId,
          intendedUserId: submission.intendedUserId,
          custody: submission.custody,
          keyStorage: submission.keyStorage,
          publicKeyThumbprint: thumbprint,
          signatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
          attestationOutcome: evidence.outcome,
        },
      );

      return {
        outcome: 'REQUESTED' as const,
        enrollmentRequestId,
        requestFingerprint: fingerprint,
        serverSelectedSignatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
        attestationOutcome: evidence.outcome,
      };
    });
  }

  // -------------------------------------------------------------------------
  // Step 3 — the independent human approval (D24-03)
  // -------------------------------------------------------------------------

  /**
   * Approves ONE exact enrollment request fingerprint.
   *
   * `expectedRequestFingerprint` is required and is compared against the
   * fingerprint RECOMPUTED from the stored request. That is C14-02's whole
   * point in one parameter: an approver approves a specific set of bytes — this
   * key, this custody, this attestation evidence evaluated at this instant —
   * and cannot be made to approve a different request that merely shares an id.
   *
   * Both separations are checked here AND again inside the commit transaction.
   * Checking twice is not redundancy: this check gives the approver a clear
   * refusal, and the commit check is the one that holds when the rows are
   * locked and nothing can move underneath it (D24-06).
   */
  async approveEnrollmentRequest(
    principal: Principal,
    input: { organisationId: string; enrollmentRequestId: string; expectedRequestFingerprint: string; traceId: string },
  ): Promise<ApproveEnrollmentOutcome> {
    const request = await this.repository.findEnrollmentRequest(input.organisationId, input.enrollmentRequestId);
    if (request === null) return { outcome: 'REFUSED', refusal: 'ENROLLMENT_REQUEST_NOT_FOUND' };

    const refusal = checkDeviceAuthority(principal, ACTION_DEVICE_ENROLLMENT_APPROVE, input.organisationId, request.siteId);
    // The refusal is collapsed to NOT_FOUND on purpose. Telling an unauthorised
    // caller that the request exists at a site they cannot reach is a roster
    // oracle; the isolation matrix in the acceptance suite asserts that a
    // foreign-tenant request and an invented id are indistinguishable here.
    if (refusal !== null) return { outcome: 'REFUSED', refusal: 'ENROLLMENT_REQUEST_NOT_FOUND' };

    if (request.state !== 'REQUESTED') {
      return { outcome: 'REFUSED', refusal: request.state === 'APPROVED' ? 'ALREADY_APPROVED' : 'ENROLLMENT_STATE_INVALID' };
    }

    const grant = await this.repository.findBootstrapGrant(input.organisationId, request.bootstrapGrantId);
    if (grant === null) return { outcome: 'REFUSED', refusal: 'BOOTSTRAP_GRANT_NOT_FOUND' };

    // D24-03: there is no self-approval path, in either direction.
    if (grant.issuedByUserId === principal.user.id) return { outcome: 'REFUSED', refusal: 'ISSUER_MAY_NOT_APPROVE' };
    if (request.intendedUserId === principal.user.id) return { outcome: 'REFUSED', refusal: 'INTENDED_USER_MAY_NOT_APPROVE' };

    const contractRequest = this.toContractRequest(request);
    if (contractRequest === null) return { outcome: 'REFUSED', refusal: 'MALFORMED_CONTRACT_STRUCTURE' };
    const fingerprint = deviceEnrollmentRequestFingerprint(contractRequest);
    if (fingerprint !== input.expectedRequestFingerprint || fingerprint !== request.requestFingerprint) {
      return { outcome: 'REFUSED', refusal: 'APPROVAL_FINGERPRINT_MISMATCH' };
    }

    // C16-01: WHAT THIS HUMAN IS ACTUALLY APPROVING.
    //
    // The frozen fingerprint above covers `DeviceEnrollmentRequestSchema`,
    // which has no régime field, so on its own it cannot express "and under
    // THIS custody régime". This digest can, and the approval binds it. The
    // stored column on the request is recomputed rather than read as authority
    // — an id names a row, a digest names its meaning, and only a recomputation
    // detects a row that was rewritten between request and approval.
    const semanticsDigest = approvedEnrollmentSemanticsDigest({
      enrollmentRequestFingerprint: fingerprint,
      custody: request.custody as DeviceCustody,
      custodyRegimeId: request.custodyRegimeId,
    });
    if (semanticsDigest !== request.approvedSemanticsDigest) {
      return { outcome: 'REFUSED', refusal: 'APPROVED_SEMANTICS_MISMATCH' };
    }

    try {
      return await this.repository.transaction(async (tx) => {
      const now = await this.repository.dbNow(tx);
      // The contract's own state matrix decides whether this move is legal.
      if (!canTransitionDeviceEnrollment('REQUESTED', 'APPROVED')) {
        return { outcome: 'REFUSED', refusal: 'ENROLLMENT_STATE_INVALID' };
      }
      const advanced = await this.repository.advanceEnrollmentState(tx, input.organisationId, request.id, 'REQUESTED', 'APPROVED');
      // C16-R3(b): lost to a concurrent approval. The unique index on
      // (organisation_id, enrollment_request_id) would refuse the second
      // approval row anyway; this reports it as a state refusal rather than a
      // driver fault. It THROWS rather than returns for the reason every other
      // fenced CAS in this module now does: a normal return COMMITS, and the
      // rule "exactly one row, or nothing happened" must not depend on a
      // reviewer noticing that this particular update happens to be the first
      // write in its transaction.
      if (advanced !== 1) throw new ShieldTransactionRollback('ALREADY_APPROVED', { audited: false });

      const approval = await this.repository.createEnrollmentApproval(tx, {
        organisationId: input.organisationId,
        enrollmentRequestId: request.id,
        approvedByUserId: principal.user.id,
        approvedRequestFingerprint: fingerprint,
        approvedSiteId: request.siteId,
        approvedIntendedUserId: request.intendedUserId,
        approvedCustody: request.custody,
        // C16-01: the régime is the APPROVAL's own record, exactly like
        // `approved_site_id`. The commit reads the régime from HERE and never
        // from the request, so a régime swapped behind a standing approval is a
        // disagreement the commit can SEE rather than one it inherits.
        approvedCustodyRegimeId: request.custodyRegimeId,
        approvedSemanticsDigest: semanticsDigest,
        approvedAt: now,
      });

      await this.audit.record(
        tx,
        { organisationId: input.organisationId, deviceId: null, actorUserId: principal.user.id, occurredAt: now, traceId: input.traceId },
        {
          type: 'ENROLLMENT_APPROVED',
          enrollmentRequestId: request.id,
          approvedRequestFingerprint: fingerprint,
          approvedByUserId: principal.user.id,
          siteId: request.siteId,
          custody: request.custody,
        },
      );

      return { outcome: 'APPROVED', approvalId: approval.id, approvedRequestFingerprint: fingerprint };
      });
    } catch (error) {
      if (!isShieldTransactionRollback(error)) throw error;
      return { outcome: 'REFUSED', refusal: error.refusal };
    }
  }

  // -------------------------------------------------------------------------
  // Step 4 — the intended user authenticates, and gets a fresh challenge
  // -------------------------------------------------------------------------

  /**
   * Issues a fresh possession challenge.
   *
   * The authority here is NOT a `device.*` action — D24-02 is explicit that a
   * Field operative's participation is not device-management authority, and it
   * would be a contradiction to require one. What is required is that the
   * INTENDED USER is the one authenticated, which is the third of the
   * contract's four facts arriving in a live session rather than as provenance.
   */
  async issuePossessionChallenge(
    principal: Principal,
    input: { organisationId: string; enrollmentRequestId: string; traceId: string },
  ): Promise<IssuePossessionChallengeOutcome> {
    if (principal.organisation_id !== input.organisationId) {
      return { outcome: 'REFUSED', refusal: 'ENROLLMENT_REQUEST_NOT_FOUND' };
    }
    const request = await this.repository.findEnrollmentRequest(input.organisationId, input.enrollmentRequestId);
    if (request === null) return { outcome: 'REFUSED', refusal: 'ENROLLMENT_REQUEST_NOT_FOUND' };
    if (request.intendedUserId !== principal.user.id) return { outcome: 'REFUSED', refusal: 'ENROLLMENT_REQUEST_NOT_FOUND' };
    // APPROVED or POSSESSION_PROVEN. A device that answered once and then lost
    // the response — a dropped connection, a crashed process — must be able to
    // ask for a fresh challenge rather than being told to start a whole new
    // ceremony and get a second human approval. Re-issuing grants NOTHING on
    // its own: the commit still requires a server verdict BOUND to the exact
    // challenge, request, fingerprint and key, so an extra challenge is an
    // extra opportunity to prove possession and never a way around proving it.
    // REQUESTED is excluded because a challenge before the human approval
    // would let a device begin proving possession of a key nobody approved.
    if (request.state !== 'APPROVED' && request.state !== 'POSSESSION_PROVEN') {
      return { outcome: 'REFUSED', refusal: 'ENROLLMENT_STATE_INVALID' };
    }

    const issuedAt = await this.repository.now();
    // The contract's ceiling again, imported. Note that this is deliberately a
    // DIFFERENT constant from the rotation challenge's, even though the two are
    // numerically equal today: D24-10A rules that rotation policy and
    // enrollment policy must not become silently coupled.
    const expiresAt = new Date(issuedAt.getTime() + DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS);
    const nonce = randomBytes(CHALLENGE_NONCE_ENTROPY_BYTES).toString('base64url');

    const challenge = await this.repository.createPossessionChallenge({
      organisationId: input.organisationId,
      enrollmentRequestId: request.id,
      nonce,
      issuedAt,
      expiresAt,
    });

    return { outcome: 'ISSUED', challengeId: challenge.id, nonce, expiresAt };
  }

  // -------------------------------------------------------------------------
  // Step 5 — the server verifies possession (C15-03)
  // -------------------------------------------------------------------------

  /**
   * Checks the device's signature and records a BOUND server verdict.
   *
   * There is no `possessionVerified: true` anywhere on this path. What is
   * written is a `DevicePossessionVerificationResult`-shaped row carrying every
   * value the check depended on — the challenge, the request, its fingerprint,
   * the APPROVED key's thumbprint, the exact statement bytes and the
   * server-selected profile — so a genuine verdict from one ceremony is
   * structurally unusable in another. The commit gate checks each of those
   * equals the corresponding approved value.
   *
   * The key used is the one on the REQUEST ROW, which is the key the human
   * approved. Nothing in the response is read as key material, and there is no
   * parameter through which a caller could pass one.
   */
  async verifyPossession(input: {
    organisationId: string;
    enrollmentRequestId: string;
    challengeId: string;
    response: unknown;
    traceId: string;
  }): Promise<VerifyPossessionOutcome> {
    const parsedResponse = DevicePossessionResponseSchema.safeParse(input.response);
    if (!parsedResponse.success) return { outcome: 'REFUSED', refusal: 'MALFORMED_CONTRACT_STRUCTURE' };
    const response = parsedResponse.data;

    const request = await this.repository.findEnrollmentRequest(input.organisationId, input.enrollmentRequestId);
    if (request === null) return { outcome: 'REFUSED', refusal: 'ENROLLMENT_REQUEST_NOT_FOUND' };

    const challenge = await this.repository.findPossessionChallenge(input.organisationId, input.challengeId);
    if (challenge === null) return { outcome: 'REFUSED', refusal: 'POSSESSION_CHALLENGE_NOT_FOUND' };
    // A challenge minted for another request cannot be answered into this one.
    // The commit gate refuses this too (CHALLENGE_MISBOUND); refusing here as
    // well means no verdict row is ever created for a mismatched pair.
    if (challenge.enrollmentRequestId !== request.id) return { outcome: 'REFUSED', refusal: 'POSSESSION_CHALLENGE_MISBOUND' };
    if (response.challenge_id !== challenge.id || response.enrollment_request_id !== request.id) {
      return { outcome: 'REFUSED', refusal: 'POSSESSION_CHALLENGE_MISBOUND' };
    }

    const contractRequest = this.toContractRequest(request);
    if (contractRequest === null) return { outcome: 'REFUSED', refusal: 'MALFORMED_CONTRACT_STRUCTURE' };
    const fingerprint = deviceEnrollmentRequestFingerprint(contractRequest);

    // C15-01: the profile bound into the SIGNED BYTES is the server's, read
    // from the request row the server itself wrote. The device's claim reaches
    // `verifySignature` only to be equality-checked against it.
    const statementInput = {
      challenge_id: challenge.id,
      enrollment_request_id: request.id,
      enrollment_request_fingerprint: fingerprint,
      nonce: challenge.nonce,
      public_key_thumbprint: request.publicKeyThumbprint,
      signature_profile: SERVER_SELECTED_SIGNATURE_PROFILE,
    };
    const statement = canonicalDevicePossessionStatement(statementInput);
    const statementFingerprint = devicePossessionStatementFingerprint(statementInput);

    const verified = this.keys.verifySignature({
      registeredPublicKey: request.publicKey,
      message: statement,
      signature: response.signature,
      serverResolvedProfile: request.serverSelectedSignatureProfile,
      claimedProfile: response.claimed_signature_profile,
    });

    try {
      return await this.repository.transaction(async (tx) => {
      // C15-03: THE SERVER's instant is freshness. `response.answered_at` — the
      // device's own claim — is read nowhere in this method or in the gate.
      const verifiedAt = await this.repository.dbNow(tx);
      const row = await this.repository.createPossessionVerification(tx, {
        organisationId: input.organisationId,
        challengeId: challenge.id,
        enrollmentRequestId: request.id,
        enrollmentRequestFingerprint: fingerprint,
        publicKeyThumbprint: request.publicKeyThumbprint,
        possessionStatementFingerprint: statementFingerprint,
        signatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
        verified,
        verifiedAt,
      });

      if (verified) {
        // C16-R3(b): the count is the concurrency signal. This update is fenced
        // on `state = 'APPROVED'`, and it runs AFTER the verification row has
        // been written — so a discarded zero committed a `verified: true`
        // verdict, and its D24-12 audit event, for a ceremony whose state never
        // advanced. The next commit would then find POSSESSION_VERIFICATION but
        // a request that is not POSSESSION_PROVEN. It throws instead, and the
        // whole transaction — verdict row included — unwinds.
        const advanced = await this.repository.advanceEnrollmentState(tx, input.organisationId, request.id, 'APPROVED', 'POSSESSION_PROVEN');
        if (advanced !== 1) throw new ShieldTransactionRollback('ENROLLMENT_STATE_INVALID', { audited: false });
      }

      await this.audit.record(
        tx,
        { organisationId: input.organisationId, deviceId: null, actorUserId: null, occurredAt: verifiedAt, traceId: input.traceId },
        {
          type: 'POSSESSION_VERIFIED',
          enrollmentRequestId: request.id,
          challengeId: challenge.id,
          publicKeyThumbprint: request.publicKeyThumbprint,
          possessionStatementFingerprint: statementFingerprint,
          signatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
          verified,
        },
      );

      return {
        outcome: verified ? ('VERIFIED' as const) : ('NOT_VERIFIED' as const),
        verificationId: row.id,
        possessionStatementFingerprint: statementFingerprint,
      };
      });
    } catch (error) {
      // C16-R3(b): the fenced-CAS rollback, translated back into this module's
      // refusal-as-data discipline. Nothing was recorded, because nothing
      // survived the abort — including the verification row this transaction
      // had already written.
      if (!isShieldTransactionRollback(error)) throw error;
      return { outcome: 'REFUSED', refusal: error.refusal };
    }
  }

  // -------------------------------------------------------------------------
  // Step 6 — ONE transaction commits the device identity (D24-06)
  // -------------------------------------------------------------------------

  /**
   * The commit. Everything below happens inside ONE `$transaction`.
   *
   * Every authority-bearing row is re-read UNDER `SELECT ... FOR UPDATE` and
   * re-validated at commit rather than trusted from an earlier read: the
   * request, the grant, the approval, the challenge and the possession verdict.
   * Then the four facts are handed to `evaluateDeviceEnrollmentCommit`, which
   * owns every admissibility rule, and only its `COMMIT` verdict causes an
   * effect.
   *
   * `candidateDeviceId` is generated BEFORE the replay consumption and used as
   * the stored outcome reference for BOTH one-shot identities. That is what
   * makes D24-06's convergence rule work: a retry generates its own candidate,
   * finds the first attempt's reference already stored, discards its own and
   * converges on the SAME device identity. A ceremony with changed semantics
   * behind the same identity conflicts and creates no second device.
   */
  async commitEnrollment(
    principal: Principal,
    input: {
      organisationId: string;
      enrollmentRequestId: string;
      challengeId: string;
      traceId: string;
    },
  ): Promise<CommitEnrollmentOutcome> {
    // The device id, minted before anything is locked so it can serve as the
    // convergence reference for both one-shot identities on a FIRST attempt.
    // On a retry it is discarded in favour of the outcome the registry
    // actually holds — see `resolveCanonicalEnrollmentOutcome`.
    const candidateDeviceId = randomUUID();

    // C16-02: what the rolled-back transaction still needs to RECORD. A
    // transaction that aborts takes its audit rows with it, so the values the
    // D24-12 event needs are captured in this closure variable and the event is
    // written afterwards, in its own transaction. The refusal is external; the
    // security state is not.
    const rolledBack: { fingerprint: string | null; replayIdentityDigest: string | null } = {
      fingerprint: null,
      replayIdentityDigest: null,
    };

    try {
      return await this.repository.transaction(async (tx) => {
        const now = await this.repository.dbNow(tx);

        const locked = await this.lockCommitState(tx, input.organisationId, input.enrollmentRequestId, input.challengeId);
        if (typeof locked === 'string') return { outcome: 'REFUSED', refusal: locked };
        rolledBack.fingerprint = locked.fingerprint;

        // ---- PREVALIDATION (C16-04) ------------------------------------
        // Everything fallible that can be decided from rows already in hand is
        // decided HERE, before the first consumption write. Each of these may
        // still `return` after writing its own refusal audit: that audit is the
        // refusal's record, it is the only thing this transaction has written,
        // and committing it is the point.

        // D24-03/D24-06: the two human separations, re-checked inside the
        // transaction against LOCKED rows — not merely at the API surface.
        if (locked.grant.issuedByUserId === locked.approverUserId) {
          await this.recordEnrollmentRefusal(tx, input, locked.fingerprint, 'ISSUER_MAY_NOT_APPROVE', now, principal.user.id);
          return { outcome: 'REFUSED', refusal: 'ISSUER_MAY_NOT_APPROVE' };
        }
        if (locked.request.intendedUserId === locked.approverUserId) {
          await this.recordEnrollmentRefusal(tx, input, locked.fingerprint, 'INTENDED_USER_MAY_NOT_APPROVE', now, principal.user.id);
          return { outcome: 'REFUSED', refusal: 'INTENDED_USER_MAY_NOT_APPROVE' };
        }

        // D24-05, re-run under lock: the key must still import. A registry
        // entry is only allowed to become CURRENT after the platform provider
        // has accepted the point.
        if (!this.keys.isRuntimeValidPublicKey(locked.request.publicKey)) {
          await this.recordEnrollmentRefusal(tx, input, locked.fingerprint, 'PUBLIC_KEY_NOT_RUNTIME_VALID', now, principal.user.id);
          return { outcome: 'REFUSED', refusal: 'PUBLIC_KEY_NOT_RUNTIME_VALID' };
        }

        // C16-01: THE APPROVAL'S OWN SEMANTICS, RECOMPUTED FROM THE LOCKED
        // REQUEST. This is the check that makes the régime approval-bound: the
        // frozen request fingerprint is blind to the régime, so a régime
        // rewritten behind a standing approval changes nothing the WP-23
        // fingerprint can see and everything this digest can.
        const semanticsDigest = approvedEnrollmentSemanticsDigest({
          enrollmentRequestFingerprint: locked.fingerprint,
          custody: locked.contractRequest.custody,
          custodyRegimeId: locked.request.custodyRegimeId,
        });
        if (semanticsDigest !== locked.approval.approvedSemanticsDigest) {
          await this.recordEnrollmentRefusal(tx, input, locked.fingerprint, 'APPROVED_SEMANTICS_MISMATCH', now, principal.user.id);
          return { outcome: 'REFUSED', refusal: 'APPROVED_SEMANTICS_MISMATCH' };
        }

        // C16-R1: THE APPROVAL'S OWN REGIME RECORD IS BOUND TOO.
        //
        // The check above recomputes the digest from the REQUEST. It proves the
        // request still says what the approval bound — and it proves NOTHING
        // about the approval row itself, which is where `performCommit` actually
        // reads the regime from. `approved_custody_regime_id` is the approval's
        // INDEPENDENT record (that is the point of it: a disagreement must be
        // visible rather than inherited), so a writer that moves the approval's
        // regime A -> B and leaves `approved_semantics_digest` alone changed
        // nothing either the frozen fingerprint or the request-derived digest
        // can see, and the device would have been associated under B.
        //
        // Two checks close it, and the ORDER is deliberate: the direct
        // comparison first, so two records disagreeing is reported as ITSELF and
        // an operator is told which row moved rather than being handed a digest
        // mismatch to work backwards from.
        if (locked.approval.approvedCustodyRegimeId !== locked.request.custodyRegimeId) {
          await this.recordEnrollmentRefusal(tx, input, locked.fingerprint, 'APPROVED_CUSTODY_REGIME_MISMATCH', now, principal.user.id);
          return { outcome: 'REFUSED', refusal: 'APPROVED_CUSTODY_REGIME_MISMATCH' };
        }

        // ... and the approval must agree with its OWN digest, recomputed from
        // its OWN approved fields. Together with the request-derived
        // recomputation above this pins the whole triple — fingerprint, custody
        // and regime — on BOTH rows: if both recomputations equal the one stored
        // digest, the two triples are equal, so the approval's approved
        // fingerprint and approved custody are the request's too.
        const approvalOwnDigest = approvedEnrollmentSemanticsDigest({
          enrollmentRequestFingerprint: locked.approval.approvedRequestFingerprint,
          custody: locked.approval.approvedCustody as DeviceCustody,
          custodyRegimeId: locked.approval.approvedCustodyRegimeId,
        });
        if (approvalOwnDigest !== locked.approval.approvedSemanticsDigest) {
          await this.recordEnrollmentRefusal(tx, input, locked.fingerprint, 'APPROVAL_RECORD_INCONSISTENT', now, principal.user.id);
          return { outcome: 'REFUSED', refusal: 'APPROVAL_RECORD_INCONSISTENT' };
        }

        // C16-R1: AND THE REGIME ITSELF, RE-READ AND LOCKED AT FINAL COMMIT.
        //
        // `resolveSubmittedCustodyRegime` judged this regime when the REQUEST
        // was opened. That was a different moment: a regime can be retired, and
        // a row can be rewritten, between a request and its commit. D24-06's
        // rule is that every authority-bearing row is re-read under `FOR UPDATE`
        // inside the commit transaction and re-validated there, and the custody
        // regime is such a row — it governs the hand-over discipline of the
        // hardware this transaction is about to register.
        //
        // Absent, foreign-tenant and right-tenant-wrong-site all answer
        // `CUSTODY_REGIME_NOT_FOUND`, exactly as they do at request time;
        // retirement is reported distinctly for the same reason it is there.
        if (locked.request.custodyRegimeId !== null) {
          const regime = await this.repository.lockCustodyRegime(tx, input.organisationId, locked.request.custodyRegimeId);
          const regimeRefusal =
            regime === null || regime.siteId !== locked.contractRequest.site_id
              ? ('CUSTODY_REGIME_NOT_FOUND' as const)
              : regime.retiredAt !== null
                ? ('CUSTODY_REGIME_RETIRED' as const)
                : null;
          if (regimeRefusal !== null) {
            await this.recordEnrollmentRefusal(tx, input, locked.fingerprint, regimeRefusal, now, principal.user.id);
            return { outcome: 'REFUSED', refusal: regimeRefusal };
          }
        }

        // C16-02: RESOLVE BEFORE BURNING. Both one-shot identities must name
        // ONE canonical committed outcome, and it must be an outcome the
        // database can actually produce. This is a pure read; a refusal here is
        // still pre-write and still returns normally with its own audit.
        const grantReplayKey = deviceBootstrapGrantReplayKey({
          organisation_id: locked.contractGrant.organisation_id,
          site_id: locked.contractGrant.site_id,
          intended_user_id: locked.contractGrant.intended_user_id,
          grant_id: locked.contractGrant.grant_id,
        });
        const challengeReplayKey = devicePossessionChallengeReplayKey({
          organisation_id: locked.contractRequest.organisation_id,
          site_id: locked.contractRequest.site_id,
          intended_user_id: locked.contractRequest.intended_user_id,
          enrollment_request_id: locked.contractRequest.enrollment_request_id,
          challenge_id: locked.contractChallenge.challenge_id,
          nonce: locked.contractChallenge.nonce,
        });

        const resolved = await this.resolveCanonicalEnrollmentOutcome(tx, {
          organisationId: input.organisationId,
          enrollmentRequestId: locked.request.id,
          fingerprint: locked.fingerprint,
          grantReplayKey,
          challengeReplayKey,
          candidateDeviceId,
        });
        if (!resolved.resolved) {
          await this.recordEnrollmentRefusal(tx, input, locked.fingerprint, resolved.refusal, now, principal.user.id);
          return { outcome: 'REFUSED', refusal: resolved.refusal };
        }

        // C16-R3: THE LAST STRUCTURAL CHECK, MOVED IN FRONT OF THE BURN.
        //
        // C15-08's custody shape used to be parsed inside `performCommit`, and a
        // failure there RETURNED a `MALFORMED_CONTRACT_STRUCTURE` refusal —
        // after both replay identities had been consumed. A normal return from a
        // Prisma interactive transaction COMMITS, so that refusal left two
        // consumption rows behind for a device that was never created: exactly
        // the defect C16-02 closed everywhere else and missed here.
        //
        // It is a pure function of rows already in hand, so it belongs here. The
        // rule this restores, and which `performCommit`'s return type now proves
        // structurally, is: THERE IS NO ORDINARY REFUSAL PATH AFTER THE FIRST
        // CONSUMPTION WRITE.
        const association = DeviceCustodyAssociationSchema.safeParse({
          schema_version: 1,
          organisation_id: input.organisationId,
          device_id: resolved.outcomeRef,
          custody: locked.contractRequest.custody,
          assigned_user_id: locked.contractRequest.custody === 'PERSONAL' ? locked.contractRequest.intended_user_id : null,
          // C16-01: THE RÉGIME COMES FROM THE APPROVAL ROW. Not from a commit
          // parameter (there is none any more), and not from the request either:
          // the approval is the human decision. C16-R1's two checks above have
          // proved the approval agrees with its own digest AND with the locked
          // request, so reading the approval here is a statement about the
          // human's decision rather than a bet that nothing moved.
          custody_regime_id: locked.approval.approvedCustodyRegimeId,
          associated_site_ids: [locked.contractRequest.site_id],
          associated_at: now.toISOString(),
          released_at: null,
        });
        if (!association.success) {
          await this.recordEnrollmentRefusal(tx, input, locked.fingerprint, 'MALFORMED_CONTRACT_STRUCTURE', now, principal.user.id);
          return { outcome: 'REFUSED', refusal: 'MALFORMED_CONTRACT_STRUCTURE' };
        }

        // ---- FIRST CONSUMPTION WRITE -----------------------------------
        // Past this line every refusal THROWS. D24-11: both one-shot
        // identities, consumed atomically inside THIS transaction so the burn
        // and the effect share a fate — and now they genuinely do, because a
        // refusal below aborts the transaction that wrote them.
        const grantConsumption = await this.replay.consume(tx, {
          organisationId: input.organisationId,
          ceremony: CEREMONY_BOOTSTRAP_GRANT,
          replayKey: grantReplayKey,
          statementFingerprint: locked.fingerprint,
          candidateOutcomeRef: resolved.outcomeRef,
          traceId: input.traceId,
        });
        rolledBack.replayIdentityDigest = grantConsumption.replayIdentityDigest;

        const challengeConsumption = await this.replay.consume(tx, {
          organisationId: input.organisationId,
          ceremony: CEREMONY_POSSESSION_CHALLENGE,
          replayKey: challengeReplayKey,
          statementFingerprint: locked.fingerprint,
          candidateOutcomeRef: resolved.outcomeRef,
          traceId: input.traceId,
        });

        // THE GATE. Every admissibility rule in the ceremony is decided here
        // and nowhere else in this file.
        const decision = evaluateDeviceEnrollmentCommit({
          request: locked.contractRequest,
          grant: locked.contractGrant,
          approval: locked.contractApproval,
          challenge: locked.contractChallenge,
          possessionVerification: locked.contractVerification,
          serverSelectedSignatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
          grantConsumption: grantConsumption.consumption,
          challengeConsumption: challengeConsumption.consumption,
          // Provenance is not identity: who is authenticated RIGHT NOW is a
          // separate input from `request.intended_user_id`, and the contract
          // compares them itself.
          authenticatedUserId: principal.user.id,
          now: now.toISOString(),
        });

        if (decision.decision === 'REFUSE') {
          // C16-02: THROWN, never returned. A pre-existing consumption row from
          // an earlier COMMITTED ceremony survives this rollback because it was
          // never part of this transaction — a spent identity stays spent. What
          // does not survive is a row THIS transaction wrote for an effect it
          // is now refusing to produce.
          throw new ShieldTransactionRollback(decision.refusal);
        }

        if (decision.decision === 'CONVERGE') {
          // D24-06: the SAME device identity, never a second. The reference was
          // resolved against the device table before either identity was spent,
          // so this answer names hardware that demonstrably exists.
          return { outcome: 'CONVERGED', deviceId: decision.stored_outcome_ref };
        }

        return this.performCommit(tx, {
          input,
          principal,
          locked,
          now,
          deviceId: resolved.outcomeRef,
          fingerprint: decision.enrollment_request_fingerprint,
          association: association.data,
        });
      });
    } catch (error) {
      if (!isShieldTransactionRollback(error)) throw error;
      // The transaction is gone; the trail is not. D24-12 still needs to record
      // that this ceremony was refused, and it is written here — after the
      // rollback — so the audit survives while the consumption rows do not.
      await this.recordRolledBackEnrollmentRefusal(input, error.refusal, principal.user.id, rolledBack);
      return { outcome: 'REFUSED', refusal: error.refusal };
    }
  }

  // -------------------------------------------------------------------------
  // Commit internals
  // -------------------------------------------------------------------------

  /**
   * The atomic effect: the device, its first key, the site/custody
   * association, the initial trust, the transition record and the audit.
   *
   * The ORDER is chosen so a foreign-key or uniqueness violation aborts before
   * anything downstream: the device row (whose composite relations prove the
   * tenant pairing at the database level, D24-04a), then the key, then the
   * scope, then history.
   */
  private async performCommit(
    tx: Tx,
    context: {
      input: { organisationId: string; enrollmentRequestId: string; challengeId: string; traceId: string };
      principal: Principal;
      locked: LockedCommitState;
      now: Date;
      deviceId: string;
      fingerprint: string;
      /**
       * C16-R3: PARSED BEFORE THE BURN, by the caller. Passing the already-valid
       * structure in is what makes "no ordinary refusal after first consumption"
       * a property of the code rather than a promise about it.
       */
      association: DeviceCustodyAssociation;
    },
  ): Promise<Extract<CommitEnrollmentOutcome, { outcome: 'COMMITTED' }>> {
    const { input, locked, now, deviceId, association } = context;

    // D24-04: DERIVED, never caller-selected. There is no parameter through
    // which a namespace could arrive, and D23-09's rule that the only way to a
    // fresh namespace is a new device_id follows from that by construction.
    const sequenceNamespaceId = deviceSequenceNamespaceId({ organisation_id: input.organisationId, device_id: deviceId });

    // D24-08 / C14-05. A brand-new identity has no history, so it has no prior
    // verified attestation to ride on — `hasPriorVerified` is false and
    // `lastVerifiedAt` is null, which is exactly why C15-08 says a first
    // enrollment during an outage starts DEGRADED rather than inheriting the
    // standing some OTHER identity earned.
    const standing = evaluateAttestationStanding({
      outcome: locked.contractRequest.attestation.outcome,
      lastVerifiedAt: null,
      now: now.toISOString(),
      hasPriorVerified: false,
    });

    // THE TRUST CONCLUSION IS THE CONTRACT'S. No request DTO carries a trust
    // field, nothing in this transaction reads one, and this line is the only
    // place an initial trust value comes from (D24-08).
    const trust = initialDeviceTrustOnEnrollment({
      keyStorage: locked.contractRequest.key_storage,
      attestationStanding: standing.standing,
    });

    // C15-08's custody shape came in ALREADY PARSED by the caller (C16-R3): a
    // PERSONAL device names its operative and no régime, a CONTROLLED_SHARED
    // device names its régime and no permanent assignee, and the CONTRACT
    // enforced that before either replay identity was spent.

    const keyId = randomUUID();
    const keyVersion = 1;

    await this.repository.createDevice(tx, {
      id: deviceId,
      organisationId: input.organisationId,
      custody: locked.contractRequest.custody,
      // PROVENANCE COLUMNS. Neither is ever consulted to answer a live
      // authorisation question (C14-02, and the schema header says so too).
      enrolledByUserId: locked.grant.issuedByUserId,
      intendedUserId: locked.contractRequest.intended_user_id,
      sequenceNamespaceId,
      trust,
      currentKeyId: keyId,
      currentKeyVersion: keyVersion,
      enrollmentRequestId: locked.request.id,
      enrolledAt: now,
    });

    await this.repository.createDeviceKey(tx, {
      id: randomUUID(),
      organisationId: input.organisationId,
      deviceId,
      keyId,
      keyVersion,
      // C15-02: the ACTUAL key, not just its name. A registry that cannot
      // verify is not a registry.
      publicKey: locked.request.publicKey,
      publicKeyThumbprint: locked.request.publicKeyThumbprint,
      signatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
      keyStorage: locked.request.keyStorage,
      // D24-05: CURRENT only after the runtime import above succeeded.
      status: 'CURRENT',
      registeredAt: now,
    });

    await this.repository.createDeviceSiteScope(tx, {
      organisationId: input.organisationId,
      deviceId,
      siteId: locked.contractRequest.site_id,
      custody: locked.contractRequest.custody,
      assignedUserId: association.assigned_user_id,
      custodyRegimeId: association.custody_regime_id,
      associatedAt: now,
    });

    // D24-08: every trust change writes a transition, and that includes the
    // first one. `DEVICE_TRUST_PREVIOUS_NONE` is used rather than one of the
    // six states because a device that did not exist a moment ago was not in
    // any of them — see the constant's own note.
    await this.repository.appendTrustTransition(tx, {
      organisationId: input.organisationId,
      deviceId,
      previousTrust: DEVICE_TRUST_PREVIOUS_NONE,
      newTrust: trust,
      reason: TRUST_REASON_ENROLLMENT_INITIAL,
      evidenceRefs: [locked.fingerprint, `attestation:${standing.standing}`],
      authorisedByUserId: locked.contractApproval.approved_by_user_id,
      occurredAt: now,
      traceId: input.traceId,
    });

    await this.repository.appendAttestationObservation(tx, {
      organisationId: input.organisationId,
      deviceId,
      enrollmentRequestId: locked.request.id,
      outcome: locked.contractRequest.attestation.outcome,
      attestationReference: locked.contractRequest.attestation.attestation_reference,
      evaluatedAt: new Date(locked.contractRequest.attestation.evaluated_at),
      observedAt: now,
      traceId: input.traceId,
    });

    // C16-R3(b): THE COUNT IS THE CONCURRENCY SIGNAL, AND IT WAS BEING THROWN
    // AWAY.
    //
    // This is a FENCED update — `state = 'POSSESSION_PROVEN'` is in the WHERE
    // clause — so a count of zero means the request left POSSESSION_PROVEN
    // between the `FOR UPDATE` read at the top of this transaction and here.
    // Discarding that left the device, its key, its scope, its trust transition
    // and its DEVICE_ENROLLED audit committed against a ceremony whose state
    // machine says the enrollment never completed. There is no ordinary refusal
    // available at this point (see the return type), so it THROWS and Postgres
    // unwinds everything this transaction wrote.
    const enrolled = await this.repository.advanceEnrollmentState(tx, input.organisationId, locked.request.id, 'POSSESSION_PROVEN', 'ENROLLED');
    if (enrolled !== 1) throw new ShieldTransactionRollback('ENROLLMENT_STATE_INVALID');

    const envelope = {
      organisationId: input.organisationId,
      deviceId,
      actorUserId: locked.contractApproval.approved_by_user_id,
      occurredAt: now,
      traceId: input.traceId,
    };
    await this.audit.record(tx, envelope, {
      type: 'BOOTSTRAP_CONSUMED',
      grantId: locked.grant.id,
      siteId: locked.grant.siteId,
      intendedUserId: locked.grant.intendedUserId,
      enrollmentRequestId: locked.request.id,
      enrollmentRequestFingerprint: locked.fingerprint,
    });
    await this.audit.record(tx, envelope, {
      type: 'DEVICE_ENROLLED',
      deviceId,
      enrollmentRequestId: locked.request.id,
      requestFingerprint: locked.fingerprint,
      siteId: locked.contractRequest.site_id,
      custody: locked.contractRequest.custody,
      sequenceNamespaceId,
      keyId,
      keyVersion,
      publicKeyThumbprint: locked.request.publicKeyThumbprint,
      keyStorage: locked.request.keyStorage,
      signatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
      initialTrust: trust,
    });
    await this.audit.record(tx, envelope, {
      type: 'TRUST_CHANGED',
      previousTrust: DEVICE_TRUST_PREVIOUS_NONE,
      newTrust: trust,
      reason: TRUST_REASON_ENROLLMENT_INITIAL,
      authorisedByUserId: locked.contractApproval.approved_by_user_id,
    });

    return { outcome: 'COMMITTED', deviceId, sequenceNamespaceId, keyId, keyVersion, trust };
  }

  /**
   * D24-06: re-reads and LOCKS every authority-bearing row, then rebuilds the
   * frozen contract structures from what the database actually holds.
   *
   * A returned string is a refusal. Locks are taken in one fixed order —
   * request, grant, approval, challenge, verification — so two concurrent
   * commits cannot deadlock by taking them in opposite directions.
   */
  private async lockCommitState(
    tx: Tx,
    organisationId: string,
    enrollmentRequestId: string,
    challengeId: string,
  ): Promise<LockedCommitState | 'ENROLLMENT_REQUEST_NOT_FOUND' | 'BOOTSTRAP_GRANT_NOT_FOUND' | 'APPROVAL_MISSING' | 'POSSESSION_CHALLENGE_NOT_FOUND' | 'POSSESSION_CHALLENGE_MISBOUND' | 'POSSESSION_VERIFICATION_NOT_FOUND' | 'MALFORMED_CONTRACT_STRUCTURE'> {
    const request = await this.repository.lockEnrollmentRequest(tx, organisationId, enrollmentRequestId);
    if (request === null) return 'ENROLLMENT_REQUEST_NOT_FOUND';

    const grant = await this.repository.lockBootstrapGrant(tx, organisationId, request.bootstrapGrantId);
    if (grant === null) return 'BOOTSTRAP_GRANT_NOT_FOUND';

    const approval = await this.repository.lockEnrollmentApproval(tx, organisationId, request.id);
    if (approval === null) return 'APPROVAL_MISSING';

    const challenge = await this.repository.lockPossessionChallenge(tx, organisationId, challengeId);
    if (challenge === null) return 'POSSESSION_CHALLENGE_NOT_FOUND';
    if (challenge.enrollmentRequestId !== request.id) return 'POSSESSION_CHALLENGE_MISBOUND';

    const verification = await this.repository.lockPossessionVerification(tx, organisationId, challenge.id);
    if (verification === null) return 'POSSESSION_VERIFICATION_NOT_FOUND';

    const contractRequest = this.toContractRequest(request);
    if (contractRequest === null) return 'MALFORMED_CONTRACT_STRUCTURE';

    const contractGrant = DeviceEnrollmentBootstrapGrantSchema.safeParse({
      schema_version: 1,
      grant_id: grant.id,
      organisation_id: grant.organisationId,
      site_id: grant.siteId,
      intended_user_id: grant.intendedUserId,
      issued_by_user_id: grant.issuedByUserId,
      issued_at: grant.issuedAt.toISOString(),
      expires_at: grant.expiresAt.toISOString(),
      single_use: true,
      consumed_at: grant.consumedAt === null ? null : grant.consumedAt.toISOString(),
      revoked_at: grant.revokedAt === null ? null : grant.revokedAt.toISOString(),
    });
    if (!contractGrant.success) return 'MALFORMED_CONTRACT_STRUCTURE';

    const contractApproval = DeviceEnrollmentApprovalSchema.safeParse({
      schema_version: 1,
      approval_id: approval.id,
      enrollment_request_id: approval.enrollmentRequestId,
      enrollment_request_fingerprint: approval.approvedRequestFingerprint,
      organisation_id: approval.organisationId,
      site_id: approval.approvedSiteId,
      custody: approval.approvedCustody,
      approved_by_user_id: approval.approvedByUserId,
      approved_at: approval.approvedAt.toISOString(),
    });
    if (!contractApproval.success) return 'MALFORMED_CONTRACT_STRUCTURE';

    const contractChallenge = DevicePossessionChallengeSchema.safeParse({
      schema_version: 1,
      challenge_id: challenge.id,
      enrollment_request_id: challenge.enrollmentRequestId,
      nonce: challenge.nonce,
      issued_at: challenge.issuedAt.toISOString(),
      expires_at: challenge.expiresAt.toISOString(),
    });
    if (!contractChallenge.success) return 'MALFORMED_CONTRACT_STRUCTURE';

    const contractVerification = DevicePossessionVerificationResultSchema.safeParse({
      schema_version: 1,
      source: 'SENTINEL_SERVER_VERIFICATION',
      verified: verification.verified,
      challenge_id: verification.challengeId,
      enrollment_request_id: verification.enrollmentRequestId,
      enrollment_request_fingerprint: verification.enrollmentRequestFingerprint,
      public_key_thumbprint: verification.publicKeyThumbprint,
      possession_statement_fingerprint: verification.possessionStatementFingerprint,
      signature_profile: verification.signatureProfile,
      verified_at: verification.verifiedAt.toISOString(),
    });
    if (!contractVerification.success) return 'MALFORMED_CONTRACT_STRUCTURE';

    return {
      request,
      approval,
      grant,
      contractRequest,
      contractGrant: contractGrant.data,
      contractApproval: contractApproval.data,
      contractChallenge: contractChallenge.data,
      contractVerification: contractVerification.data,
      approverUserId: approval.approvedByUserId,
      fingerprint: deviceEnrollmentRequestFingerprint(contractRequest),
    };
  }

  /**
   * Rebuilds the frozen `DeviceEnrollmentRequest` from a stored row.
   *
   * Every consumer recomputes the fingerprint FROM THIS, never reads the
   * stored `request_fingerprint` column as authority. The column exists to be
   * compared against a recomputation, which is the only way a rewritten row is
   * detectable — an id names a row, a fingerprint names its contents.
   */
  private toContractRequest(row: EnrollmentRequestRow): DeviceEnrollmentRequest | null {
    const parsed = DeviceEnrollmentRequestSchema.safeParse({
      schema_version: 1,
      enrollment_request_id: row.id,
      organisation_id: row.organisationId,
      site_id: row.siteId,
      intended_user_id: row.intendedUserId,
      bootstrap_grant_id: row.bootstrapGrantId,
      custody: row.custody,
      claimed_signature_profile: row.claimedSignatureProfile,
      key_storage: row.keyStorage,
      public_key: row.publicKey,
      public_key_thumbprint: row.publicKeyThumbprint,
      attestation: {
        outcome: row.attestationOutcome,
        evaluated_at: row.attestationEvaluatedAt.toISOString(),
        attestation_reference: row.attestationReference,
      },
      requested_at: row.requestedAt.toISOString(),
    });
    return parsed.success ? parsed.data : null;
  }

  // -------------------------------------------------------------------------
  // C16-01 / C16-02 internals
  // -------------------------------------------------------------------------

  /**
   * C16-01: the two custody rules and the catalogue lookup, in one place.
   *
   * `null` means the submission's régime is acceptable. Anything else is the
   * refusal to return verbatim.
   *
   * THE TWO RULES ARE THE CONTRACT'S, NOT THIS METHOD'S SHAPE.
   * `DeviceCustodyAssociationSchema` (C15-08) already refuses a PERSONAL device
   * carrying a régime and a CONTROLLED_SHARED device carrying an assignee. What
   * a schema cannot do is refuse a CONTROLLED_SHARED enrollment that names NO
   * régime — the field is nullable there because a PERSONAL association
   * legitimately leaves it empty — so the requirement is enforced here, at the
   * point where custody is actually chosen, and proved by test.
   *
   * ISOLATION: absent, foreign-tenant and right-tenant-wrong-site all answer
   * `CUSTODY_REGIME_NOT_FOUND`. Retirement is reported distinctly, and that is
   * not an oracle: to reach this line at all the presenter has already proved,
   * by holding a USABLE bootstrap grant, that they are operating inside this
   * exact organisation and site.
   */
  private async resolveSubmittedCustodyRegime(submission: EnrollmentRequestSubmission): Promise<ShieldRefusalCode | null> {
    if (submission.custody === 'CONTROLLED_SHARED') {
      if (submission.custodyRegimeId === null) return 'CUSTODY_REGIME_REQUIRED';
    } else if (submission.custodyRegimeId !== null) {
      return 'CUSTODY_REGIME_NOT_PERMITTED';
    }
    if (submission.custodyRegimeId === null) return null;

    const regime = await this.repository.findCustodyRegime(submission.organisationId, submission.custodyRegimeId);
    if (regime === null) return 'CUSTODY_REGIME_NOT_FOUND';
    // A régime in the right tenant but the WRONG SITE is not a régime this
    // ceremony may name: custody is a site fact, and widening it silently is
    // exactly the sort of scope creep the composite keys elsewhere prevent.
    if (regime.siteId !== submission.siteId) return 'CUSTODY_REGIME_NOT_FOUND';
    if (regime.retiredAt !== null) return 'CUSTODY_REGIME_RETIRED';
    return null;
  }

  /**
   * C16-02: is this the SAME submission arriving a second time under the same
   * grant, or a different one?
   *
   * Every value a caller controls is compared. The server-derived values —
   * fingerprint, thumbprint, attestation, timestamps — are deliberately NOT,
   * because they cannot repeat: `requested_at` and the attestation instant move
   * every call, so comparing them would make every retry a conflict and the
   * convergence arm unreachable.
   */
  private submissionMatchesRequest(submission: EnrollmentRequestSubmission, row: EnrollmentRequestRow): boolean {
    return (
      row.organisationId === submission.organisationId &&
      row.siteId === submission.siteId &&
      row.intendedUserId === submission.intendedUserId &&
      row.custody === submission.custody &&
      row.custodyRegimeId === submission.custodyRegimeId &&
      row.publicKey === submission.publicKey &&
      row.keyStorage === submission.keyStorage &&
      row.claimedSignatureProfile === submission.claimedSignatureProfile
    );
  }

  /**
   * C16-02 — ONE CEREMONY, ONE COMMITTED OUTCOME, RESOLVED BEFORE ANY BURN.
   *
   * Returns the outcome reference BOTH one-shot identities will be consumed
   * against, or a refusal.
   *
   * WHY THIS EXISTS
   * ---------------
   * The two identities are spent independently, so they can disagree: a
   * transaction that crashed between them, a partial retry, a service-bypassing
   * writer. The old code handed each a FRESHLY MINTED candidate device id and
   * let the classifier sort it out, which produced two failures at once —
   *
   *   * a refused ceremony still committed a FIRST_SEEN row naming a device
   *     that was never created, so the next exact retry "converged" on nothing;
   *   * a lagging identity's first-seen row named the RETRY's candidate rather
   *     than the outcome the first attempt actually produced.
   *
   * Resolving first fixes both. If either identity is an exact duplicate, its
   * stored reference is resolved BY AUTHORITATIVE DATABASE READ to a device
   * that exists AND whose `enrollment_request_id` is THIS request. Only then is
   * it used, for BOTH identities, so the lagging first-seen row is written
   * against the effect that genuinely exists.
   *
   * A reference that does not resolve fails closed. That is the whole point:
   * the alternative is manufacturing a convergence onto hardware the registry
   * cannot produce, which is worse than refusing an honest retry.
   */
  private async resolveCanonicalEnrollmentOutcome(
    tx: Tx,
    input: {
      organisationId: string;
      enrollmentRequestId: string;
      fingerprint: string;
      grantReplayKey: string;
      challengeReplayKey: string;
      candidateDeviceId: string;
    },
  ): Promise<
    | { readonly resolved: true; readonly outcomeRef: string }
    | { readonly resolved: false; readonly refusal: 'REPLAY_OUTCOME_UNRESOLVABLE' | 'REPLAY_OUTCOME_DIVERGED' }
  > {
    const peeked = await Promise.all([
      this.replay.peek(tx, { organisationId: input.organisationId, replayKey: input.grantReplayKey }),
      this.replay.peek(tx, { organisationId: input.organisationId, replayKey: input.challengeReplayKey }),
    ]);

    const references = new Set<string>();
    for (const fact of peeked) {
      if (fact === null) continue;
      // A stored fingerprint that differs is REUSED_WITH_CHANGED_SEMANTICS, and
      // that is the CONTRACT's verdict to reach, not this method's. It is left
      // alone here so the gate produces the refusal the vocabulary defines.
      if (fact.statementFingerprint !== input.fingerprint) continue;
      // C15-R1: a stored row naming no outcome is inconsistent, and again the
      // contract's `*_CONSUMPTION_INCONSISTENT` verdict is the honest answer.
      if (fact.storedOutcomeRef === null || fact.storedOutcomeRef.length === 0) continue;
      references.add(fact.storedOutcomeRef);
    }

    // Two duplicates telling two different stories about one ceremony.
    // Converging on either would be picking one at random.
    if (references.size > 1) return { resolved: false, refusal: 'REPLAY_OUTCOME_DIVERGED' };
    if (references.size === 0) return { resolved: true, outcomeRef: input.candidateDeviceId };

    const reference = [...references][0] as string;
    const device = await this.repository.resolveDeviceOutcomeRef(
      tx,
      input.organisationId,
      reference,
      input.enrollmentRequestId,
    );
    if (device === null) return { resolved: false, refusal: 'REPLAY_OUTCOME_UNRESOLVABLE' };
    return { resolved: true, outcomeRef: device.id };
  }

  /**
   * C16-02: the D24-12 record of a refusal whose transaction was ROLLED BACK.
   *
   * It runs in its own transaction, after the abort, because the rows the
   * refused transaction wrote are gone and the audit must not go with them. The
   * `REPLAY_CONFLICT` event is emitted for exactly the refusals that describe a
   * spent identity, as before.
   */
  private async recordRolledBackEnrollmentRefusal(
    input: { organisationId: string; enrollmentRequestId: string; traceId: string },
    refusal: ShieldRefusalCode,
    actorUserId: string,
    context: { fingerprint: string | null; replayIdentityDigest: string | null },
  ): Promise<void> {
    await this.repository.transaction(async (tx) => {
      const now = await this.repository.dbNow(tx);
      if (
        context.replayIdentityDigest !== null &&
        context.fingerprint !== null &&
        (refusal === 'BOOTSTRAP_GRANT_REUSED' ||
          refusal === 'CHALLENGE_REUSED' ||
          refusal === 'BOOTSTRAP_CONSUMPTION_INCONSISTENT' ||
          refusal === 'CHALLENGE_CONSUMPTION_INCONSISTENT')
      ) {
        await this.audit.record(
          tx,
          { organisationId: input.organisationId, deviceId: null, actorUserId, occurredAt: now, traceId: input.traceId },
          {
            type: 'REPLAY_CONFLICT',
            ceremony: CEREMONY_BOOTSTRAP_GRANT,
            replayIdentityDigest: context.replayIdentityDigest,
            presentedStatementFingerprint: context.fingerprint ?? '',
            outcome: refusal,
          },
        );
      }
      await this.recordEnrollmentRefusal(tx, input, context.fingerprint, refusal, now, actorUserId);
    });
  }

  private async recordEnrollmentRefusal(
    tx: Tx,
    input: { organisationId: string; enrollmentRequestId: string; traceId: string },
    fingerprint: string | null,
    refusal: string,
    now: Date,
    actorUserId: string,
  ): Promise<void> {
    await this.audit.record(
      tx,
      { organisationId: input.organisationId, deviceId: null, actorUserId, occurredAt: now, traceId: input.traceId },
      { type: 'ENROLLMENT_REFUSED', enrollmentRequestId: input.enrollmentRequestId, requestFingerprint: fingerprint, refusal },
    );
  }

  /**
   * D24-03a: >= 256 bits of cryptographic randomness, base64url in transit,
   * SHA-256 hex at rest.
   *
   * The two values exist together only inside this function's return value and
   * are separated immediately by the caller: the digest goes to the database,
   * the token goes back to the issuer, and nothing holds both again.
   */
  private mintBootstrapToken(): MintedBootstrapToken {
    const token = randomBytes(BOOTSTRAP_TOKEN_ENTROPY_BYTES).toString('base64url');
    return { token, digest: this.digestBootstrapToken(token) };
  }

  private digestBootstrapToken(token: string): string {
    return createHash(BOOTSTRAP_TOKEN_DIGEST_ALGORITHM).update(token, 'utf8').digest('hex');
  }
}
