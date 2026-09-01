import { Inject, Injectable } from '@nestjs/common';
import { randomBytes, randomUUID } from 'node:crypto';
import {
  DEVICE_KEY_ROTATION_CHALLENGE_MAX_AGE_MS,
  DeviceKeyRotationChallengeSchema,
  DeviceKeyRotationPossessionResponseSchema,
  DeviceKeyRotationPossessionVerificationResultSchema,
  DeviceKeyRotationRequestSchema,
  DeviceRequestProofSchema,
  canonicalDeviceKeyRotationPossessionStatement,
  canonicalDeviceRequestProofStatement,
  deriveP256PublicKeyThumbprint,
  deviceKeyRotationPossessionStatementFingerprint,
  deviceKeyRotationReplayKey,
  deviceKeyRotationRequestFingerprint,
  deviceRequestProofStatementInput,
  evaluateDeviceKeyRotation,
  type DeviceKeyLifecycleState,
  type DeviceKeyRotationChallenge,
  type DeviceKeyRotationPossessionVerificationResult,
  type DeviceKeyRotationRequest,
  type DeviceKeyStorage,
} from '@sentinel/contracts';
import type { Principal } from '../../common/security/principal';
import { DeviceReplayService } from './device-replay.service';
import { DeviceSecurityAudit } from './device-security-audit';
import { P256KeyImporter } from './p256-key.importer';
import { checkGlobalDeviceMutationAuthority } from './shield.authority';
import { ShieldTransactionRollback, isShieldTransactionRollback } from './shield.rollback';
import {
  ACTION_DEVICE_KEY_ROTATE,
  CEREMONY_KEY_ROTATION,
  CHALLENGE_NONCE_ENTROPY_BYTES,
  ROTATION_STATE_CHALLENGED,
  ROTATION_STATE_REQUESTED,
  ROTATION_STATE_ROTATED,
  SERVER_SELECTED_SIGNATURE_PROFILE,
} from './shield.constants';
import { ShieldRepository, type DeviceKeyRow, type DeviceRow, type Tx } from './shield.repository';
import type {
  CommitKeyRotationOutcome,
  IssueRotationChallengeOutcome,
  RequestKeyRotationOutcome,
  VerifyRotationPossessionOutcome,
} from './shield.types';

/**
 * WP-24/D24-10, D24-10A — KEY ROTATION PRESERVES IDENTITY; IT NEVER RESETS IT.
 *
 * ROTATION IS A TWO-KEY PROOF AND NEITHER HALF SUBSTITUTES FOR THE OTHER.
 *
 *     CURRENT REGISTERED KEY
 *       signs a DeviceRequestProof, purpose = DEVICE_KEY_ROTATION,
 *       whose payload_digest is the EXACT rotation-request fingerprint
 *         -> CONTINUITY of the old credential
 *
 *     the server imports the new public key and issues a rotation challenge
 *
 *     NEW KEY
 *       signs sentinel.device.key-rotation-possession.v1
 *         -> POSSESSION of the new credential
 *
 * Continuity without possession registers a key nobody can show they hold —
 * the upload C14-02 refuses. Possession without continuity lets anyone holding
 * a fresh keypair replace a device's credential. Binding the continuity
 * proof's `payload_digest` to the exact rotation-request fingerprint is what
 * stops an otherwise valid current-key proof being borrowed for a DIFFERENT
 * replacement key.
 *
 * WHAT THIS SERVICE DOES NOT DECIDE
 * --------------------------------
 * `evaluateDeviceKeyRotation` owns every admissibility rule: profile binding,
 * request/challenge/verdict binding, STALE_ROTATION against the re-read
 * registry, the runtime-validity requirement, replay classification,
 * continuity, possession, chronology and convergence. This service assembles
 * the facts, performs the two crypto checks the contract cannot, takes the
 * locks, and applies the effect the contract authorised.
 *
 * C16-03 — AN EXACT RETRY CONVERGES; IT DOES NOT REPORT A STALE WORLD
 * ---------------------------------------------------------------------
 * `evaluateDeviceKeyRotation` checks STALE_ROTATION at step 3 and consults the
 * replay fact only at step 5. Once a rotation has LANDED the registry has moved
 * by definition, so under that ordering every honest retry was answered
 * STALE_ROTATION. Safe — nothing rotated twice — but not TRUTHFUL: the caller is
 * told its request was invalidated by a concurrent change when in fact its own
 * earlier attempt succeeded.
 *
 * The contract is frozen and its ordering is not this work package's to change,
 * so the fix is in the RUNTIME and it is placed BEFORE the evaluator: the
 * durable replay outcome is resolved first. If the identity is an EXACT
 * duplicate, the stored reference is read back AUTHORITATIVELY and must resolve
 * to precisely the committed rotation it claims — the key row exists, is
 * CURRENT, sits at `proposed_key_version`, carries `proposed_key_id`, belongs to
 * this device and tenant, and the device's own pointer agrees. Only then does
 * this service answer CONVERGE, and it answers with the key the REGISTRY holds
 * rather than the one the request asked for. If the reference does not resolve
 * to exactly that, it FAILS CLOSED (`ROTATION_OUTCOME_UNRESOLVABLE`) — a
 * manufactured convergence is worse than an honest refusal.
 *
 * Only when the fact is NOT an exact duplicate is the evaluator called, where a
 * genuinely moved registry still yields STALE_ROTATION exactly as before.
 *
 * C16-04 — NO PARTIAL SECURITY-STATE COMMITS
 * ----------------------------------------
 * The effect below writes three things: the old key goes ROTATED, the new key
 * is created, the device pointer advances. The last two are fenced
 * compare-and-sets, and RETURNING a refusal from one of them committed
 * everything written before it — two live keys, a device pointing at neither,
 * and no rotation. Every fallible condition is now prevalidated, and a
 * post-write CAS failure `throw`s `ShieldTransactionRollback` so Postgres
 * aborts the whole transaction. The external refusal is produced afterwards.
 *
 * WHY THE FULL `evaluateDeviceRequestProof` IS NOT CALLED FOR CONTINUITY
 * ---------------------------------------------------------------------
 * That evaluator judges a proof against an authenticated DEVICE CONTEXT —
 * context lifetime, actor authority, purpose-permitted trust, the context's
 * own replay identity — and no such context exists in WP-24: establishing one
 * is WP-25's authenticated gateway, which D24-13 forbids here. What
 * `evaluateDeviceKeyRotation` actually asks for is narrower and exact: did a
 * proof with purpose `DEVICE_KEY_ROTATION`, signed by the registered current
 * key, verify over a statement whose `payload_digest` equals this rotation
 * request's fingerprint. `verifyContinuityProof` below answers precisely that
 * question and nothing wider, and the identity fields are checked against the
 * REGISTRY row rather than against anything the proof asserts about itself.
 */

/** Everything the rotation commit re-read under lock. */
interface LockedRotationState {
  readonly device: DeviceRow;
  readonly currentKey: DeviceKeyRow;
  readonly contractRequest: DeviceKeyRotationRequest;
  readonly contractChallenge: DeviceKeyRotationChallenge;
  readonly contractVerification: DeviceKeyRotationPossessionVerificationResult;
  readonly fingerprint: string;
  readonly newPublicKey: string;
  readonly newKeyStorage: string;
  readonly rotationRequestId: string;
  readonly rotationRequestState: string;
}

@Injectable()
export class DeviceKeyService {
  constructor(
    @Inject(ShieldRepository) private readonly repository: ShieldRepository,
    @Inject(DeviceReplayService) private readonly replay: DeviceReplayService,
    @Inject(DeviceSecurityAudit) private readonly audit: DeviceSecurityAudit,
    @Inject(P256KeyImporter) private readonly keys: P256KeyImporter,
  ) {}

  // -------------------------------------------------------------------------
  // Step 1 — the rotation request (D24-10A)
  // -------------------------------------------------------------------------

  /**
   * Opens a rotation. THE SERVER generates the proposed key identity and
   * version; the caller supplies only the new public key and its storage class.
   *
   * `proposed_key_version === current_key_version + 1` is enforced at PARSE by
   * the contract, not merely checked later — "greater than" would admit skipped
   * versions, and a client that can skip versions can shape registry history,
   * leaving gaps that make "which key signed this?" unanswerable for the
   * versions nothing occupies. There is no parameter here through which a
   * version or a key id could arrive.
   *
   * D24-05 runs before anything is written: an off-curve point parses at every
   * contract boundary and must be refused by the provider first.
   */
  async requestKeyRotation(
    principal: Principal,
    input: {
      organisationId: string;
      deviceId: string;
      newPublicKey: string;
      newKeyStorage: DeviceKeyStorage;
      traceId: string;
    },
  ): Promise<RequestKeyRotationOutcome> {
    const device = await this.repository.findDevice(input.organisationId, input.deviceId);
    if (device === null) return { outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' };

    const siteIds = await this.repository.listDeviceSiteIds(input.organisationId, device.id);
    if (this.authoriseAgainstDeviceSites(principal, input.organisationId, siteIds) !== null) {
      return { outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' };
    }

    const currentKey = await this.currentKey(device);
    if (currentKey === null) return { outcome: 'REFUSED', refusal: 'DEVICE_HAS_NO_CURRENT_KEY' };

    if (!this.keys.isRuntimeValidPublicKey(input.newPublicKey)) {
      return { outcome: 'REFUSED', refusal: 'PUBLIC_KEY_NOT_RUNTIME_VALID' };
    }

    const requestedAt = await this.repository.now();
    const rotationRequestId = randomUUID();
    const proposedKeyId = randomUUID();
    const draft = {
      schema_version: 1 as const,
      rotation_request_id: rotationRequestId,
      organisation_id: input.organisationId,
      device_id: device.id,
      current_key_id: currentKey.keyId,
      current_key_version: currentKey.keyVersion,
      proposed_key_id: proposedKeyId,
      proposed_key_version: currentKey.keyVersion + 1,
      new_public_key: input.newPublicKey,
      // C15-02: DERIVED from the key, never independently supplied.
      new_public_key_thumbprint: deriveP256PublicKeyThumbprint(input.newPublicKey),
      new_key_storage: input.newKeyStorage,
      // C15-01/C11-04: the SERVER's profile, not a client claim.
      server_resolved_signature_profile: SERVER_SELECTED_SIGNATURE_PROFILE,
      requested_at: requestedAt.toISOString(),
    };
    const parsed = DeviceKeyRotationRequestSchema.safeParse(draft);
    if (!parsed.success) return { outcome: 'REFUSED', refusal: 'MALFORMED_CONTRACT_STRUCTURE' };
    const fingerprint = deviceKeyRotationRequestFingerprint(parsed.data);

    await this.repository.createRotationRequest({
      id: rotationRequestId,
      organisationId: input.organisationId,
      deviceId: device.id,
      currentKeyId: currentKey.keyId,
      currentKeyVersion: currentKey.keyVersion,
      proposedKeyId,
      proposedKeyVersion: currentKey.keyVersion + 1,
      newPublicKey: input.newPublicKey,
      newPublicKeyThumbprint: parsed.data.new_public_key_thumbprint,
      newKeyStorage: input.newKeyStorage,
      serverResolvedSignatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
      requestFingerprint: fingerprint,
      requestedAt,
      state: ROTATION_STATE_REQUESTED,
    });

    return {
      outcome: 'REQUESTED',
      rotationRequestId,
      rotationRequestFingerprint: fingerprint,
      proposedKeyId,
      proposedKeyVersion: currentKey.keyVersion + 1,
    };
  }

  // -------------------------------------------------------------------------
  // Step 2 — the rotation challenge, bound to the WHOLE proposal
  // -------------------------------------------------------------------------

  /**
   * Issues a rotation challenge.
   *
   * `DEVICE_KEY_ROTATION_CHALLENGE_MAX_AGE_MS` is deliberately its OWN constant
   * with its own tests, numerically equal to the enrollment possession ceiling
   * today. Using the enrollment constant here — because the numbers happen to
   * match — is exactly the silent coupling D24-10A forbids.
   */
  async issueRotationChallenge(
    principal: Principal,
    input: { organisationId: string; rotationRequestId: string; traceId: string },
  ): Promise<IssueRotationChallengeOutcome> {
    const request = await this.repository.findRotationRequest(input.organisationId, input.rotationRequestId);
    if (request === null) return { outcome: 'REFUSED', refusal: 'ROTATION_REQUEST_NOT_FOUND' };

    const siteIds = await this.repository.listDeviceSiteIds(input.organisationId, request.deviceId);
    if (this.authoriseAgainstDeviceSites(principal, input.organisationId, siteIds) !== null) {
      return { outcome: 'REFUSED', refusal: 'ROTATION_REQUEST_NOT_FOUND' };
    }
    if (request.state !== ROTATION_STATE_REQUESTED && request.state !== ROTATION_STATE_CHALLENGED) {
      return { outcome: 'REFUSED', refusal: 'ROTATION_STATE_INVALID' };
    }

    const nonce = randomBytes(CHALLENGE_NONCE_ENTROPY_BYTES).toString('base64url');

    // ONE transaction: the challenge and the state it advances the request to
    // are one fact about how far the ceremony has got.
    try {
      return await this.repository.transaction(async (tx) => {
      const issuedAt = await this.repository.dbNow(tx);
      const expiresAt = new Date(issuedAt.getTime() + DEVICE_KEY_ROTATION_CHALLENGE_MAX_AGE_MS);
      const challenge = await this.repository.createRotationChallenge(tx, {
        organisationId: input.organisationId,
        deviceId: request.deviceId,
        rotationRequestId: request.id,
        // The fingerprint travels beside the id for the reason it does in the
        // enrollment ceremony: an id names a row, a fingerprint names its
        // CONTENTS, and only the second detects a row that was rewritten.
        rotationRequestFingerprint: request.requestFingerprint,
        currentKeyId: request.currentKeyId,
        currentKeyVersion: request.currentKeyVersion,
        proposedKeyId: request.proposedKeyId,
        proposedKeyVersion: request.proposedKeyVersion,
        newPublicKeyThumbprint: request.newPublicKeyThumbprint,
        nonce,
        issuedAt,
        expiresAt,
      });
      // C16-R3(b): fenced on the state read before the transaction opened, and
      // performed AFTER the challenge row was written. A discarded zero left a
      // live challenge attached to a request whose state never advanced — the
      // ceremony would then present a challenge the state machine does not
      // believe was issued.
      const advanced = await this.repository.setRotationRequestState(tx, input.organisationId, request.id, request.state, ROTATION_STATE_CHALLENGED);
      if (advanced !== 1) throw new ShieldTransactionRollback('ROTATION_STATE_INVALID', { audited: false });
      return { outcome: 'ISSUED', challengeId: challenge.id, nonce, expiresAt };
      });
    } catch (error) {
      if (!isShieldTransactionRollback(error)) throw error;
      return { outcome: 'REFUSED', refusal: error.refusal };
    }
  }

  // -------------------------------------------------------------------------
  // Step 3 — the NEW key proves possession
  // -------------------------------------------------------------------------

  /**
   * Verifies the new key's possession signature and records a BOUND verdict.
   *
   * D24-10A: there is no `newKeyPossessionVerified: true` anywhere in this
   * runtime. The row carries organisation, device, request id and fingerprint,
   * challenge id, both key identities, the new thumbprint, the profile, the
   * canonical statement fingerprint and the server's own instant — so a verdict
   * from another rotation, challenge, device, proposed key or request
   * fingerprint is structurally unusable rather than merely unlikely to be
   * misapplied.
   *
   * IMPORT PRECEDES POSSESSION. The key verified against is the request row's
   * `new_public_key`, and `verifySignature` imports it through the D24-05
   * boundary before touching a signature — so an off-curve key cannot acquire a
   * valid rotation verification result at all.
   */
  async verifyRotationPossession(input: {
    organisationId: string;
    rotationRequestId: string;
    challengeId: string;
    response: unknown;
    traceId: string;
  }): Promise<VerifyRotationPossessionOutcome> {
    const parsedResponse = DeviceKeyRotationPossessionResponseSchema.safeParse(input.response);
    if (!parsedResponse.success) return { outcome: 'REFUSED', refusal: 'MALFORMED_CONTRACT_STRUCTURE' };
    const response = parsedResponse.data;

    const request = await this.repository.findRotationRequest(input.organisationId, input.rotationRequestId);
    if (request === null) return { outcome: 'REFUSED', refusal: 'ROTATION_REQUEST_NOT_FOUND' };
    const challenge = await this.repository.findRotationChallenge(input.organisationId, input.challengeId);
    if (challenge === null) return { outcome: 'REFUSED', refusal: 'ROTATION_CHALLENGE_NOT_FOUND' };
    if (challenge.rotationRequestId !== request.id) return { outcome: 'REFUSED', refusal: 'CHALLENGE_MISBOUND' };
    if (response.challenge_id !== challenge.id || response.rotation_request_id !== request.id) {
      return { outcome: 'REFUSED', refusal: 'CHALLENGE_MISBOUND' };
    }

    const statementInput = {
      organisation_id: request.organisationId,
      device_id: request.deviceId,
      rotation_request_id: request.id,
      rotation_request_fingerprint: request.requestFingerprint,
      current_key_id: request.currentKeyId,
      current_key_version: request.currentKeyVersion,
      proposed_key_id: request.proposedKeyId,
      proposed_key_version: request.proposedKeyVersion,
      new_public_key_thumbprint: request.newPublicKeyThumbprint,
      rotation_challenge_id: challenge.id,
      nonce: challenge.nonce,
      // The SERVER-resolved profile is what the statement binds. The new public
      // key itself is not repeated inside the signed bytes — the request
      // fingerprint already commits to it — but the thumbprint stays explicit.
      signature_profile: SERVER_SELECTED_SIGNATURE_PROFILE,
    };
    const statement = canonicalDeviceKeyRotationPossessionStatement(statementInput);
    const statementFingerprint = deviceKeyRotationPossessionStatementFingerprint(statementInput);

    const verified = this.keys.verifySignature({
      registeredPublicKey: request.newPublicKey,
      message: statement,
      signature: response.signature,
      serverResolvedProfile: request.serverResolvedSignatureProfile,
      claimedProfile: response.claimed_signature_profile,
    });

    return this.repository.transaction(async (tx) => {
      const verifiedAt = await this.repository.dbNow(tx);
      const row = await this.repository.createRotationVerification(tx, {
        organisationId: input.organisationId,
        deviceId: request.deviceId,
        rotationRequestId: request.id,
        rotationRequestFingerprint: request.requestFingerprint,
        rotationChallengeId: challenge.id,
        currentKeyId: request.currentKeyId,
        currentKeyVersion: request.currentKeyVersion,
        proposedKeyId: request.proposedKeyId,
        proposedKeyVersion: request.proposedKeyVersion,
        newPublicKeyThumbprint: request.newPublicKeyThumbprint,
        signatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
        canonicalStatementFingerprint: statementFingerprint,
        verified,
        verifiedAt,
      });
      return {
        outcome: verified ? ('VERIFIED' as const) : ('NOT_VERIFIED' as const),
        verificationId: row.id,
        canonicalStatementFingerprint: statementFingerprint,
      };
    });
  }

  // -------------------------------------------------------------------------
  // Step 4 — the commit transaction refuses a moved world
  // -------------------------------------------------------------------------

  /**
   * Commits the rotation, atomically.
   *
   * The registry is RE-READ UNDER LOCK and handed to
   * `evaluateDeviceKeyRotation` as `registered`, which is the STALE_ROTATION
   * defence: a rotation proposes to supersede one specific key, and if that key
   * is no longer the current one, is no longer CURRENT, or the credential has
   * been withdrawn at EITHER level, the proposal describes a world that has
   * gone. Rotating anyway would silently retarget the ceremony at whatever is
   * current now, which is precisely how a race becomes an authorisation.
   *
   * Then, atomically: old key `CURRENT -> ROTATED` with `rotated_at` at
   * authoritative server time, the new key `CURRENT`, and the device keeping
   * its `id` and `sequence_namespace_id` while its current key reference and
   * version advance. There is no write in this method that touches
   * `sequenceNamespaceId` at all — D23-09's "there is no sequence reset" is
   * upheld by there being no code that could perform one.
   */
  async commitKeyRotation(
    principal: Principal,
    input: {
      organisationId: string;
      rotationRequestId: string;
      challengeId: string;
      /** The CURRENT key's `DeviceRequestProof`, purpose DEVICE_KEY_ROTATION. */
      continuityProof: unknown;
      traceId: string;
    },
  ): Promise<CommitKeyRotationOutcome> {
    // The new key row's id, minted before the replay consumption so it can be
    // the outcome reference a FIRST attempt stores. A retry never uses it: the
    // resolution below reads back what actually committed.
    const candidateKeyRowId = randomUUID();

    // C16-04: what a ROLLED-BACK transaction still needs to record. Captured in
    // this closure so it survives the abort that takes the transaction's own
    // audit rows with it.
    const replayConflict: { value: { digest: string; refusal: string; deviceId: string; fingerprint: string } | null } = {
      value: null,
    };

    try {
      return await this.repository.transaction(async (tx) => {
      const now = await this.repository.dbNow(tx);
      const locked = await this.lockRotationState(tx, input.organisationId, input.rotationRequestId, input.challengeId);
      if (typeof locked === 'string') return { outcome: 'REFUSED', refusal: locked };

      const siteIds = await this.repository.listDeviceSiteIds(input.organisationId, locked.device.id);
      // C16-06: rotation replaces the ONE credential every site this device
      // serves depends on, so it needs authority over the whole device — not
      // over one of the sites it happens to touch.
      if (checkGlobalDeviceMutationAuthority(principal, ACTION_DEVICE_KEY_ROTATE, input.organisationId, siteIds) !== null) {
        return { outcome: 'REFUSED', refusal: 'ROTATION_REQUEST_NOT_FOUND' };
      }

      // D24-10A: the CURRENT key authorised THIS EXACT proposal. Verified
      // against the REGISTRY's key row, never against anything the proof says
      // about which key signed it.
      const continuity = this.verifyContinuityProof(input.continuityProof, locked);

      // D24-05: the new key must have been imported by the runtime provider.
      const newKeyRuntimeValid = this.keys.isRuntimeValidPublicKey(locked.newPublicKey);

      const replayKey = deviceKeyRotationReplayKey({
        organisation_id: locked.contractRequest.organisation_id,
        device_id: locked.contractRequest.device_id,
        rotation_request_id: locked.contractRequest.rotation_request_id,
        rotation_challenge_id: locked.contractChallenge.challenge_id,
        current_key_id: locked.contractRequest.current_key_id,
        current_key_version: locked.contractRequest.current_key_version,
        proposed_key_id: locked.contractRequest.proposed_key_id,
        proposed_key_version: locked.contractRequest.proposed_key_version,
        nonce: locked.contractChallenge.nonce,
      });

      // C16-03: THE DURABLE REPLAY OUTCOME IS RESOLVED BEFORE THE EVALUATOR.
      //
      // A pure read, taken before anything is written. If this identity has
      // already been spent on the SAME statement, the rotation it produced is
      // read back from the registry and this ceremony converges on it — with
      // the real committed key, not the one the request proposed. If the stored
      // reference does not resolve to exactly that committed rotation, the
      // answer is a refusal: convergence is never manufactured.
      const peeked = await this.replay.peek(tx, { organisationId: input.organisationId, replayKey });
      if (peeked !== null && peeked.statementFingerprint === locked.fingerprint && peeked.storedOutcomeRef !== null) {
        const committed = await this.resolveCommittedRotation(tx, locked, peeked.storedOutcomeRef);
        if (committed === null) return { outcome: 'REFUSED', refusal: 'ROTATION_OUTCOME_UNRESOLVABLE' };
        return {
          outcome: 'CONVERGED',
          deviceId: locked.device.id,
          storedOutcomeRef: peeked.storedOutcomeRef,
          // C16-R4: read back from the REGISTRY, and reporting WHAT THIS
          // ROTATION COMMITTED — not what is current now. A later rotation may
          // already have superseded this key; this answer says the retried
          // ceremony landed, and grants nothing.
          toKeyId: committed.keyId,
          toKeyVersion: committed.keyVersion,
          committedKeyLifecycleState: committed.status as DeviceKeyLifecycleState,
        };
      }

      // ---- FIRST CONSUMPTION WRITE. Every refusal past this line THROWS. ---
      const consumption = await this.replay.consume(tx, {
        organisationId: input.organisationId,
        ceremony: CEREMONY_KEY_ROTATION,
        replayKey,
        statementFingerprint: locked.fingerprint,
        candidateOutcomeRef: candidateKeyRowId,
        traceId: input.traceId,
      });

      // THE GATE.
      const decision = evaluateDeviceKeyRotation({
        request: locked.contractRequest,
        challenge: locked.contractChallenge,
        possessionVerification: locked.contractVerification,
        continuity,
        newKeyRuntimeValid,
        registered: {
          organisation_id: locked.device.organisationId,
          device_id: locked.device.id,
          current_key_id: locked.currentKey.keyId,
          current_key_version: locked.currentKey.keyVersion,
          current_key_status: locked.currentKey.status as DeviceKeyLifecycleState,
          // D24-09/C15-R4-final: the two revocations are asked SEPARATELY,
          // from two different rows, and the contract ORs them itself.
          current_key_revoked: locked.currentKey.revokedAt !== null,
          device_revoked: locked.device.revokedAt !== null || locked.device.trust === 'COMPROMISED',
          server_resolved_signature_profile: SERVER_SELECTED_SIGNATURE_PROFILE,
        },
        consumption: consumption.consumption,
        now: now.toISOString(),
      });

      if (decision.decision === 'REFUSE') {
        if (
          decision.refusal === 'ROTATION_REUSED_WITH_CHANGED_SEMANTICS' ||
          decision.refusal === 'ROTATION_CONSUMPTION_INCONSISTENT' ||
          decision.refusal === 'ROTATION_CONSUMPTION_MISBOUND'
        ) {
          replayConflict.value = {
            digest: consumption.replayIdentityDigest,
            refusal: decision.refusal,
            deviceId: locked.device.id,
            fingerprint: locked.fingerprint,
          };
        }
        // C16-02/C16-04: THROWN, never returned. The consumption row this
        // transaction just wrote must not outlive the rotation it claimed, and
        // a normal return would commit it.
        throw new ShieldTransactionRollback(decision.refusal);
      }

      if (decision.decision === 'CONVERGE') {
        // C16-03: UNREACHABLE BY CONSTRUCTION, AND FAIL-CLOSED ANYWAY.
        //
        // The contract returns CONVERGE only when the consumption fact is an
        // EXACT duplicate, and every exact duplicate was already resolved and
        // answered above, before this identity was consumed. Reaching here
        // therefore means the store classified a row this transaction only just
        // inserted as a duplicate — an integrity fault, not a retry. Refusing
        // is the only honest answer: the alternative is converging on a
        // reference nothing has verified against the registry, which is exactly
        // the manufactured convergence C16-03 exists to remove.
        throw new ShieldTransactionRollback('ROTATION_OUTCOME_UNRESOLVABLE');
      }

      // ---- the effect, in one transaction --------------------------------
      // C16-04: THREE WRITES, ONE FATE. Two of them are fenced
      // compare-and-sets, and a CAS that reports zero rows means the world
      // moved between the lock and here. RETURNING a refusal at either of them
      // used to commit whatever had already been written — an old key marked
      // ROTATED with no successor, or two live keys and a device pointing at
      // neither. Both now THROW, so Postgres unwinds the lot.
      //
      // Old key first, fenced on `status = 'CURRENT'`, so a key that moved
      // between the lock and here cannot be walked backwards into a rotation.
      const superseded = await this.repository.markDeviceKeyRotated(tx, input.organisationId, locked.currentKey.keyId, now);
      if (superseded !== 1) throw new ShieldTransactionRollback('STALE_ROTATION');

      await this.repository.createDeviceKey(tx, {
        id: candidateKeyRowId,
        organisationId: input.organisationId,
        deviceId: locked.device.id,
        keyId: locked.contractRequest.proposed_key_id,
        keyVersion: locked.contractRequest.proposed_key_version,
        publicKey: locked.newPublicKey,
        publicKeyThumbprint: locked.contractRequest.new_public_key_thumbprint,
        signatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
        keyStorage: locked.newKeyStorage,
        status: 'CURRENT',
        registeredAt: now,
      });

      // The device keeps its id and its sequence namespace. Only the pointer
      // moves, and it is fenced on the pair it was rotating away from.
      const advanced = await this.repository.advanceDeviceCurrentKey(
        tx,
        input.organisationId,
        locked.device.id,
        { keyId: locked.currentKey.keyId, keyVersion: locked.currentKey.keyVersion },
        { keyId: locked.contractRequest.proposed_key_id, keyVersion: locked.contractRequest.proposed_key_version },
      );
      if (advanced !== 1) throw new ShieldTransactionRollback('STALE_ROTATION');

      // C16-R3(b): the third fenced CAS, and its count was being discarded too.
      // Fenced on the state the lock read observed, so zero rows means the
      // rotation request left that state between the `FOR UPDATE` and here. The
      // key writes above are already committed-in-transaction at this point, so
      // returning would have left a device rotated under a request whose state
      // machine never recorded the rotation. It throws, and the lot unwinds.
      const stateAdvanced = await this.repository.setRotationRequestState(
        tx,
        input.organisationId,
        locked.rotationRequestId,
        locked.rotationRequestState,
        ROTATION_STATE_ROTATED,
      );
      if (stateAdvanced !== 1) throw new ShieldTransactionRollback('ROTATION_STATE_INVALID');

      await this.audit.record(
        tx,
        { organisationId: input.organisationId, deviceId: locked.device.id, actorUserId: principal.user.id, occurredAt: now, traceId: input.traceId },
        {
          type: 'KEY_ROTATED',
          rotationRequestId: locked.rotationRequestId,
          rotationRequestFingerprint: locked.fingerprint,
          fromKeyId: locked.currentKey.keyId,
          fromKeyVersion: locked.currentKey.keyVersion,
          toKeyId: locked.contractRequest.proposed_key_id,
          toKeyVersion: locked.contractRequest.proposed_key_version,
          newPublicKeyThumbprint: locked.contractRequest.new_public_key_thumbprint,
          newKeyStorage: locked.newKeyStorage,
          signatureProfile: SERVER_SELECTED_SIGNATURE_PROFILE,
        },
      );

      return {
        outcome: 'ROTATED',
        deviceId: locked.device.id,
        sequenceNamespaceId: locked.device.sequenceNamespaceId,
        fromKeyId: locked.currentKey.keyId,
        fromKeyVersion: locked.currentKey.keyVersion,
        toKeyId: locked.contractRequest.proposed_key_id,
        toKeyVersion: locked.contractRequest.proposed_key_version,
      };
      });
    } catch (error) {
      if (!isShieldTransactionRollback(error)) throw error;
      // C16-02/C16-04: the transaction is gone; the D24-12 trail is not. The
      // replay-conflict event is written afterwards, in its own transaction, so
      // an operator can still see that a spent identity was presented again.
      if (replayConflict.value !== null) {
        const conflict = replayConflict.value;
        await this.repository.transaction(async (tx) => {
          const at = await this.repository.dbNow(tx);
          await this.audit.record(
            tx,
            { organisationId: input.organisationId, deviceId: conflict.deviceId, actorUserId: principal.user.id, occurredAt: at, traceId: input.traceId },
            {
              type: 'REPLAY_CONFLICT',
              ceremony: CEREMONY_KEY_ROTATION,
              replayIdentityDigest: conflict.digest,
              presentedStatementFingerprint: conflict.fingerprint,
              outcome: conflict.refusal,
            },
          );
        });
      }
      return { outcome: 'REFUSED', refusal: error.refusal };
    }
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  /**
   * The continuity half of the two-key proof, reduced to exactly the two
   * values `evaluateDeviceKeyRotation` asks for.
   *
   * `purpose_payload_digest` travels separately from `verified` so the binding
   * is checked by the CONTRACT rather than assumed by this caller: even a
   * `verified: true` here is useless to the gate unless the digest equals the
   * rotation-request fingerprint the gate computed for itself.
   *
   * Every identity field is checked against the REGISTRY row — the current key
   * id and version the registry holds, and the device the registry holds them
   * for. A proof asserting a different key id would otherwise be verified with
   * whatever key the proof named, which is the algorithm/key-selection hole
   * C11-04 closed, re-opened from the other side.
   */
  private verifyContinuityProof(
    raw: unknown,
    locked: LockedRotationState,
  ): { readonly verified: boolean; readonly purpose_payload_digest: string } | null {
    const parsed = DeviceRequestProofSchema.safeParse(raw);
    if (!parsed.success) return null;
    const proof = parsed.data;

    if (proof.purpose !== 'DEVICE_KEY_ROTATION') return null;
    if (
      proof.organisation_id !== locked.device.organisationId ||
      proof.device_id !== locked.device.id ||
      proof.key_id !== locked.currentKey.keyId ||
      proof.key_version !== locked.currentKey.keyVersion
    ) {
      return null;
    }

    // C15-01: the statement the device signed binds the SERVER's profile, and
    // `deviceRequestProofStatementInput` performs that substitution for us —
    // the client's `claimed_signature_profile` never reaches the signed bytes.
    const statement = canonicalDeviceRequestProofStatement(
      deviceRequestProofStatementInput(proof, SERVER_SELECTED_SIGNATURE_PROFILE),
    );
    const verified = this.keys.verifySignature({
      // The key is the REGISTRY's current key, resolved by the lock read.
      registeredPublicKey: locked.currentKey.publicKey,
      message: statement,
      signature: proof.signature,
      serverResolvedProfile: locked.currentKey.signatureProfile,
      claimedProfile: proof.claimed_signature_profile,
    });

    return { verified, purpose_payload_digest: proof.payload_digest };
  }

  private async lockRotationState(
    tx: Tx,
    organisationId: string,
    rotationRequestId: string,
    challengeId: string,
  ): Promise<
    | LockedRotationState
    | 'ROTATION_REQUEST_NOT_FOUND'
    | 'ROTATION_CHALLENGE_NOT_FOUND'
    | 'CHALLENGE_MISBOUND'
    | 'DEVICE_NOT_FOUND'
    | 'DEVICE_HAS_NO_CURRENT_KEY'
    | 'POSSESSION_VERIFICATION_MISSING'
    | 'MALFORMED_CONTRACT_STRUCTURE'
  > {
    const request = await this.repository.lockRotationRequest(tx, organisationId, rotationRequestId);
    if (request === null) return 'ROTATION_REQUEST_NOT_FOUND';

    const challenge = await this.repository.lockRotationChallenge(tx, organisationId, challengeId);
    if (challenge === null) return 'ROTATION_CHALLENGE_NOT_FOUND';
    if (challenge.rotationRequestId !== request.id) return 'CHALLENGE_MISBOUND';

    const device = await this.repository.lockDevice(tx, organisationId, request.deviceId);
    if (device === null) return 'DEVICE_NOT_FOUND';
    if (device.currentKeyId === null) return 'DEVICE_HAS_NO_CURRENT_KEY';

    // The registry's CURRENT key as it stands NOW — not the key the request
    // named. Handing the contract the request's own claim would defeat
    // STALE_ROTATION entirely.
    const currentKey = await this.repository.lockDeviceKeyByKeyId(tx, organisationId, device.currentKeyId);
    if (currentKey === null) return 'DEVICE_HAS_NO_CURRENT_KEY';

    const verification = await this.repository.lockRotationVerification(tx, organisationId, challenge.id);
    if (verification === null) return 'POSSESSION_VERIFICATION_MISSING';

    const contractRequest = DeviceKeyRotationRequestSchema.safeParse({
      schema_version: 1,
      rotation_request_id: request.id,
      organisation_id: request.organisationId,
      device_id: request.deviceId,
      current_key_id: request.currentKeyId,
      current_key_version: request.currentKeyVersion,
      proposed_key_id: request.proposedKeyId,
      proposed_key_version: request.proposedKeyVersion,
      new_public_key: request.newPublicKey,
      new_public_key_thumbprint: request.newPublicKeyThumbprint,
      new_key_storage: request.newKeyStorage,
      server_resolved_signature_profile: request.serverResolvedSignatureProfile,
      requested_at: request.requestedAt.toISOString(),
    });
    if (!contractRequest.success) return 'MALFORMED_CONTRACT_STRUCTURE';

    const contractChallenge = DeviceKeyRotationChallengeSchema.safeParse({
      schema_version: 1,
      challenge_id: challenge.id,
      organisation_id: challenge.organisationId,
      device_id: challenge.deviceId,
      rotation_request_id: challenge.rotationRequestId,
      rotation_request_fingerprint: challenge.rotationRequestFingerprint,
      current_key_id: challenge.currentKeyId,
      current_key_version: challenge.currentKeyVersion,
      proposed_key_id: challenge.proposedKeyId,
      proposed_key_version: challenge.proposedKeyVersion,
      new_public_key_thumbprint: challenge.newPublicKeyThumbprint,
      nonce: challenge.nonce,
      issued_at: challenge.issuedAt.toISOString(),
      expires_at: challenge.expiresAt.toISOString(),
    });
    if (!contractChallenge.success) return 'MALFORMED_CONTRACT_STRUCTURE';

    const contractVerification = DeviceKeyRotationPossessionVerificationResultSchema.safeParse({
      schema_version: 1,
      source: 'SENTINEL_DEVICE_KEY_ROTATION_VERIFIER',
      verified: verification.verified,
      organisation_id: verification.organisationId,
      device_id: verification.deviceId,
      rotation_request_id: verification.rotationRequestId,
      rotation_request_fingerprint: verification.rotationRequestFingerprint,
      rotation_challenge_id: verification.rotationChallengeId,
      current_key_id: verification.currentKeyId,
      current_key_version: verification.currentKeyVersion,
      proposed_key_id: verification.proposedKeyId,
      proposed_key_version: verification.proposedKeyVersion,
      new_public_key_thumbprint: verification.newPublicKeyThumbprint,
      signature_profile: verification.signatureProfile,
      canonical_statement_fingerprint: verification.canonicalStatementFingerprint,
      verified_at: verification.verifiedAt.toISOString(),
    });
    if (!contractVerification.success) return 'MALFORMED_CONTRACT_STRUCTURE';

    return {
      device,
      currentKey,
      contractRequest: contractRequest.data,
      contractChallenge: contractChallenge.data,
      contractVerification: contractVerification.data,
      // Recomputed from the parsed request, never read from the stored column
      // as authority — an id names a row, a fingerprint names its contents.
      fingerprint: deviceKeyRotationRequestFingerprint(contractRequest.data),
      newPublicKey: request.newPublicKey,
      newKeyStorage: request.newKeyStorage,
      rotationRequestId: request.id,
      rotationRequestState: request.state,
    };
  }

  private async currentKey(device: DeviceRow): Promise<DeviceKeyRow | null> {
    if (device.currentKeyId === null) return null;
    return this.repository.findDeviceKeyByKeyId(device.organisationId, device.currentKeyId);
  }

  /**
   * C16-03 / C16-R4: does this stored outcome reference name the EXACT
   * committed rotation it claims?
   *
   * THE QUESTION THIS ANSWERS IS "DID IT COMMIT?", NOT "IS IT STILL CURRENT?"
   * ------------------------------------------------------------------------
   * C16-03's first version also required the resolved key to still be `CURRENT`
   * AND still be the device's pointer. Those two conditions conflated a
   * historical fact with a live one, and rejected a perfectly ordinary history:
   *
   *     R1 rotates v1 -> v2 and COMMITS
   *     R2 rotates v2 -> v3 and COMMITS
   *     an exact network retry of R1 arrives
   *
   * R1 really did commit — its replay row is the durable proof — but v2 is now
   * `ROTATED`, so the old conditions called R1 unresolvable and answered
   * `ROTATION_OUTCOME_UNRESOLVABLE`: a fail-closed refusal aimed at a ceremony
   * that succeeded. Worse, that refusal is indistinguishable from the one raised
   * when the store is genuinely corrupt, so a real integrity fault would have
   * been drowned in the noise of honest retries.
   *
   * What still has to hold is everything that ties the stored reference to THIS
   * rotation, and every one of these is load-bearing:
   *
   *   the key row exists                ... or nothing was ever committed;
   *   in THIS tenant                    ... enforced by `findDeviceKeyRowById`,
   *                                         which is scoped to the organisation;
   *   on THIS device                    ... or it is another device's key;
   *   carrying the proposed key id      ... or it is a different rotation;
   *   at the proposed key version       ... or a different version landed.
   *
   * The key's CURRENT lifecycle state is deliberately NOT among them: `ROTATED`,
   * `REVOKED` and `COMPROMISED` are all consistent with "this rotation
   * committed, and the world has moved since".
   *
   * WHAT THE CALLER MAY DO WITH THE ANSWER: nothing operational. See the
   * `CONVERGED` arm of `CommitKeyRotationOutcome` — it reports a historical
   * commit and confers NO current key authority. `DeviceRegistryService` is the
   * only thing that answers "which credential is live?".
   *
   * `null` means "this does not resolve", and the caller fails closed.
   */
  private async resolveCommittedRotation(
    tx: Tx,
    locked: LockedRotationState,
    storedOutcomeRef: string,
  ): Promise<DeviceKeyRow | null> {
    const key = await this.repository.findDeviceKeyRowById(tx, locked.device.organisationId, storedOutcomeRef);
    if (key === null) return null;
    if (key.deviceId !== locked.device.id) return null;
    if (key.keyId !== locked.contractRequest.proposed_key_id) return null;
    if (key.keyVersion !== locked.contractRequest.proposed_key_version) return null;
    return key;
  }

  /**
   * C16-06: rotation is a GLOBAL physical-device mutation.
   *
   * There is one credential, and rotating it at site A rotates it at site B
   * too. `checkGlobalDeviceMutationAuthority` therefore requires genuine
   * organisation-wide authority, or authority over EVERY active associated
   * site; and a device associated with no site at all is reachable only
   * organisation-wide, where the old code treated it as reachable by anyone
   * holding the action anywhere.
   */
  private authoriseAgainstDeviceSites(
    principal: Principal,
    organisationId: string,
    siteIds: string[],
  ): 'DEVICE_NOT_FOUND' | null {
    return checkGlobalDeviceMutationAuthority(principal, ACTION_DEVICE_KEY_ROTATE, organisationId, siteIds);
  }
}
