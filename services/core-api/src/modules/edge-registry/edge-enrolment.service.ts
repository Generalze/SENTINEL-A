import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import {
  EDGE_ENROLMENT_AUTHORITY_MAX_AGE_MS,
  EDGE_POSSESSION_CHALLENGE_MAX_AGE_MS,
  EdgeEnrolmentRequestIdentitySchema,
  canonicalEdgeEnrolmentPossessionStatement,
  classifyEdgeEnrolmentAuthority,
  deriveP256PublicKeyThumbprint,
  edgeEnrolmentAuthorityReplayKey,
  edgeEnrolmentPossessionReplayKey,
  edgeEnrolmentPossessionStatementFingerprint,
  edgeEnrolmentRequestFingerprint,
  isConsistentDeviceNonceConsumption,
} from '@sentinel/contracts';
import type { Principal } from '../../common/security/principal';
import { DeviceReplayService } from '../shield/device-replay.service';
import { P256KeyImporter } from '../shield/p256-key.importer';
import {
  ACTION_EDGE_ENROLMENT_AUTHORISE,
  ACTION_EDGE_REVOKE,
  CEREMONY_EDGE_ENROLMENT_AUTHORITY,
  CEREMONY_EDGE_POSSESSION_CHALLENGE,
  EDGE_AUTHORITY_SECRET_DIGEST_ALGORITHM,
  EDGE_AUTHORITY_SECRET_ENTROPY_BYTES,
  EDGE_CHALLENGE_NONCE_ENTROPY_BYTES,
  EDGE_REQUEST_STATE_ACTIVATED,
  EDGE_REQUEST_STATE_PENDING,
  EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
  EDGE_STATE_ACTIVE,
  EDGE_STATE_PENDING,
  EDGE_STATE_WITHDRAWN,
  EDGE_TRUST_REVOKED,
  EDGE_TRUST_SUSPENDED,
  EDGE_TRUST_TRUSTED,
} from './edge-registry.constants';
import { EdgeRegistryRepository, type EdgeTx } from './edge-registry.repository';
import type {
  CompleteEdgeEnrolmentOutcome,
  EdgeRefusalCode,
  IssueEdgeAuthorityOutcome,
  IssueEdgeChallengeOutcome,
  RequestEdgeEnrolmentOutcome,
  WithdrawEdgeOutcome,
} from './edge-registry.types';

/** The secret and its digest, together for exactly as long as it takes to store one. */
interface MintedAuthoritySecret {
  readonly secret: string;
  readonly digest: string;
}

/**
 * ============================================================================
 * WP-29B / migration 26 — THE EDGE ENROLMENT CEREMONY.
 *
 * ENROLLING AN EDGE IS NOT TRUST ON FIRST USE, and every step below exists to
 * make that structurally true rather than merely intended.
 *
 * The naive design is obvious and wrong: let an Edge POST its public key, store
 * it, trust it. That is a door. Whoever reaches the network segment first
 * becomes the site's TIME WITNESS — the principal whose receipts place other
 * people's offline operations inside their lease windows — and nothing
 * afterwards can distinguish the real appliance from the one an attacker
 * plugged into the same switch.
 *
 * So the ceremony begins with a HUMAN:
 *
 *   1. A holder of `edge.enrolment.authorise`, scoped to the organisation and
 *      site, mints a short-lived one-use authority. Only its digest is stored.
 *   2. The Edge generates its keypair LOCALLY and offers the public half with
 *      the authority secret. THE SERVER RESOLVES ORGANISATION AND SITE FROM THE
 *      AUTHORITY ROW, never from anything the Edge said.
 *   3. The server issues a challenge it chose.
 *   4. The Edge signs a statement binding the challenge, the request, the key,
 *      the Edge identity, the tenant and the site.
 *   5. Only then does a registry key exist, and only then is the Edge TRUSTED.
 *
 * WHAT IS NOT HERE
 * ----------------
 * No controller. This module registers no HTTP surface at all, following the
 * WP-24 Shield precedent (D24-13) — the transport that carries an Edge's half
 * of the ceremony is EDGE-B's work and arrives with its own authentication
 * argument. Publishing a route before that exists would mean accepting an Edge
 * identity from a JSON body, which is the C10-02 hole a fourth time.
 * ============================================================================
 */
@Injectable()
export class EdgeEnrolmentService {
  constructor(
    @Inject(EdgeRegistryRepository) private readonly repository: EdgeRegistryRepository,
    @Inject(DeviceReplayService) private readonly replay: DeviceReplayService,
    @Inject(P256KeyImporter) private readonly keys: P256KeyImporter,
  ) {}

  /**
   * STEP 1 — a human authorises one enrolment, at one site.
   *
   * The authority is not a credential: on its own it enrols nothing. It names
   * a tenant, a site and the human it is auditable to; it is single-use,
   * revocable, and bounded by the contract's own ceiling.
   */
  async issueEnrolmentAuthority(
    principal: Principal,
    input: { organisationId: string; siteId: string; traceId: string },
  ): Promise<IssueEdgeAuthorityOutcome> {
    const refusal = this.checkEdgeAuthority(principal, ACTION_EDGE_ENROLMENT_AUTHORISE, input.organisationId, input.siteId);
    if (refusal !== null) return { outcome: 'REFUSED', refusal };

    if (!(await this.repository.organisationExists(input.organisationId))) {
      return { outcome: 'REFUSED', refusal: 'ORGANISATION_NOT_FOUND' };
    }
    // Proven before the write so a cross-tenant pairing answers with a refusal
    // rather than surfacing the composite foreign key as a driver fault. The
    // constraint remains the real defence (D24-04a).
    if (!(await this.repository.siteExistsInOrganisation(input.organisationId, input.siteId))) {
      return { outcome: 'REFUSED', refusal: 'SITE_NOT_IN_ORGANISATION' };
    }

    const minted = this.mintAuthoritySecret();

    // ONE transaction. The authority row and the event attributing it to a
    // human commit together or not at all: an authority with no
    // EDGE_AUTHORITY_ISSUED event is an unattributable credential-in-waiting.
    return this.repository.transaction(async (tx) => {
      const issuedAt = await this.repository.dbNow(tx);
      // The ceiling is the CONTRACT's, imported rather than chosen here.
      const expiresAt = new Date(issuedAt.getTime() + EDGE_ENROLMENT_AUTHORITY_MAX_AGE_MS);

      const authority = await this.repository.createEnrolmentAuthority(tx, {
        organisationId: input.organisationId,
        siteId: input.siteId,
        issuedByUserId: principal.user.id,
        secretDigest: minted.digest,
        issuedAt,
        expiresAt,
      });

      await this.record(tx, {
        organisationId: input.organisationId,
        edgeId: null,
        siteId: input.siteId,
        eventType: 'EDGE_AUTHORITY_ISSUED',
        actorUserId: principal.user.id,
        occurredAt: issuedAt,
        traceId: input.traceId,
        // NO SECRET. The payload names the authority and its window; the
        // material itself has nowhere to go, which is D23-14 as structure.
        payload: { authority_id: authority.id, site_id: input.siteId, expires_at: expiresAt.toISOString() },
      });

      return { outcome: 'ISSUED', authorityId: authority.id, secret: minted.secret, siteId: input.siteId, expiresAt };
    });
  }

  /** A human withdraws an unspent authority. Revocation is a state, never a delete. */
  async revokeEnrolmentAuthority(
    principal: Principal,
    input: { organisationId: string; authorityId: string; traceId: string },
  ): Promise<{ outcome: 'REVOKED' } | { outcome: 'REFUSED'; refusal: EdgeRefusalCode }> {
    const authority = await this.repository.findAuthorityByIdForRead(input.organisationId, input.authorityId);
    if (authority === null) return { outcome: 'REFUSED', refusal: 'AUTHORITY_NOT_FOUND' };
    const refusal = this.checkEdgeAuthority(principal, ACTION_EDGE_ENROLMENT_AUTHORISE, input.organisationId, authority.siteId);
    if (refusal !== null) return { outcome: 'REFUSED', refusal };

    return this.repository.transaction(async (tx) => {
      const now = await this.repository.dbNow(tx);
      const revoked = await this.repository.revokeAuthority(tx, input.organisationId, input.authorityId, now);
      if (revoked !== 1) return { outcome: 'REFUSED', refusal: 'AUTHORITY_NOT_USABLE' };
      await this.record(tx, {
        organisationId: input.organisationId,
        edgeId: null,
        siteId: authority.siteId,
        eventType: 'EDGE_AUTHORITY_REVOKED',
        actorUserId: principal.user.id,
        occurredAt: now,
        traceId: input.traceId,
        payload: { authority_id: input.authorityId },
      });
      return { outcome: 'REVOKED' };
    });
  }

  /**
   * STEP 2 — the Edge presents its authority and offers its public key.
   *
   * THE SERVER RESOLVES ORGANISATION AND SITE ITSELF. `claimedSiteId` is
   * compared, never believed: a mismatch is a refusal AND burns the authority,
   * following D24-03a — presenting an authority in an unexpected context is a
   * probe, not a typo, and an authority that survives being probed is one an
   * attacker may keep trying.
   *
   * There is no `organisationId` parameter a caller could get wrong in a useful
   * direction: it scopes the digest lookup, and a wrong tenant simply resolves
   * nothing.
   */
  async requestEnrolment(input: {
    organisationId: string;
    claimedSiteId: string;
    authoritySecret: string;
    offeredPublicKey: string;
    traceId: string;
  }): Promise<RequestEdgeEnrolmentOutcome> {
    const digest = this.digestAuthoritySecret(input.authoritySecret);
    const found = await this.repository.findAuthorityByDigest(input.organisationId, digest);
    if (found === null) return { outcome: 'REFUSED', refusal: 'AUTHORITY_NOT_FOUND' };

    return this.repository.transaction(async (tx) => {
      const now = await this.repository.dbNow(tx);
      const authority = await this.repository.lockAuthority(tx, input.organisationId, found.id);
      if (authority === null) return { outcome: 'REFUSED', refusal: 'AUTHORITY_NOT_FOUND' };

      const standing = classifyEdgeEnrolmentAuthority(
        {
          issued_at: authority.issuedAt.toISOString(),
          expires_at: authority.expiresAt.toISOString(),
          consumed_at: authority.consumedAt?.toISOString() ?? null,
          revoked_at: authority.revokedAt?.toISOString() ?? null,
        },
        now.toISOString(),
      );
      if (standing !== 'USABLE') {
        await this.recordRefusal(tx, input.organisationId, authority.siteId, 'EDGE_AUTHORITY_REFUSED', standing, now, input.traceId, {
          authority_id: authority.id,
        });
        return { outcome: 'REFUSED', refusal: standing === 'CONSUMED' ? 'AUTHORITY_ALREADY_CONSUMED' : 'AUTHORITY_NOT_USABLE' };
      }

      // A PROBE BURNS THE AUTHORITY. The site is the authority's, and a
      // presenter naming a different one has demonstrated it is not the party
      // the authority was handed to.
      if (authority.siteId !== input.claimedSiteId) {
        await this.repository.markAuthorityConsumed(tx, authority.id, now);
        await this.recordRefusal(
          tx,
          input.organisationId,
          authority.siteId,
          'EDGE_AUTHORITY_REFUSED',
          'AUTHORITY_SITE_MISMATCH',
          now,
          input.traceId,
          { authority_id: authority.id },
        );
        return { outcome: 'REFUSED', refusal: 'AUTHORITY_SITE_MISMATCH' };
      }

      // D24-05, at the Edge boundary: the offered point must actually import.
      // A structurally perfect off-curve key passes every contract check and
      // only the platform provider refuses it — and a registry entry must never
      // hold a key that cannot verify anything.
      if (!this.keys.isRuntimeValidPublicKey(input.offeredPublicKey)) {
        await this.recordRefusal(
          tx,
          input.organisationId,
          authority.siteId,
          'EDGE_ENROLMENT_REFUSED',
          'PUBLIC_KEY_NOT_RUNTIME_VALID',
          now,
          input.traceId,
          { authority_id: authority.id },
        );
        return { outcome: 'REFUSED', refusal: 'PUBLIC_KEY_NOT_RUNTIME_VALID' };
      }

      const edgeId = randomUUID();
      const requestId = randomUUID();
      const thumbprint = deriveP256PublicKeyThumbprint(input.offeredPublicKey);

      // A ROW IS NOT A TRUSTED EDGE. PENDING and SUSPENDED, with no registry
      // key at all, so nothing this Edge signs can verify anywhere.
      await this.repository.createPendingEdge(tx, {
        id: edgeId,
        organisationId: authority.organisationId,
        siteId: authority.siteId,
        enrolledByUserId: authority.issuedByUserId,
        enrolmentState: EDGE_STATE_PENDING,
        edgeTrust: EDGE_TRUST_SUSPENDED,
      });

      const identity = EdgeEnrolmentRequestIdentitySchema.parse({
        schema_version: 1,
        organisation_id: authority.organisationId,
        site_id: authority.siteId,
        authority_id: authority.id,
        edge_id: edgeId,
        public_key_thumbprint: thumbprint,
        signature_profile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
      });

      await this.repository.createEnrolmentRequest(tx, {
        id: requestId,
        organisationId: authority.organisationId,
        siteId: authority.siteId,
        authorityId: authority.id,
        edgeId,
        offeredPublicKey: input.offeredPublicKey,
        offeredPublicKeyThumbprint: thumbprint,
        signatureProfile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
        state: EDGE_REQUEST_STATE_PENDING,
        requestFingerprint: edgeEnrolmentRequestFingerprint(identity),
      });

      await this.record(tx, {
        organisationId: authority.organisationId,
        edgeId,
        siteId: authority.siteId,
        eventType: 'EDGE_ENROLMENT_REQUESTED',
        actorUserId: authority.issuedByUserId,
        occurredAt: now,
        traceId: input.traceId,
        payload: {
          authority_id: authority.id,
          enrolment_request_id: requestId,
          // A DIGEST, never the key. D23-14's rule for an audit payload.
          public_key_thumbprint: thumbprint,
        },
      });

      return {
        outcome: 'REQUESTED',
        enrolmentRequestId: requestId,
        edgeId,
        siteId: authority.siteId,
        organisationId: authority.organisationId,
      };
    });
  }

  /** STEP 3 — a challenge the SERVER chose, bound to this one request. */
  async issuePossessionChallenge(input: {
    organisationId: string;
    enrolmentRequestId: string;
    traceId: string;
  }): Promise<IssueEdgeChallengeOutcome> {
    const request = await this.repository.findEnrolmentRequest(input.organisationId, input.enrolmentRequestId);
    if (request === null) return { outcome: 'REFUSED', refusal: 'ENROLMENT_REQUEST_NOT_FOUND' };
    // Re-issuing is allowed while the request is still PENDING: an Edge that
    // answered once and lost the response — a dropped link, a power cut — must
    // be able to ask again rather than needing a fresh human authority.
    // Re-issuing grants nothing on its own, because activation still requires a
    // proof BOUND to the exact challenge, request, fingerprint and key.
    if (request.state !== EDGE_REQUEST_STATE_PENDING) return { outcome: 'REFUSED', refusal: 'ENROLMENT_STATE_INVALID' };

    return this.repository.transaction(async (tx) => {
      const issuedAt = await this.repository.dbNow(tx);
      const expiresAt = new Date(issuedAt.getTime() + EDGE_POSSESSION_CHALLENGE_MAX_AGE_MS);
      // UNPREDICTABLE is the whole property. A challenge an attacker can
      // anticipate is a challenge they can pre-sign.
      const nonce = randomBytes(EDGE_CHALLENGE_NONCE_ENTROPY_BYTES).toString('base64url');
      const challenge = await this.repository.createPossessionChallenge(tx, {
        organisationId: input.organisationId,
        enrolmentRequestId: request.id,
        nonce,
        issuedAt,
        expiresAt,
      });
      return { outcome: 'ISSUED', challengeId: challenge.id, nonce, expiresAt };
    });
  }

  /**
   * STEPS 4 AND 5 — the proof, and the registry record it produces.
   *
   * Verification and activation are ONE transaction on purpose. Splitting them
   * would leave a verified-but-unactivated verdict sitting in the database as a
   * thing a later call could pick up, and the whole point of C15-03's bound
   * verdict is that a `true` is never usable on its own.
   *
   * THE ORDER, AND WHY:
   *
   *   lock request, edge, authority   — nothing is judged against a row another
   *                                     transaction is mid-way through changing
   *   authority still usable          — an expired or burned authority cannot
   *                                     complete a ceremony it started
   *   challenge belongs to THIS request — a proof for request A cannot activate
   *                                     request B
   *   challenge still fresh           — the contract's ceiling, exclusive
   *   verify the signature over bytes that bind the key, the Edge, the tenant
   *     and the site                  — a proof from site X cannot produce a
   *                                     record for site Y
   *   consume BOTH one-shot identities — so an exact retry converges rather
   *                                     than minting a second Edge
   *   only then: registry key CURRENT, Edge ACTIVE and TRUSTED, authority burned
   */
  async completeEnrolment(input: {
    organisationId: string;
    enrolmentRequestId: string;
    challengeId: string;
    signature: string;
    traceId: string;
  }): Promise<CompleteEdgeEnrolmentOutcome> {
    return this.repository.transaction(async (tx) => {
      const now = await this.repository.dbNow(tx);

      const request = await this.repository.lockEnrolmentRequest(tx, input.organisationId, input.enrolmentRequestId);
      if (request === null) return { outcome: 'REFUSED', refusal: 'ENROLMENT_REQUEST_NOT_FOUND' };

      const challenge = await this.repository.findChallenge(input.organisationId, input.challengeId, tx);
      // MISBOUND is its own refusal: a challenge that exists but belongs to a
      // different request is a different failure from one that does not exist,
      // and the audit trail should say which.
      if (challenge === null) return { outcome: 'REFUSED', refusal: 'CHALLENGE_NOT_FOUND' };
      if (challenge.enrolmentRequestId !== request.id) return { outcome: 'REFUSED', refusal: 'CHALLENGE_MISBOUND' };
      // Exclusive boundary, per the existing WP-23 doctrine.
      if (now.getTime() >= challenge.expiresAt.getTime()) return { outcome: 'REFUSED', refusal: 'CHALLENGE_EXPIRED' };

      const authority = await this.repository.lockAuthority(tx, input.organisationId, request.authorityId);
      if (authority === null) return { outcome: 'REFUSED', refusal: 'AUTHORITY_NOT_FOUND' };

      const edge = await this.repository.lockEdge(tx, input.organisationId, request.edgeId);
      if (edge === null) return { outcome: 'REFUSED', refusal: 'EDGE_NOT_FOUND' };

      // THE BYTES. Every binding the ceremony depends on is inside them.
      const statementInput = {
        challenge_id: challenge.id,
        enrolment_request_id: request.id,
        enrolment_request_fingerprint: request.requestFingerprint,
        nonce: challenge.nonce,
        public_key_thumbprint: request.offeredPublicKeyThumbprint,
        edge_id: edge.id,
        organisation_id: edge.organisationId,
        site_id: edge.siteId,
        signature_profile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
      } as const;
      const message = canonicalEdgeEnrolmentPossessionStatement(statementInput);
      const statementFingerprint = edgeEnrolmentPossessionStatementFingerprint(statementInput);

      const verified = this.keys.verifySignature({
        registeredPublicKey: request.offeredPublicKey,
        message,
        signature: input.signature,
        serverResolvedProfile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
        claimedProfile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
      });

      // ONE VERDICT PER CHALLENGE, and the retry path reads it rather than
      // writing a second.
      //
      // `edge_possession_verification_challenge_key` makes a second row
      // impossible, and that constraint exists so a challenge cannot be
      // answered repeatedly until one of the answers is `true`. A legitimate
      // retry — the same Edge re-driving a ceremony whose response it lost —
      // therefore has to converge on the answer already recorded, and a stored
      // `false` is FINAL for that challenge: the Edge must ask for a new one.
      const existingVerdict = await this.repository.findVerificationByChallenge(input.organisationId, challenge.id, tx);
      if (existingVerdict === null) {
        // THE VERDICT IS RECORDED WHETHER OR NOT IT PASSED. `false` is a real,
        // recordable answer, and a ceremony that only writes its successes has
        // no record of the attempts that failed.
        await this.repository.recordPossessionVerification(tx, {
          organisationId: input.organisationId,
          challengeId: challenge.id,
          enrolmentRequestId: request.id,
          enrolmentRequestFingerprint: request.requestFingerprint,
          publicKeyThumbprint: request.offeredPublicKeyThumbprint,
          possessionStatementFingerprint: statementFingerprint,
          signatureProfile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
          verified,
          verifiedAt: now,
        });
      } else if (!existingVerdict.verified || existingVerdict.possessionStatementFingerprint !== statementFingerprint) {
        // Either this challenge has already been answered wrongly, or the
        // retry is presenting DIFFERENT bytes under the same challenge — which
        // is a second attempt wearing a retry's clothes.
        await this.recordRefusal(
          tx,
          input.organisationId,
          edge.siteId,
          'EDGE_POSSESSION_REFUSED',
          'POSSESSION_NOT_VERIFIED',
          now,
          input.traceId,
          { enrolment_request_id: request.id, challenge_id: challenge.id },
        );
        return { outcome: 'REFUSED', refusal: 'POSSESSION_NOT_VERIFIED' };
      }

      if (!verified) {
        await this.recordRefusal(
          tx,
          input.organisationId,
          edge.siteId,
          'EDGE_POSSESSION_REFUSED',
          'POSSESSION_NOT_VERIFIED',
          now,
          input.traceId,
          { enrolment_request_id: request.id, challenge_id: challenge.id, edge_id: edge.id },
        );
        return { outcome: 'REFUSED', refusal: 'POSSESSION_NOT_VERIFIED' };
      }

      // C16-02: RESOLVE BEFORE BURNING. Both one-shot identities must name ONE
      // canonical outcome, and on a retry that outcome is the Edge that already
      // exists rather than a candidate this transaction is about to discard.
      const authorityReplayKey = edgeEnrolmentAuthorityReplayKey({
        organisation_id: edge.organisationId,
        site_id: edge.siteId,
        authority_id: authority.id,
      });
      const challengeReplayKey = edgeEnrolmentPossessionReplayKey({
        organisation_id: edge.organisationId,
        site_id: edge.siteId,
        enrolment_request_id: request.id,
        challenge_id: challenge.id,
        nonce: challenge.nonce,
      });
      const peeked = await this.replay.peek(tx, { organisationId: input.organisationId, replayKey: authorityReplayKey });
      const outcomeRef = peeked?.storedOutcomeRef !== undefined && peeked.storedOutcomeRef !== null ? peeked.storedOutcomeRef : edge.id;

      const authorityConsumption = await this.replay.consume(tx, {
        organisationId: input.organisationId,
        ceremony: CEREMONY_EDGE_ENROLMENT_AUTHORITY,
        replayKey: authorityReplayKey,
        statementFingerprint,
        candidateOutcomeRef: outcomeRef,
        traceId: input.traceId,
      });
      const challengeConsumption = await this.replay.consume(tx, {
        organisationId: input.organisationId,
        ceremony: CEREMONY_EDGE_POSSESSION_CHALLENGE,
        replayKey: challengeReplayKey,
        statementFingerprint,
        candidateOutcomeRef: outcomeRef,
        traceId: input.traceId,
      });

      for (const fact of [authorityConsumption.consumption, challengeConsumption.consumption]) {
        // The contract's own consistency gate, run before the fact is acted on
        // — C15-R1's rule that a half-written row fails CLOSED with a named
        // refusal rather than falling past a convergence branch.
        if (!isConsistentDeviceNonceConsumption(fact)) {
          return { outcome: 'REFUSED', refusal: 'REPLAY_FACT_INCONSISTENT' };
        }
        if (fact.outcome === 'REUSED_WITH_CHANGED_SEMANTICS') {
          await this.recordRefusal(tx, input.organisationId, edge.siteId, 'EDGE_REPLAY_CONFLICT', 'REPLAY_CONFLICT', now, input.traceId, {
            enrolment_request_id: request.id,
          });
          return { outcome: 'REFUSED', refusal: 'REPLAY_CONFLICT' };
        }
      }

      // AN EXACT RETRY CONVERGES. No second Edge, no second key, no second
      // effect — the ceremony already completed and this is the same one.
      if (authorityConsumption.consumption.outcome === 'EXACT_DUPLICATE') {
        return { outcome: 'CONVERGED', edgeId: authorityConsumption.consumption.stored_outcome_ref };
      }

      // The authority is spent, fenced: a count of zero means somebody else
      // burned it between the lock and here, which cannot happen under the lock
      // and is refused rather than assumed benign.
      if ((await this.repository.markAuthorityConsumed(tx, authority.id, now)) !== 1) {
        return { outcome: 'REFUSED', refusal: 'AUTHORITY_ALREADY_CONSUMED' };
      }

      const edgeKeyId = randomUUID();
      const edgeKeyVersion = 1;
      await this.repository.createRegistryKey(tx, {
        organisationId: edge.organisationId,
        edgeId: edge.id,
        enrolmentRequestId: request.id,
        edgeKeyId,
        edgeKeyVersion,
        publicKey: request.offeredPublicKey,
        publicKeyThumbprint: request.offeredPublicKeyThumbprint,
        signatureProfile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
        // CURRENT only now: possession has been proved against an authority a
        // human issued, at the site the authority named.
        status: 'CURRENT',
        registeredAt: now,
        activatedAt: now,
      });

      if ((await this.repository.activateEdge(tx, edge.organisationId, edge.id, now, EDGE_STATE_ACTIVE, EDGE_TRUST_TRUSTED)) !== 1) {
        return { outcome: 'REFUSED', refusal: 'EDGE_STATE_INVALID' };
      }
      if ((await this.repository.advanceRequestState(tx, edge.organisationId, request.id, EDGE_REQUEST_STATE_PENDING, EDGE_REQUEST_STATE_ACTIVATED)) !== 1) {
        return { outcome: 'REFUSED', refusal: 'ENROLMENT_STATE_INVALID' };
      }

      await this.record(tx, {
        organisationId: edge.organisationId,
        edgeId: edge.id,
        siteId: edge.siteId,
        eventType: 'EDGE_POSSESSION_VERIFIED',
        actorUserId: null,
        occurredAt: now,
        traceId: input.traceId,
        payload: { enrolment_request_id: request.id, challenge_id: challenge.id, statement_fingerprint: statementFingerprint },
      });
      await this.record(tx, {
        organisationId: edge.organisationId,
        edgeId: edge.id,
        siteId: edge.siteId,
        eventType: 'EDGE_AUTHORITY_CONSUMED',
        actorUserId: authority.issuedByUserId,
        occurredAt: now,
        traceId: input.traceId,
        payload: { authority_id: authority.id, enrolment_request_id: request.id },
      });
      await this.record(tx, {
        organisationId: edge.organisationId,
        edgeId: edge.id,
        siteId: edge.siteId,
        eventType: 'EDGE_ENROLLED',
        actorUserId: authority.issuedByUserId,
        occurredAt: now,
        traceId: input.traceId,
        edgeKeyId,
        edgeKeyVersion,
        outcome: 'ACCEPTED',
        payload: {
          enrolment_request_id: request.id,
          authority_id: authority.id,
          authorised_by_user_id: authority.issuedByUserId,
          authority_issued_at: authority.issuedAt.toISOString(),
          authority_expires_at: authority.expiresAt.toISOString(),
          public_key_thumbprint: request.offeredPublicKeyThumbprint,
          signature_profile: EDGE_SERVER_SELECTED_SIGNATURE_PROFILE,
        },
      });

      return { outcome: 'ENROLLED', edgeId: edge.id, edgeKeyId, edgeKeyVersion };
    });
  }

  /**
   * WITHDRAWAL. A state, never a deletion.
   *
   * The Edge stops being TRUSTED and its key is REVOKED, and both rows stay
   * exactly where they are. Deleting them would make every receipt this Edge
   * ever signed unverifiable after the fact — which is the moment somebody most
   * needs to know which box witnessed a shift's work.
   */
  async withdrawEdge(principal: Principal, input: { organisationId: string; edgeId: string; traceId: string }): Promise<WithdrawEdgeOutcome> {
    const edge = await this.repository.findEdge(input.organisationId, input.edgeId);
    if (edge === null) return { outcome: 'REFUSED', refusal: 'EDGE_NOT_FOUND' };
    const refusal = this.checkEdgeAuthority(principal, ACTION_EDGE_REVOKE, input.organisationId, edge.siteId);
    if (refusal !== null) return { outcome: 'REFUSED', refusal };

    return this.repository.transaction(async (tx) => {
      const now = await this.repository.dbNow(tx);
      const withdrawn = await this.repository.withdrawEdge(tx, {
        organisationId: input.organisationId,
        edgeId: input.edgeId,
        withdrawnAt: now,
        state: EDGE_STATE_WITHDRAWN,
        trust: EDGE_TRUST_REVOKED,
      });
      if (withdrawn !== 1) return { outcome: 'REFUSED', refusal: 'EDGE_STATE_INVALID' };
      await this.repository.revokeRegistryKeys(tx, input.organisationId, input.edgeId, now);
      await this.record(tx, {
        organisationId: input.organisationId,
        edgeId: input.edgeId,
        siteId: edge.siteId,
        eventType: 'EDGE_WITHDRAWN',
        actorUserId: principal.user.id,
        occurredAt: now,
        traceId: input.traceId,
        payload: { edge_id: input.edgeId, withdrawn_by_user_id: principal.user.id },
      });
      return { outcome: 'WITHDRAWN', edgeId: input.edgeId };
    });
  }

  // -------------------------------------------------------------------------

  /**
   * RBAC plus the tenant and site boundary, in one place.
   *
   * The `@RequiresAction` decorator on any future controller is defence in
   * depth and cannot do this: the site an action concerns is not in the request
   * body, it is on the row being acted on. This is Shield's
   * `checkDeviceAuthority` argument, applied to Edge.
   */
  private checkEdgeAuthority(principal: Principal, action: string, organisationId: string, siteId: string): EdgeRefusalCode | null {
    if (principal.organisation_id !== organisationId) return 'NOT_AUTHORISED';
    if (!principal.hasAction(action)) return 'NOT_AUTHORISED';
    // A site-scoped assignment grants the action at THAT site only; an
    // organisation-wide assignment (site_id null) grants it across the tenant.
    const scoped = principal.roles.some((assignment) => assignment.site_id === null || assignment.site_id === siteId);
    return scoped ? null : 'NOT_AUTHORISED';
  }

  /**
   * D24-03a's sizing: >= 256 bits of cryptographic randomness, base64url in
   * transit, SHA-256 hex at rest. The two values exist together only inside
   * this function's return and are separated immediately by the caller — the
   * digest goes to the database, the secret goes back to the issuer, and
   * nothing holds both again.
   */
  private mintAuthoritySecret(): MintedAuthoritySecret {
    const secret = randomBytes(EDGE_AUTHORITY_SECRET_ENTROPY_BYTES).toString('base64url');
    return { secret, digest: this.digestAuthoritySecret(secret) };
  }

  private digestAuthoritySecret(secret: string): string {
    return createHash(EDGE_AUTHORITY_SECRET_DIGEST_ALGORITHM).update(secret, 'utf8').digest('hex');
  }

  private async record(
    tx: EdgeTx,
    input: {
      organisationId: string;
      edgeId: string | null;
      siteId: string | null;
      eventType: string;
      actorUserId: string | null;
      occurredAt: Date;
      traceId: string;
      edgeKeyId?: string;
      edgeKeyVersion?: number;
      outcome?: string;
      payload: Record<string, unknown>;
    },
  ): Promise<void> {
    await this.repository.appendSecurityEvent(tx, {
      organisationId: input.organisationId,
      edgeId: input.edgeId,
      siteId: input.siteId,
      eventType: input.eventType,
      actorUserId: input.actorUserId,
      edgeKeyId: input.edgeKeyId ?? null,
      edgeKeyVersion: input.edgeKeyVersion ?? null,
      outcome: input.outcome ?? null,
      refusalCode: null,
      payload: input.payload as never,
      occurredAt: input.occurredAt,
      traceId: input.traceId,
    });
  }

  private async recordRefusal(
    tx: EdgeTx,
    organisationId: string,
    siteId: string | null,
    eventType: string,
    refusalCode: string,
    occurredAt: Date,
    traceId: string,
    payload: Record<string, unknown>,
  ): Promise<void> {
    await this.repository.appendSecurityEvent(tx, {
      organisationId,
      edgeId: null,
      siteId,
      eventType,
      actorUserId: null,
      edgeKeyId: null,
      edgeKeyVersion: null,
      outcome: 'REFUSED',
      refusalCode,
      payload: payload as never,
      occurredAt,
      traceId,
    });
  }
}
