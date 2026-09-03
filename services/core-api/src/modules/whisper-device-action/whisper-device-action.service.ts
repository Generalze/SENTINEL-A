import { Inject, Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import {
  WHISPER_DEVICE_ACTION_V2_PROFILE,
  WhisperDeviceActionV2VerificationResultSchema,
  canonicalWhisperDeviceActionV2Statement,
  classifyDeviceNonceConsumption,
  evaluateWhisperDeviceActionV2Admissibility,
  parseWhisperDeviceActionV2Claims,
  whisperDeviceActionV2Fingerprint,
  whisperDeviceActionV2ReplayKey,
  whisperDeviceActionV2StatementInput,
  whisperDeviceActionV2Submission,
  type AuthenticatedDeviceContext,
  type DeviceNonceConsumption,
  type WhisperDeviceActionSubmissionV2,
  type WhisperDeviceActionV2Refusal,
  type WhisperDeviceActionV2RegistryFacts,
  type WhisperDeviceActionV2VerificationResult,
} from '@sentinel/contracts';
import { createHash } from 'node:crypto';
import { PrismaService } from '../../prisma/prisma.service';
import { DeviceReplayService } from '../shield/device-replay.service';
import { P256KeyImporter } from '../shield/p256-key.importer';
import { WHISPER_DEVICE_ACTION_V2_CEREMONY } from './whisper-device-action.constants';
import { WhisperDeviceActionKeyResolver } from './whisper-device-action.key-resolver';

/**
 * ===========================================================================
 * WP-27 — THE V2 DEVICE-ACTION VERIFICATION PATH.
 * ===========================================================================
 *
 * THE ENTRY POINT IS NARROW, AND IT TAKES THE GENUINE CONTEXT
 * ----------------------------------------------------------
 * `verifyStatement` takes an `AuthenticatedDeviceContext` — WP-23's real,
 * server-issued scope statement, resolved by WP-25's gateway from its own
 * persisted row under the authenticated session's tenant. It is NEVER cast,
 * coerced, widened or adapted into `AuthenticatedWhisperDeviceContext`. Those
 * two types describe different things: v1's carries a `verificationKeyId` and a
 * `deviceTrust` for a frozen Ed25519 seam that resolves nothing, and pretending
 * one is the other would be a compile-time lie about which facility established
 * the facts.
 *
 * WHAT THIS PATH DOES, IN ORDER, AND WHY THAT ORDER
 * -------------------------------------------------
 * ```text
 * 1  parse the CLAIMS                 schema_version 2, strict, branded signature
 * 2  assemble the SUBMISSION          server identity + client claims
 * 3  resolve the REGISTRY key         by the DEVICE ROW's pointer, in-org, in-tx
 * 4  gate the PROFILE                 P256_ECDSA_SHA256 or refuse; no fallback
 * 5  VERIFY                           OpenSSL, over the canonical v2 statement
 * 6  PEEK the replay identity         reads; consumes nothing; decides nothing
 * 7  EVALUATE admissibility           the frozen contract gate, possession LAST
 * 8  CONSUME                          only on PROCEED, inside the caller's tx
 * ```
 *
 * THERE IS NO CONVERGENCE ARM IN THIS PATH, DELIBERATELY. The byte-identical
 * TRANSPORT retry — the lost-response case C17-03 is about — converges ONE LAYER
 * UP, at the gateway's own request-proof identity, and never re-enters this
 * method at all. An exact duplicate reaching HERE therefore means the same
 * action under a DIFFERENT transport proof, which is a replay of a spent action
 * and is refused. `probeVerifiedStatement` below is what the gateway's own
 * convergence reads to prove the effect exists; it causes nothing.
 *
 * STEP 8 IS AFTER STEP 5 ON PURPOSE. B11-12's ruling, carried forward: AN
 * INVALID SIGNATURE MUST NOT CONSUME A REPLAY IDENTITY. The one-shot identity is
 * a finite resource whose every field an attacker chooses in an unsigned
 * submission, so burning one before possession is proven would let anyone who
 * can reach this path pre-spend the identities a genuine operative's future
 * signals need — a denial of service on a duress channel, which is worse than
 * the replay it would be preventing.
 *
 * THE CONSUMPTION JOINS THE CALLER'S TRANSACTION. It is not this module's
 * transaction and it is deliberately not its own: WP-25's governing invariant
 * is that no replay consumption may survive without its effect and no effect
 * without its consumption, and the only way to hold that is for both to be
 * inside the one transaction the gateway commits.
 *
 * WHAT THIS PATH DELIBERATELY DOES **NOT** DO — STATED PLAINLY
 * ------------------------------------------------------------
 * IT DOES NOT ENTER THE WHISPER RECOGNITION PIPELINE, AND IT DOES NOT CLAIM TO.
 *
 * The frozen v1 runtime (`WhisperService.recognise`) is reachable only with a
 * `DeviceActionWhisperResult` — `schema_version: 1`, `signature_algorithm:
 * 'Ed25519'` — AND an `AuthenticatedWhisperDeviceContext`, and it re-verifies
 * that Ed25519 signature through `WhisperSignatureVerifier` before it will do
 * anything at all. A P-256 device cannot produce that signature, this module is
 * forbidden to forge one, and forbidden equally to coerce the context type or
 * to modify any v1 file. Its private receipt/incident machinery
 * (`consumeReplayIdentity`, `executeAndFinalize`) has no public seam.
 *
 * So convergence into the downstream pipeline CANNOT preserve the invariants,
 * and this path stops at a VERIFIED STATEMENT rather than pretending otherwise.
 * Reimplementing the receipt lifecycle, the incident entry or the eligibility
 * gate here would be a second copy of a security decision — the one thing every
 * ruling in this repository refuses — and it would be a copy that no auditor
 * reads. `WHAT 'VERIFIED_STATEMENT' MEANS, PRECISELY` on the contract's own
 * result type is the honest scope: authentic, bound, fresh, unspent. NOT
 * eligible, NOT accepted, NOT dispatched. No signal is resolved, no roster
 * consulted, no threshold compared, no context requirement evaluated and no
 * response protocol entered.
 *
 * NO ERROR CHANNEL AND NO ORACLE. Every refusal is DATA, every cause collapses
 * to the same external answer at the gateway boundary, and the precise reason
 * goes to the internal audit where an operator can read it and an attacker
 * cannot.
 */

/**
 * The two states in which there is not enough SERVER-ESTABLISHED fact to name a
 * full verification result.
 *
 * They are a separate arm rather than a result with null fields, because a
 * result whose identity fields are null is a result that can be compared
 * against anything — which is exactly the borrowed-verdict defect the result
 * type exists to close.
 */
export type WhisperDeviceActionVerificationOutcome =
  | { readonly kind: 'RESOLVED'; readonly result: WhisperDeviceActionV2VerificationResult }
  | { readonly kind: 'UNRESOLVED'; readonly refusal: WhisperDeviceActionV2Refusal };

export interface WhisperDeviceActionVerificationInput {
  /** The GENUINE server-issued context. Compared against; never adapted. */
  readonly context: AuthenticatedDeviceContext;
  /** The site the operation is being performed at, as the SERVER resolved it. */
  readonly siteId: string;
  /** The device's claims, exactly as they arrived. Parsed here, trusted nowhere. */
  readonly claims: unknown;
  /** The authoritative server clock, read inside the caller's transaction. */
  readonly now: Date;
  /**
   * The reference a later exact re-presentation converges ON.
   *
   * It is the caller's SERVER-DERIVED identity for this exact signed operation
   * (WP-25's domain idempotency key), supplied before the effect exists for the
   * reason `DeviceReplayService` documents: a row written with no reference is a
   * duplicate that names no outcome, and the contract's own union makes that
   * unrepresentable precisely because such a fact caused a SECOND effect.
   */
  readonly outcomeRef: string;
  readonly traceId: string;
}

/** What a converged re-presentation is answered with — the STORE's truth, not the request's. */
export interface WhisperDeviceActionConvergedView {
  readonly schema_version: 2;
  readonly source: 'SENTINEL_SERVER_VERIFICATION';
  readonly outcome: 'CONVERGED_ON_VERIFIED_STATEMENT';
  readonly statement_fingerprint: string;
  readonly replay_identity_digest: string;
  readonly stored_outcome_ref: string;
}

@Injectable()
export class WhisperDeviceActionService {
  constructor(
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(WhisperDeviceActionKeyResolver) private readonly keyResolver: WhisperDeviceActionKeyResolver,
    @Inject(P256KeyImporter) private readonly keys: P256KeyImporter,
    @Inject(DeviceReplayService) private readonly replay: DeviceReplayService,
  ) {}

  /**
   * THE V2 ENTRY POINT.
   *
   * `tx` is the CALLER's transaction. Everything this method reads and the one
   * row it writes join it, so the verification, the replay consumption and the
   * caller's own effect commit together or not at all.
   */
  async verifyStatement(
    tx: Prisma.TransactionClient,
    input: WhisperDeviceActionVerificationInput,
  ): Promise<WhisperDeviceActionVerificationOutcome> {
    // 1. THE VERSION DISCRIMINANT FIRST. A v1-shaped payload is refused as a
    //    version mismatch here, not probed, not coerced and not retried under
    //    another schema. Dispatch is a decision; "try v2, fall back to v1"
    //    would be a downgrade with a friendly name.
    const parsed = parseWhisperDeviceActionV2Claims(input.claims);
    if (!parsed.ok) return { kind: 'UNRESOLVED', refusal: parsed.refusal };

    // 2. The submission is ASSEMBLED: identity from the context the SERVER
    //    established, claims from the device. There is no shape anywhere in
    //    this module through which a caller could propose an identity field.
    const submission = whisperDeviceActionV2Submission(
      {
        context_id: input.context.context_id,
        organisation_id: input.context.organisation_id,
        site_id: input.siteId,
        actor_user_id: input.context.actor_user_id,
        device_id: input.context.device_id,
      },
      parsed.claims,
    );

    // 3. The registry, read inside the caller's transaction, starting from the
    //    DEVICE ROW's own key pointer.
    const resolved = await this.keyResolver.resolve(input.context.organisation_id, input.context.device_id, tx);
    if (resolved === null) return { kind: 'UNRESOLVED', refusal: 'REGISTRY_KEY_UNRESOLVABLE' };
    const registered = resolved.registered;

    // 4. THE PROFILE GATE, BEFORE ANY VERIFIER IS REACHABLE. An unsupported
    //    registry profile refuses; it never selects a different verifier and
    //    never falls back to one.
    if (!this.keyResolver.supportsProfile(registered.signature_profile)) {
      return { kind: 'RESOLVED', result: this.refuse(submission, registered, input, 'SIGNATURE_PROFILE_NOT_SUPPORTED') };
    }

    // 5. VERIFY, over exactly the canonical statement, against exactly the
    //    registered key. The profile handed to the importer on both sides is
    //    the SERVER's, because v2 HAS NO CLIENT CLAIM to bind — the support
    //    gate above is the check, and inventing a client field so that a
    //    binding had something to bind would be re-creating the very input
    //    C11-04 removed.
    const statement = canonicalWhisperDeviceActionV2Statement(
      whisperDeviceActionV2StatementInput(submission, registered.signature_profile),
    );
    const verified = this.keys.verifySignature({
      registeredPublicKey: resolved.publicKey,
      message: statement,
      signature: submission.signature,
      serverResolvedProfile: registered.signature_profile,
      claimedProfile: registered.signature_profile,
    });

    const fingerprint = whisperDeviceActionV2Fingerprint(
      whisperDeviceActionV2StatementInput(submission, registered.signature_profile),
    );
    const replayKey = whisperDeviceActionV2ReplayKey(submission);

    // 6. PEEK — read what the store already holds for this identity, taking no
    //    decision and consuming nothing. `consume`, the call that BURNS the
    //    identity, happens only after the gate says PROCEED.
    const peeked = await this.replay.peek(tx, { organisationId: input.context.organisation_id, replayKey });

    // 7. THE FROZEN GATE, ONCE. Every ordering argument lives inside it; a
    //    second decision tree here would be a second thing to keep faithful.
    const decision = evaluateWhisperDeviceActionV2Admissibility({
      context: input.context,
      submission,
      now: input.now.toISOString(),
      registered,
      verified,
      consumption: classify(replayKey, fingerprint, peeked),
    });

    if (!decision.admissible) {
      return { kind: 'RESOLVED', result: this.refuse(submission, registered, input, decision.refusal) };
    }

    // 8. FIRST_SEEN. Claim the identity — uncommitted — inside the caller's
    //    transaction, so the claim and the caller's effect land together.
    const claimed = await this.replay.consume(tx, {
      organisationId: input.context.organisation_id,
      ceremony: WHISPER_DEVICE_ACTION_V2_CEREMONY,
      replayKey,
      statementFingerprint: fingerprint,
      candidateOutcomeRef: input.outcomeRef,
      traceId: input.traceId,
    });

    if (claimed.consumption.outcome === 'REUSED_WITH_CHANGED_SEMANTICS') {
      // A concurrent statement spent this identity on different bytes between
      // the peek and this insert. The store's answer is authoritative.
      return { kind: 'RESOLVED', result: this.refuse(submission, registered, input, 'REPLAY_IDENTITY_REUSED') };
    }
    if (claimed.consumption.outcome === 'EXACT_DUPLICATE') {
      // A concurrent IDENTICAL statement won the race between the peek and this
      // insert. The store's answer is authoritative and it says this action is
      // already spent — decided against the database rather than against the
      // peek, and refused for the same reason the gate refuses it.
      return { kind: 'RESOLVED', result: this.refuse(submission, registered, input, 'REPLAY_IDENTITY_ALREADY_SPENT') };
    }

    return {
      kind: 'RESOLVED',
      result: this.result(submission, registered, input, {
        outcome: 'VERIFIED_STATEMENT',
        refusal: null,
        fingerprint,
        replayKey,
        storedOutcomeRef: input.outcomeRef,
      }),
    };
  }

  /**
   * READ-ONLY EVIDENCE: has this exact statement's one-shot identity already
   * been spent, on these exact bytes, against this exact outcome reference?
   *
   * PURE PROBE. It reads and can cause no effect — which is the whole point:
   * proving a duplicate by re-running the verifying path would CONSUME the
   * identity whose prior consumption is the thing being detected.
   *
   * `false` means FAIL CLOSED. A stored reference that cannot be proved against
   * the authoritative row never manufactures convergence.
   */
  async probeVerifiedStatement(input: {
    organisationId: string;
    siteId: string;
    actorUserId: string;
    deviceId: string;
    contextId: string;
    claims: unknown;
    expectedOutcomeRef: string;
  }): Promise<WhisperDeviceActionConvergedView | null> {
    const parsed = parseWhisperDeviceActionV2Claims(input.claims);
    if (!parsed.ok) return null;
    const submission = whisperDeviceActionV2Submission(
      {
        context_id: input.contextId,
        organisation_id: input.organisationId,
        site_id: input.siteId,
        actor_user_id: input.actorUserId,
        device_id: input.deviceId,
      },
      parsed.claims,
    );
    const replayKey = whisperDeviceActionV2ReplayKey(submission);
    const fingerprint = whisperDeviceActionV2Fingerprint(
      whisperDeviceActionV2StatementInput(submission, WHISPER_DEVICE_ACTION_V2_PROFILE),
    );

    const peeked = await this.prisma.$transaction(async (tx) =>
      this.replay.peek(tx, { organisationId: input.organisationId, replayKey }),
    );
    if (peeked === null) return null;
    // All three must agree: the same identity, the same bytes, and the same
    // server-derived outcome reference. Two out of three is not evidence.
    if (peeked.statementFingerprint !== fingerprint) return null;
    if (peeked.storedOutcomeRef !== input.expectedOutcomeRef) return null;

    return {
      schema_version: 2,
      source: 'SENTINEL_SERVER_VERIFICATION',
      outcome: 'CONVERGED_ON_VERIFIED_STATEMENT',
      statement_fingerprint: peeked.statementFingerprint,
      replay_identity_digest: peeked.replayIdentityDigest,
      stored_outcome_ref: peeked.storedOutcomeRef,
    };
  }

  // -------------------------------------------------------------------------

  private refuse(
    submission: WhisperDeviceActionSubmissionV2,
    registered: WhisperDeviceActionV2RegistryFacts,
    input: WhisperDeviceActionVerificationInput,
    refusal: WhisperDeviceActionV2Refusal,
  ): WhisperDeviceActionV2VerificationResult {
    // A refusal still carries WHAT it is about, and it carries the fingerprint
    // and identity digest computed from the SERVER's resolved profile — so an
    // operator can correlate a refusal with the statement that caused it
    // without the audit ever holding the signature or the nonce.
    return this.result(submission, registered, input, {
      outcome: 'REFUSED',
      refusal,
      fingerprint: whisperDeviceActionV2Fingerprint(whisperDeviceActionV2StatementInput(submission, registered.signature_profile)),
      replayKey: whisperDeviceActionV2ReplayKey(submission),
      storedOutcomeRef: null,
    });
  }

  private result(
    submission: WhisperDeviceActionSubmissionV2,
    registered: WhisperDeviceActionV2RegistryFacts,
    input: WhisperDeviceActionVerificationInput,
    verdict: {
      outcome: WhisperDeviceActionV2VerificationResult['outcome'];
      refusal: WhisperDeviceActionV2Refusal | null;
      fingerprint: string;
      replayKey: string;
      storedOutcomeRef: string | null;
    },
  ): WhisperDeviceActionV2VerificationResult {
    // Parsed through the contract's own schema rather than asserted into its
    // type. The schema's refinements — a refusal must name a reason, a
    // convergence must name what it converged on — are what make an incoherent
    // verdict impossible rather than merely discouraged.
    return WhisperDeviceActionV2VerificationResultSchema.parse({
      schema_version: 2,
      source: 'SENTINEL_SERVER_VERIFICATION',
      outcome: verdict.outcome,
      refusal: verdict.refusal,
      context_id: submission.context_id,
      organisation_id: submission.organisation_id,
      site_id: submission.site_id,
      actor_user_id: submission.actor_user_id,
      device_id: submission.device_id,
      key_id: registered.key_id,
      key_version: registered.key_version,
      signature_profile: registered.signature_profile,
      device_trust: registered.trust,
      key_state: registered.key_state,
      revocation_disposition: registered.revocation_disposition,
      whisper_signal_id: submission.whisper_signal_id,
      whisper_signal_version: submission.whisper_signal_version,
      device_action_id: submission.device_action_id,
      statement_fingerprint: verdict.fingerprint,
      replay_identity_digest: replayIdentityDigest(verdict.replayKey),
      stored_outcome_ref: verdict.storedOutcomeRef,
      verified_at: input.now.toISOString(),
    });
  }
}

/**
 * The same digest `DeviceReplayService` keys its rows on, computed the same
 * way, so an operator can join a verification result to the consumption row it
 * produced. The canonical key itself is never carried in a result: it contains
 * the nonce, and a one-shot value in an audit is a one-shot value that has left
 * the security boundary (D25-13).
 */
function replayIdentityDigest(replayKey: string): string {
  return createHash('sha256').update(replayKey, 'utf8').digest('hex');
}

/**
 * The contract's own classifier, fed with what the store actually holds.
 *
 * C15-R1: a stored row naming no outcome is reported HONESTLY as the empty
 * string rather than papered over with the caller's fresh candidate, and the
 * contract's consistency guard then refuses it as
 * `NONCE_CONSUMPTION_INCONSISTENT` instead of converging on nothing.
 */
function classify(
  replayKey: string,
  fingerprint: string,
  peeked: { statementFingerprint: string; storedOutcomeRef: string | null } | null,
): DeviceNonceConsumption {
  return classifyDeviceNonceConsumption({
    replay_key: replayKey,
    statement_fingerprint: fingerprint,
    stored: peeked === null ? null : { statement_fingerprint: peeked.statementFingerprint, stored_outcome_ref: peeked.storedOutcomeRef ?? '' },
  });
}
