import { Inject, Injectable, Logger } from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';
import {
  DeviceKeyStorageSchema,
  deriveP256PublicKeyThumbprint,
  type DeviceCustody,
  type DeviceKeyStorage,
  type DeviceSignatureProfile,
} from '@sentinel/contracts';
import type { Principal } from '../../common/security/principal';
import { DeviceEnrollmentService } from '../shield/device-enrollment.service';
import { P256KeyImporter } from '../shield/p256-key.importer';
import type {
  CommitEnrollmentOutcome,
  CreateEnrollmentRequestOutcome,
  IssuePossessionChallengeOutcome,
  VerifyPossessionOutcome,
} from '../shield/shield.types';
import { AndroidKeyAttestationVerifier } from './android-key-attestation.verifier';
import {
  ATTESTATION_CHALLENGE_ENTROPY_BYTES,
  DEVICE_ATTESTATION_CHALLENGE_MAX_AGE_MS,
} from './device-enrollment-ingress.constants';
import { DeviceEnrollmentIngressRepository } from './device-enrollment-ingress.repository';
import type {
  IngressRefused,
  IssueAttestationChallengeOutcome,
  SubmitEnrollmentRequestOutcome,
} from './device-enrollment-ingress.types';

/**
 * ============================================================================
 * WP-26/D26-01, D26-04A, D26-09 — THE ENROLLMENT BRIDGE.
 *
 * THE PROBLEM THIS SERVICE EXISTS TO SOLVE, STATED PLAINLY
 * --------------------------------------------------------
 * WP-24 built the enrollment ceremony as an INTERNAL service with, deliberately,
 * zero HTTP surface. WP-25 built a gateway that requires an ESTABLISHED CONTEXT,
 * which requires an ALREADY REGISTERED device. WP-26 has a physical phone
 * holding a freshly generated hardware key that is registered nowhere, and can
 * therefore use neither.
 *
 * THE DEVICE IS NOT AUTHENTICATED HERE, AND THAT IS NOT A GAP.
 *
 * It cannot be: it has no registered key, and that is the reason the ceremony
 * exists rather than a hole in it. What substitutes for device authentication is
 * the SECOND HUMAN approving the exact request fingerprint, on the Command side,
 * where the phone cannot reach. If the phone could cause its own approval the
 * ceremony would be decorative.
 *
 * SO THIS INGRESS IS AUTHENTICATED BY TWO INDEPENDENT FACTS, NEITHER OF THEM
 * THE DEVICE
 * --------------------------------------------------------------------------
 *     (1) the INTENDED USER's authenticated human session   proves WHO
 *     (2) the one-shot bootstrap grant secret               proves THIS
 *                                                           CEREMONY was
 *                                                           authorised by a
 *                                                           commander, for this
 *                                                           org + site + user
 *
 * and the device contributes EVIDENCE, never authority: a public key and a
 * hardware attestation chain.
 *
 * THE SESSION IS THE ANCHOR (C17-01 / C17-02), AND IT IS BOUND FIRST
 * ------------------------------------------------------------------
 * Every method below equality-binds the authenticated principal's organisation
 * and user id to the grant's intended organisation, site and user BEFORE
 * anything enters Shield. That ordering is the property, not a detail: an org-A
 * session naming org-B must produce ZERO rows and ZERO events under org-B, and
 * the only way to guarantee that is to refuse before the first Shield call.
 *
 * A BOOTSTRAP GRANT CREATES ZERO DEVICE AUTHORITY (D26-01). Nothing in this
 * file registers a device, approves anything, or moves trust. It arranges
 * evidence and calls Shield, which owns every rule.
 *
 * IT WRITES NO SHIELD TABLE. Two tables, both its own:
 * `device_attestation_challenges` and `android_key_attestation_artifacts`.
 * `test/device-enrollment-ingress-boundary.architecture.spec.ts` asserts that
 * as a source scan.
 * ============================================================================
 */
@Injectable()
export class DeviceEnrollmentIngressService {
  /**
   * The internal reason log.
   *
   * D25-13's discipline: every EXTERNAL refusal on this surface is identical,
   * and the precise reason goes somewhere an operator can read it and an
   * attacker cannot. Shield's own refusals already reach
   * `device_security_events`; the refusals this file owns — a session that is
   * not the intended user, a spent or expired attestation challenge — happen
   * before any Shield ceremony exists to attach them to, so they are logged
   * here with the trace id.
   *
   * WHAT NEVER ENTERS THIS LOG: the bootstrap token, the challenge value, a raw
   * certificate, a public key, a signature. The log takes a reason code and a
   * trace id, and there is no call site below that passes anything else.
   */
  private readonly logger = new Logger(DeviceEnrollmentIngressService.name);

  constructor(
    @Inject(DeviceEnrollmentService) private readonly enrollment: DeviceEnrollmentService,
    @Inject(P256KeyImporter) private readonly keys: P256KeyImporter,
    @Inject(AndroidKeyAttestationVerifier) private readonly verifier: AndroidKeyAttestationVerifier,
    @Inject(DeviceEnrollmentIngressRepository) private readonly repository: DeviceEnrollmentIngressRepository,
  ) {}

  // -------------------------------------------------------------------------
  // Phase 0 — D26-04A: the server nonce, BEFORE the phone generates its key
  // -------------------------------------------------------------------------

  /**
   * Issues an attestation challenge for a presented bootstrap grant.
   *
   * WHY THIS PHASE EXISTS AT ALL, AND WHY IT IS FIRST
   * -------------------------------------------------
   * Android Key Attestation is produced WHEN THE KEY IS GENERATED:
   * `setAttestationChallenge()` places the relying party's challenge inside the
   * attestation certificate, precisely so the key can be shown to have been
   * created in response to a specific request. A server that does not compare
   * that value against its own challenge can be handed an old certificate — so
   * a sequence in which the phone generates a key and THEN asks the server for
   * something is replayable, and this one is not.
   *
   * WHAT IT HANDS BACK IS NOT A SECRET. It is >= 256 bits of server randomness
   * and it is a FRESHNESS VALUE. The phone embeds it in a certificate anyone
   * holding the device could read. The entropy is there so it cannot be
   * PREDICTED — a challenge an attacker can guess in advance is a challenge they
   * can have a key pre-generated against, which is the exact replay this phase
   * closes.
   *
   * THE CHALLENGE CANNOT OUTLIVE ITS GRANT. `expiresAt` is the EARLIER of
   * `now + DEVICE_ATTESTATION_CHALLENGE_MAX_AGE_MS` and the grant's own expiry.
   * A grant that is already dead cannot mint a challenge at all — that is
   * `presentBootstrapGrantForCeremony`'s refusal, taken before this code runs.
   */
  async issueAttestationChallenge(
    principal: Principal,
    input: { organisationId: string; siteId: string; intendedUserId: string; bootstrapToken: string; traceId: string },
  ): Promise<IssueAttestationChallengeOutcome> {
    const bound = this.bindSession(principal, input, 'ATTESTATION_CHALLENGE');
    if (bound !== null) return bound;

    const grant = await this.enrollment.presentBootstrapGrantForCeremony({
      organisationId: input.organisationId,
      siteId: input.siteId,
      intendedUserId: input.intendedUserId,
      bootstrapToken: input.bootstrapToken,
      traceId: input.traceId,
    });
    if (grant.outcome !== 'USABLE') {
      this.refused('BOOTSTRAP_NOT_USABLE', input.traceId, grant.refusal);
      return { outcome: 'REFUSED' };
    }

    const issuedAt = await this.repository.now();
    const ownCeiling = new Date(issuedAt.getTime() + DEVICE_ATTESTATION_CHALLENGE_MAX_AGE_MS);
    // THE CLAMP. Two independent bounds, and the challenge gets the tighter one.
    const expiresAt = ownCeiling.getTime() <= grant.expiresAt.getTime() ? ownCeiling : grant.expiresAt;
    // A grant with no usable time left cannot support a challenge with none
    // either. `presentBootstrapGrantForCeremony` has already refused an EXPIRED
    // grant; this catches the sliver in which a grant is alive but expires
    // before a challenge issued against it could ever be answered.
    if (expiresAt.getTime() <= issuedAt.getTime()) {
      this.refused('CHALLENGE_WINDOW_EMPTY', input.traceId, null);
      return { outcome: 'REFUSED' };
    }

    // Canonical unpadded base64url, matching every other opaque value WP-23..26
    // puts on the wire.
    const challengeValue = randomBytes(ATTESTATION_CHALLENGE_ENTROPY_BYTES).toString('base64url');
    const challenge = await this.repository.createAttestationChallenge({
      // The grant's OWN organisation, site and intended user — proved equal to
      // the presented ones by `presentBootstrapGrantForCeremony`, and taken from
      // the server's row rather than from the request either way (C17-02).
      organisationId: input.organisationId,
      siteId: grant.siteId,
      intendedUserId: grant.intendedUserId,
      bootstrapGrantId: grant.grantId,
      challengeValue,
      issuedAt,
      expiresAt,
    });

    return {
      outcome: 'ISSUED',
      attestationChallengeId: challenge.id,
      challengeValue,
      expiresAt: challenge.expiresAt,
    };
  }

  // -------------------------------------------------------------------------
  // Phase A — D26-01 crossing A: the enrollment request
  // -------------------------------------------------------------------------

  /**
   * The device's public key and attestation chain, turned into a Shield request.
   *
   * THE ORDER OF THIS METHOD IS THE SECURITY ARGUMENT
   * -------------------------------------------------
   *   1. bind the session          nothing enters Shield under a claimed tenant
   *   2. present the grant         D24-03a's probe rule, unchanged
   *   3. bind the challenge        to THIS grant, site and intended user
   *   4. CONSUME the challenge     one-shot, fenced, before any verification
   *   5. import the submitted key  D24-05's runtime boundary
   *   6. verify the chain          the D26-04B verifier, against SERVER anchors
   *   7. persist the artifact      the restricted record, always, whatever it said
   *   8. call Shield               with a server-owned reference and nothing else
   *
   * STEP 4 IS BEFORE STEP 6 DELIBERATELY. The challenge is spent by the
   * ATTEMPT, not by the success. A challenge that survived a failed verification
   * would let an attacker grind certificates against one server nonce, which is
   * the whole thing a nonce is for. D26-04A's own words for the failure case are
   * that the phone "discards the unfinished key and restarts" — a fresh
   * challenge and a fresh key, not another go with the old one.
   *
   * D26-02 — `keyStorage` IS EARNED, NEVER CLAIMED.
   *
   * There is no `key_storage` field on this surface and there never will be. The
   * value is DERIVED from the server's own verdict: `HARDWARE_BACKED` only when
   * the verifier returned VERIFIED, which means StrongBox, P-256, origin
   * GENERATED, the exact server challenge, the submitted key, a chain to a
   * pinned root, and an acceptable boot state. Everything else — including
   * `UNAVAILABLE` — enrols as `SOFTWARE`. A client that could claim
   * `HARDWARE_BACKED` is a client that could claim TRUSTED, which is the whole
   * model inverted; and D23-03 already rules that a software-backed key can
   * never become TRUSTED, so the conservative value is also the safe one.
   */
  async submitEnrollmentRequest(
    principal: Principal,
    input: {
      organisationId: string;
      siteId: string;
      intendedUserId: string;
      bootstrapToken: string;
      attestationChallengeId: string;
      publicKey: string;
      claimedSignatureProfile: DeviceSignatureProfile;
      custody: DeviceCustody;
      custodyRegimeId: string | null;
      certificateChainBase64: readonly string[];
      traceId: string;
    },
  ): Promise<SubmitEnrollmentRequestOutcome> {
    const bound = this.bindSession(principal, input, 'ENROLLMENT_REQUEST');
    if (bound !== null) return bound;

    const grant = await this.enrollment.presentBootstrapGrantForCeremony({
      organisationId: input.organisationId,
      siteId: input.siteId,
      intendedUserId: input.intendedUserId,
      bootstrapToken: input.bootstrapToken,
      traceId: input.traceId,
    });
    if (grant.outcome !== 'USABLE') {
      this.refused('BOOTSTRAP_NOT_USABLE', input.traceId, grant.refusal);
      return { outcome: 'REFUSED' };
    }

    // The challenge is read under the SESSION's organisation. A challenge in
    // another tenant and an id that never existed are the same answer.
    const challenge = await this.repository.findAttestationChallenge(input.organisationId, input.attestationChallengeId);
    if (challenge === null) {
      this.refused('ATTESTATION_CHALLENGE_NOT_FOUND', input.traceId, null);
      return { outcome: 'REFUSED' };
    }
    // EVERY binding, and each of them separately, so no one of them can be the
    // only thing standing between two ceremonies.
    if (
      challenge.bootstrapGrantId !== grant.grantId ||
      challenge.siteId !== grant.siteId ||
      challenge.intendedUserId !== grant.intendedUserId
    ) {
      this.refused('ATTESTATION_CHALLENGE_MISBOUND', input.traceId, null);
      return { outcome: 'REFUSED' };
    }

    // THE MATERIAL CONTENT OF THIS SUBMISSION, AS ONE VALUE (C18-03).
    //
    // Computed BEFORE the challenge is spent, because it is what the spend is
    // recorded against and what a later retry is compared to. Every input that
    // could make two submissions different ceremonies is in it; nothing that
    // varies between two honest retries of the same submission is.
    const submissionFingerprint = enrollmentSubmissionFingerprint({
      organisationId: input.organisationId,
      siteId: grant.siteId,
      intendedUserId: grant.intendedUserId,
      bootstrapGrantId: grant.grantId,
      attestationChallengeId: challenge.id,
      publicKey: input.publicKey,
      claimedSignatureProfile: input.claimedSignatureProfile,
      custody: input.custody,
      custodyRegimeId: input.custodyRegimeId,
      certificateChainBase64: input.certificateChainBase64,
    });

    // ---- C18-03: A SUCCESSFUL REQUEST SURVIVES A LOST RESPONSE ------------
    //
    // THE FAILURE THIS CLOSES. Shield creates the enrollment request, the HTTP
    // response is lost on the way back to the phone, the phone retries the
    // byte-identical submission — and, because the challenge is spent, is told
    // `ATTESTATION_CHALLENGE_ALREADY_CONSUMED` and never learns its own request
    // id or fingerprint. The ceremony is then unfinishable: the operative
    // cannot read a fingerprint to a commander, and a request nobody can name
    // sits in the queue. Shield already established the opposite doctrine one
    // layer down — an identical repeat under one grant CONVERGES on the request
    // that exists — and this restores it at the ingress.
    //
    // SPENDING A CHALLENGE ON AN ATTEMPT IS STILL RIGHT AND IS UNCHANGED. What
    // is wrong is treating an exact retry of an already-SUCCESSFUL request as
    // another attempt. So this is not a relaxation of the one-shot rule; it is a
    // read of durable state that PROVES the attempt already happened and already
    // produced a specific answer.
    //
    // IT IS AUTHORITATIVE OR IT REFUSES. `CONVERGED` requires that the server's
    // own row records BOTH that this exact submission spent this challenge AND
    // the complete outcome it produced. Any of: no recorded fingerprint, a
    // different fingerprint, a partially recorded outcome — fails closed. The
    // answer is served entirely from recorded state: NO second artifact, NO
    // second Shield request, NO re-verification, and no expiry is extended.
    //
    // IT IS CHECKED BEFORE THE EXPIRY BOUND, deliberately. The expiry governs
    // whether a NEW attempt may proceed; it has no business erasing the record
    // of one that already succeeded. A retry that arrives 121 seconds late is
    // still asking about a request that exists, and answering it creates
    // nothing.
    if (challenge.consumedAt !== null) {
      const resolved = resolveRecordedSubmission(challenge, submissionFingerprint);
      if (resolved !== null) return resolved;
      this.refused('ATTESTATION_CHALLENGE_ALREADY_CONSUMED', input.traceId, null);
      return { outcome: 'REFUSED' };
    }

    const now = await this.repository.now();
    // EXCLUSIVE boundary, evaluated at REQUEST TIME. There is no expiry
    // scheduler anywhere in this module (D25-08).
    if (now.getTime() >= challenge.expiresAt.getTime()) {
      this.refused('ATTESTATION_CHALLENGE_EXPIRED', input.traceId, null);
      return { outcome: 'REFUSED' };
    }

    // ONE-SHOT, AS A DATABASE FACT. The read above is a courtesy that produces a
    // clear refusal; THIS is the check that holds when two submissions race. The
    // same statement records WHICH submission spent it, so the row can never say
    // "consumed" without saying by what.
    const claimed = await this.repository.consumeAttestationChallenge(
      input.organisationId,
      challenge.id,
      now,
      submissionFingerprint,
    );
    if (!claimed) {
      this.refused('ATTESTATION_CHALLENGE_ALREADY_CONSUMED', input.traceId, null);
      return { outcome: 'REFUSED' };
    }

    // D24-05's runtime crypto boundary, reused rather than reimplemented. A
    // structurally perfect off-curve point dies here, and the SPKI the verifier
    // compares against the leaf is built by the platform from the key the server
    // received — never re-derived from anything the certificate said.
    const submittedKey = this.keys.importPublicKey(input.publicKey);
    if (submittedKey === null) {
      this.refused('PUBLIC_KEY_NOT_RUNTIME_VALID', input.traceId, null);
      return { outcome: 'REFUSED' };
    }
    const submittedPublicKeySpkiDer = Buffer.from(submittedKey.export({ format: 'der', type: 'spki' }));

    const verdict = await this.verifier.verify({
      certificateChainBase64: input.certificateChainBase64,
      expectedChallengeValue: challenge.challengeValue,
      submittedPublicKeySpkiDer,
      now,
    });

    // C15-02: the thumbprint is COMPUTED from the key, never believed.
    const publicKeyThumbprint = deriveP256PublicKeyThumbprint(input.publicKey);

    // THE ARTIFACT IS WRITTEN WHATEVER THE VERDICT SAID. An append-only provider
    // record that only recorded successes would be a record of nothing: the
    // interesting rows are the refusals.
    const artifactId = await this.repository.recordAttestationArtifact({
      organisationId: input.organisationId,
      bootstrapGrantId: grant.grantId,
      attestationChallengeId: challenge.id,
      publicKeyThumbprint,
      certificateChainHash: verdict.certificateChainHash,
      verifierVersion: verdict.verifierVersion,
      trustAnchorSetVersion: verdict.trustAnchorSetVersion,
      revocationSnapshotVersion: verdict.revocationSnapshotVersion,
      claims: verdict.claims,
      outcome: verdict.outcome,
      outcomeReason: verdict.reason,
      evaluatedAt: now,
      // THE RESTRICTED COLUMN, and the only place these bytes come to rest.
      certificateChainDer: input.certificateChainBase64,
    });

    const keyStorage: DeviceKeyStorage = verdict.outcome === 'VERIFIED' ? 'HARDWARE_BACKED' : 'SOFTWARE';

    const created: CreateEnrollmentRequestOutcome = await this.enrollment.createEnrollmentRequest({
      organisationId: input.organisationId,
      siteId: grant.siteId,
      intendedUserId: grant.intendedUserId,
      bootstrapToken: input.bootstrapToken,
      custody: input.custody,
      publicKey: input.publicKey,
      keyStorage,
      // C15-01: a CLAIM, passed through as one. Shield equality-binds it to the
      // profile its own registry selected and never consults it.
      claimedSignatureProfile: input.claimedSignatureProfile,
      custodyRegimeId: input.custodyRegimeId,
      // The server's own handle on the server's own verdict. See
      // `AndroidKeyAttestationEvaluator` for why this confers nothing.
      attestationArtifactRef: artifactId,
      traceId: input.traceId,
    });
    if (created.outcome === 'REFUSED') {
      this.refused('SHIELD_REFUSED_REQUEST', input.traceId, created.refusal);
      return { outcome: 'REFUSED' };
    }

    // C18-03: THE RECEIPT, written only once a request actually exists.
    //
    // Recorded AFTER Shield answered, so the row can only ever describe an
    // outcome that really happened. A crash between the consume above and this
    // write leaves the challenge spent with no recorded outcome, and a retry
    // then FAILS CLOSED — which is correct: the server cannot prove what
    // happened, so it must not claim to know. Write-once at the database level,
    // and its result is deliberately not acted on: the request exists either
    // way, and failing a real success over a bookkeeping row would be the wrong
    // trade.
    await this.repository.recordEnrollmentOutcome({
      organisationId: input.organisationId,
      challengeId: challenge.id,
      enrollmentRequestId: created.enrollmentRequestId,
      enrollmentRequestFingerprint: created.requestFingerprint,
      attestationOutcome: created.attestationOutcome,
      keyStorage,
    });

    return {
      outcome: created.outcome,
      enrollmentRequestId: created.enrollmentRequestId,
      requestFingerprint: created.requestFingerprint,
      attestationOutcome: created.attestationOutcome,
      keyStorage,
    };
  }

  // -------------------------------------------------------------------------
  // Phase B — D26-01 crossing B: possession, and the commit
  //
  // These three are thin. Shield owns every rule; what the ingress adds is the
  // C17-01 session binding, which WP-24 could not perform because it had no
  // transport at all.
  // -------------------------------------------------------------------------

  async issuePossessionChallenge(
    principal: Principal,
    input: { organisationId: string; enrollmentRequestId: string; traceId: string },
  ): Promise<IssuePossessionChallengeOutcome | IngressRefused> {
    const bound = this.bindCeremonySession(principal, input);
    if (bound !== null) return bound;
    return this.enrollment.issuePossessionChallenge(principal, input);
  }

  /**
   * The StrongBox signature over the server's possession challenge.
   *
   * `DeviceEnrollmentService.verifyPossession` takes NO principal, because WP-24
   * had no transport and modelled this as the device speaking. The network
   * ingress is where the human half is bound, and it is bound BEFORE the call:
   * `readIntendedUserEnrollment` refuses unless the authenticated session IS the
   * request's intended user, so a perfect signature carried by somebody else's
   * live session creates no verification row at all (C17-01).
   */
  async verifyPossession(
    principal: Principal,
    input: { organisationId: string; enrollmentRequestId: string; challengeId: string; response: unknown; traceId: string },
  ): Promise<VerifyPossessionOutcome | IngressRefused> {
    const bound = await this.bindIntendedUser(principal, input);
    if (bound !== null) return bound;
    return this.enrollment.verifyPossession(input);
  }

  async commitEnrollment(
    principal: Principal,
    input: { organisationId: string; enrollmentRequestId: string; challengeId: string; traceId: string },
  ): Promise<CommitEnrollmentOutcome | IngressRefused> {
    const bound = await this.bindIntendedUser(principal, input);
    if (bound !== null) return bound;
    return this.enrollment.commitEnrollment(principal, input);
  }

  // -------------------------------------------------------------------------
  // The bindings
  // -------------------------------------------------------------------------

  /**
   * C17-01/C17-02 — THE SESSION IS EQUALITY-BOUND BEFORE ANYTHING ENTERS SHIELD.
   *
   * Two comparisons, and both must hold:
   *
   *     the session's ORGANISATION  ===  the organisation being acted in
   *     the session's USER          ===  the grant's intended user
   *
   * The first is C17-02's tenant anchor: a lookup or an audit row must never be
   * keyed on a tenant a request merely NAMED. The second is D26-05: a device
   * credential must never become an implicit login and a login must never become
   * an implicit device, so the human who will hold this hardware is the human
   * whose session opens its ceremony.
   *
   * Returning BEFORE the first Shield call is the load-bearing part. Shield
   * would refuse most of these too — but some of its refusals write a security
   * event under the organisation they were told about, and an org-A session must
   * be unable to cause ANY row under org-B, refusal rows included.
   */
  private bindSession(
    principal: Principal,
    input: { organisationId: string; intendedUserId: string; traceId: string },
    phase: string,
  ): IngressRefused | null {
    if (principal.organisation_id !== input.organisationId) {
      this.refused(`${phase}_ORGANISATION_NOT_SESSION_TENANT`, input.traceId, null);
      return { outcome: 'REFUSED' };
    }
    if (principal.user.id !== input.intendedUserId) {
      this.refused(`${phase}_SESSION_IS_NOT_INTENDED_USER`, input.traceId, null);
      return { outcome: 'REFUSED' };
    }
    return null;
  }

  /** The tenant half alone, for the phases that name a ceremony rather than a user. */
  private bindCeremonySession(
    principal: Principal,
    input: { organisationId: string; traceId: string },
  ): IngressRefused | null {
    if (principal.organisation_id !== input.organisationId) {
      this.refused('CEREMONY_ORGANISATION_NOT_SESSION_TENANT', input.traceId, null);
      return { outcome: 'REFUSED' };
    }
    return null;
  }

  /**
   * The tenant half, plus "this session is the ceremony's intended user".
   *
   * The intended user is a SHIELD fact, so it is asked of Shield rather than
   * read out of an enrollment table by this module (D26-09). A foreign-tenant
   * request, another operative's request and an id that never existed all answer
   * the same refusal, which is the isolation rule Shield's own vocabulary is
   * built around.
   */
  private async bindIntendedUser(
    principal: Principal,
    input: { organisationId: string; enrollmentRequestId: string; traceId: string },
  ): Promise<IngressRefused | null> {
    const tenant = this.bindCeremonySession(principal, input);
    if (tenant !== null) return tenant;
    const view = await this.enrollment.readIntendedUserEnrollment(principal, {
      organisationId: input.organisationId,
      enrollmentRequestId: input.enrollmentRequestId,
    });
    if (view.outcome !== 'FOUND') {
      this.refused('SESSION_IS_NOT_INTENDED_USER', input.traceId, view.refusal);
      return { outcome: 'REFUSED' };
    }
    return null;
  }

  /**
   * One internal refusal line. A REASON CODE and a TRACE ID, and nothing else.
   *
   * There is no parameter here through which a secret could travel, which is a
   * stronger guarantee than remembering not to pass one — the same construction
   * `device-security-audit.ts` uses to make the bootstrap token unloggable.
   */
  private refused(reason: string, traceId: string, shieldRefusal: string | null): void {
    this.logger.warn(
      `device-enrollment-ingress refused: reason=${reason} trace_id=${traceId}` +
        (shieldRefusal === null ? '' : ` shield_refusal=${shieldRefusal}`),
    );
  }
}

/**
 * ===========================================================================
 * C18-03 — THE SUBMISSION FINGERPRINT, AND WHAT IT IS FOR.
 * ===========================================================================
 *
 * ONE VALUE THAT ANSWERS "IS THIS THE SAME SUBMISSION?"
 *
 * A consumed attestation challenge may only produce `CONVERGED` when the server
 * can prove that THIS EXACT submission already produced THAT EXACT enrollment
 * request. This digest is the "exact submission" half of that proof, and its
 * membership is chosen by one question: could two submissions differing in this
 * field be two different ceremonies? If yes, it is in.
 *
 *     the tenant, site and intended user     whose ceremony this is
 *     the bootstrap grant                    what a commander authorised
 *     the attestation challenge              which freshness value was answered
 *     the submitted public key               WHICH KEY is being enrolled
 *     the certificate chain, as submitted    the attestation artifact itself
 *     custody + régime + claimed profile     the terms the request is opened on
 *
 * The chain is digested AS SUBMITTED — the base64 text, not the decoded bytes —
 * so the fingerprint names exactly what arrived, for the reason the verifier's
 * own chain hash gives: a re-encoding is a different submission and must not be
 * mistaken for a retry of this one.
 *
 * WHAT IS DELIBERATELY ABSENT: the trace id, the bootstrap TOKEN, any clock, any
 * server-generated id. An honest retry re-sends the same body with a new trace
 * id, so anything varying between two identical retries would make every retry
 * look like a new ceremony and defeat the whole mechanism. The token is absent
 * for a different reason — the same one `device-security-audit.ts` keeps it out
 * of a log line: a one-shot secret has no business entering a value that will be
 * stored and compared. The grant ID it authorises is in the digest instead, and
 * the token itself has already been proved by `presentBootstrapGrantForCeremony`
 * before this is computed.
 *
 * THIS IS NOT A CREDENTIAL AND NOT A SUBSTITUTE FOR ONE. Presenting a matching
 * fingerprint authorises nothing: it is only ever read AFTER the session has
 * been equality-bound, the grant has been presented, and the challenge has been
 * proved to belong to that grant, site and intended user. It answers "same or
 * different", and nothing else.
 *
 * Every field is LENGTH-PREFIXED and labelled, so no two distinct submissions
 * can produce one digest by concatenation — the discipline the verifier's chain
 * hash uses, applied to a wider structure.
 */
function enrollmentSubmissionFingerprint(input: {
  organisationId: string;
  siteId: string;
  intendedUserId: string;
  bootstrapGrantId: string;
  attestationChallengeId: string;
  publicKey: string;
  claimedSignatureProfile: string;
  custody: string;
  custodyRegimeId: string | null;
  certificateChainBase64: readonly string[];
}): string {
  const digest = createHash('sha256');
  const field = (label: string, value: string): void => {
    digest.update(label, 'utf8');
    digest.update('=');
    digest.update(String(Buffer.byteLength(value, 'utf8')));
    digest.update('.');
    digest.update(value, 'utf8');
    digest.update('|');
  };

  // A VERSION TAG, first. When the membership above changes, this changes with
  // it, so a receipt written by an older server can never be matched by a
  // fingerprint a newer one computed over different fields.
  field('v', 'wp26.enrollment-submission.v1');
  field('org', input.organisationId);
  field('site', input.siteId);
  field('user', input.intendedUserId);
  field('grant', input.bootstrapGrantId);
  field('challenge', input.attestationChallengeId);
  field('key', input.publicKey);
  field('profile', input.claimedSignatureProfile);
  field('custody', input.custody);
  // Presence and value separately: `null` and a régime id are different
  // submissions, and an encoding in which one could be read as the other would
  // be an encoding in which they could converge on each other.
  field('regime_present', input.custodyRegimeId === null ? '0' : '1');
  field('regime', input.custodyRegimeId ?? '');
  field('chain_length', String(input.certificateChainBase64.length));
  for (const [index, certificate] of input.certificateChainBase64.entries()) {
    field(`chain_${index}`, certificate);
  }
  return digest.digest('hex');
}

/**
 * C18-03 — THE RECORDED OUTCOME OF A CONSUMED CHALLENGE, OR `null`.
 *
 * FAIL CLOSED IS THE DEFAULT AND EVERY BRANCH BELOW RETURNS TO IT.
 *
 * `null` means "this server cannot prove what that challenge produced", and the
 * caller turns that into the ordinary refusal. It is returned for a consumed
 * challenge that recorded no submission fingerprint, one whose fingerprint is
 * for a DIFFERENT submission (a retry with another public key, another custody,
 * another chain), and one whose recorded outcome is incomplete — which is what a
 * crash between the consume and the receipt leaves behind.
 *
 * There is no path here that reconstructs, re-derives or infers an outcome. It
 * either reads four recorded values and echoes them, or it declines.
 *
 * The comparison is a plain string equality and that is correct: both sides are
 * server-computed digests of data the server already holds, neither is a secret,
 * and there is no secret to leak through its timing. What an attacker would need
 * in order to reach this comparison at all is the intended user's live session,
 * the grant secret and the challenge id — at which point they are not guessing
 * a fingerprint, they are replaying a submission they already have.
 */
function resolveRecordedSubmission(
  challenge: {
    consumedAt: Date | null;
    submissionFingerprint: string | null;
    enrollmentRequestId: string | null;
    enrollmentRequestFingerprint: string | null;
    attestationOutcome: string | null;
    keyStorage: string | null;
  },
  submissionFingerprint: string,
): SubmitEnrollmentRequestOutcome | null {
  if (challenge.consumedAt === null) return null;
  if (challenge.submissionFingerprint === null) return null;
  if (challenge.submissionFingerprint !== submissionFingerprint) return null;

  const { enrollmentRequestId, enrollmentRequestFingerprint, attestationOutcome, keyStorage } = challenge;
  if (
    enrollmentRequestId === null ||
    enrollmentRequestFingerprint === null ||
    attestationOutcome === null ||
    keyStorage === null
  ) {
    return null;
  }
  // The stored key storage is re-parsed against the frozen contract rather than
  // cast. A column is a string; `DeviceKeyStorage` is a closed vocabulary, and a
  // value that is not in it is a row this code did not write.
  const storage = DeviceKeyStorageSchema.safeParse(keyStorage);
  if (!storage.success) return null;

  return {
    // WP-24's convergence arm, reached for WP-24's reason: the ceremony already
    // happened, and the client is being told what it already achieved.
    outcome: 'CONVERGED',
    enrollmentRequestId,
    requestFingerprint: enrollmentRequestFingerprint,
    attestationOutcome,
    keyStorage: storage.data,
  };
}
