import { describe, expect, it } from 'vitest';
import type { Principal } from '../../common/security/principal';
import type { DeviceEnrollmentService } from '../shield/device-enrollment.service';
import type { P256KeyImporter } from '../shield/p256-key.importer';
import type { AndroidKeyAttestationVerifier } from './android-key-attestation.verifier';
import { DeviceEnrollmentIngressService } from './device-enrollment-ingress.service';
import type { DeviceEnrollmentIngressRepository } from './device-enrollment-ingress.repository';

/**
 * ============================================================================
 * WP-26/C18-R1 — THE LOSER OF THE FENCED CONSUME, DETERMINISTICALLY.
 *
 * WHY THIS SPEC EXISTS AND WHY IT IS NOT IN THE CRUCIBLE.
 *
 * `submitEnrollmentRequest` has two doors into the recorded-submission
 * resolver. The first — the courtesy read of an already-consumed challenge — is
 * driven end to end over real HTTP by the acceptance suite. The second is
 * reached ONLY when the fenced `UPDATE ... WHERE consumed_at IS NULL` finds no
 * row, i.e. when another submission consumed the challenge in the microseconds
 * between this request's read and its write. Before C18-R1 that door led to an
 * unconditional refusal; it now leads to the same three-way answer as the
 * first, and the whole point of the correction is what the loser is told.
 *
 * THAT WINDOW CANNOT BE OPENED HONESTLY OVER HTTP ON ONE NODE PROCESS. Two
 * genuinely simultaneous POSTs do not interleave inside it: the winner's
 * certificate-chain verification is synchronous work on the single event loop,
 * so the loser's request is not even parsed until the winner has finished, and
 * it converges through the FIRST door instead. The acceptance suite asserts
 * exactly that — one request, one artifact, never a terminal refusal — and it
 * is a true and useful fact, but it is not this branch. A regression that
 * claimed to cover this branch by racing two HTTP calls would be a regression
 * that passes without ever executing the line it names.
 *
 * SO THIS DRIVES THE SERVICE DIRECTLY, WITH THE FENCE FORCED TO LOSE. Nothing
 * here stubs a security decision: the fakes are a grant that is usable, a clock,
 * a row store, and a consume that returns `false` — which is precisely what
 * Postgres returns to the loser. The RULE under test is the service's own.
 *
 * THE FINGERPRINT IS NEVER RECOMPUTED HERE. The fake consume CAPTURES the
 * fingerprint the service passes it — which is what the winning statement would
 * have stamped on the row — and the re-read hands that same value back. A test
 * that reimplemented the digest would be testing its own copy of it.
 * ============================================================================
 */

const ORG = 'org-race';
const SITE = 'site-race';
const USER = 'user-race';
const GRANT = 'grant-race';
const CHALLENGE = 'challenge-race';

const principal: Principal = {
  user: { id: USER, clearance: 5 },
  organisation_id: ORG,
  roles: [],
  hasAction: () => false,
};

interface ChallengeRow {
  id: string;
  organisationId: string;
  siteId: string;
  intendedUserId: string;
  bootstrapGrantId: string;
  challengeValue: string;
  issuedAt: Date;
  expiresAt: Date;
  consumedAt: Date | null;
  submissionFingerprint: string | null;
  enrollmentRequestId: string | null;
  enrollmentRequestFingerprint: string | null;
  attestationOutcome: string | null;
  keyStorage: string | null;
}

function freshRow(): ChallengeRow {
  const now = new Date();
  return {
    id: CHALLENGE,
    organisationId: ORG,
    siteId: SITE,
    intendedUserId: USER,
    bootstrapGrantId: GRANT,
    challengeValue: 'Y2hhbGxlbmdl',
    issuedAt: now,
    expiresAt: new Date(now.getTime() + 120_000),
    consumedAt: null,
    submissionFingerprint: null,
    enrollmentRequestId: null,
    enrollmentRequestFingerprint: null,
    attestationOutcome: null,
    keyStorage: null,
  };
}

/**
 * The ONE input body, reused byte for byte, because a lost-response retry and a
 * simultaneous duplicate are the same bytes arriving twice.
 */
function submission() {
  return {
    organisationId: ORG,
    siteId: SITE,
    intendedUserId: USER,
    bootstrapToken: 'bootstrap-secret',
    attestationChallengeId: CHALLENGE,
    publicKey: 'AQIDBAUGBwgJCgsMDQ4PEA',
    claimedSignatureProfile: 'P256_ECDSA_SHA256' as const,
    custody: 'PERSONAL' as const,
    custodyRegimeId: null,
    certificateChainBase64: ['bGVhZg', 'cm9vdA'],
    traceId: 'trace-race',
  };
}

/**
 * The service, wired to a row store whose fenced consume ALWAYS LOSES.
 *
 * Counters on the collaborators the loser must never reach. `UNKNOWN` and
 * `CONVERGED` are both served entirely from recorded state, so a single call to
 * the verifier, the artifact writer or Shield is a failure of the property, not
 * a detail of the fake.
 */
function serviceWithLosingFence(row: ChallengeRow) {
  const calls = { verify: 0, artifact: 0, shield: 0, importKey: 0, recordOutcome: 0 };

  const repository = {
    now: async () => new Date(),
    findAttestationChallenge: async (organisationId: string, challengeId: string) =>
      organisationId === row.organisationId && challengeId === row.id ? { ...row } : null,
    // THE FENCE, LOST. Postgres would return count 0 to the loser of two
    // simultaneous consumes; this returns `false` for the same reason, and
    // records the fingerprint the WINNER would have stamped.
    consumeAttestationChallenge: async (
      _organisationId: string,
      _challengeId: string,
      at: Date,
      submissionFingerprint: string,
    ) => {
      row.consumedAt = at;
      row.submissionFingerprint = submissionFingerprint;
      return false;
    },
    recordEnrollmentOutcome: async () => {
      calls.recordOutcome += 1;
      return true;
    },
    recordAttestationArtifact: async () => {
      calls.artifact += 1;
      return 'artifact-should-not-exist';
    },
  } as unknown as DeviceEnrollmentIngressRepository;

  const enrollment = {
    presentBootstrapGrantForCeremony: async () => ({
      outcome: 'USABLE' as const,
      grantId: GRANT,
      siteId: SITE,
      intendedUserId: USER,
      expiresAt: new Date(Date.now() + 600_000),
    }),
    createEnrollmentRequest: async () => {
      calls.shield += 1;
      throw new Error('the loser of the fence must never reach Shield');
    },
  } as unknown as DeviceEnrollmentService;

  const keys = {
    importPublicKey: () => {
      calls.importKey += 1;
      return null;
    },
  } as unknown as P256KeyImporter;

  const verifier = {
    verify: async () => {
      calls.verify += 1;
      throw new Error('the loser of the fence must never re-verify');
    },
  } as unknown as AndroidKeyAttestationVerifier;

  return { service: new DeviceEnrollmentIngressService(enrollment, keys, verifier, repository), calls, row };
}

describe('WP-26/C18-R1 the loser of the fenced consume is answered, never refused', () => {
  it('answers UNKNOWN while the winner has not yet written its receipt, and creates nothing', async () => {
    // THE STATE: the winner has stamped `consumed_at` and the submission
    // fingerprint in one statement, and has not yet recorded what Shield
    // produced. That is not "this did not happen" — the row already PROVES this
    // exact submission spent this challenge — so it must not be a refusal.
    const { service, calls, row } = serviceWithLosingFence(freshRow());

    const outcome = await service.submitEnrollmentRequest(principal, submission());

    expect(outcome.outcome).toBe('UNKNOWN');
    // Nothing else is on the shape. There is no id, no fingerprint and no
    // verdict to leak, because `IngressCompletionUnknown` has nowhere to put one.
    expect(Object.keys(outcome)).toEqual(['outcome']);

    // ZERO ADDITIONAL WORK. No re-import, no re-verification, no second
    // artifact, no second Shield request, no receipt write.
    expect(calls).toEqual({ verify: 0, artifact: 0, shield: 0, importKey: 0, recordOutcome: 0 });
    // The fingerprint the winner stamped is exactly what this submission
    // computes, which is why the row resolves to UNKNOWN rather than a refusal.
    expect(row.submissionFingerprint).not.toBeNull();
  });

  it('answers CONVERGED once the winner has written its receipt', async () => {
    const { service, calls, row } = serviceWithLosingFence(freshRow());

    // First pass: the winner is still working.
    expect((await service.submitEnrollmentRequest(principal, submission())).outcome).toBe('UNKNOWN');

    // The winner finishes. Its receipt is now on the row, written once.
    row.enrollmentRequestId = 'enrollment-request-race';
    row.enrollmentRequestFingerprint = 'fingerprint-race';
    row.attestationOutcome = 'VERIFIED';
    row.keyStorage = 'HARDWARE_BACKED';

    const converged = await service.submitEnrollmentRequest(principal, submission());
    expect(converged).toEqual({
      outcome: 'CONVERGED',
      enrollmentRequestId: 'enrollment-request-race',
      requestFingerprint: 'fingerprint-race',
      attestationOutcome: 'VERIFIED',
      keyStorage: 'HARDWARE_BACKED',
    });
    // Still nothing created, on either pass.
    expect(calls).toEqual({ verify: 0, artifact: 0, shield: 0, importKey: 0, recordOutcome: 0 });
  });

  it('answers a TERMINAL refusal when the challenge was spent by a DIFFERENT submission', async () => {
    // The one-shot rule, unchanged and unsoftened. A changed key, custody,
    // régime or chain under a spent challenge is a second ceremony wearing a
    // spent nonce; it is not ambiguous and it must never become UNKNOWN.
    const row = freshRow();
    const { service, calls } = serviceWithLosingFence(row);

    const first = await service.submitEnrollmentRequest(principal, submission());
    expect(first.outcome).toBe('UNKNOWN');
    expect(row.submissionFingerprint).not.toBeNull();

    // The row now says the challenge was spent by SOMEBODY ELSE's submission.
    row.submissionFingerprint = 'a-fingerprint-from-another-ceremony';
    const refused = await service.submitEnrollmentRequest(principal, submission());
    expect(refused.outcome).toBe('REFUSED');
    expect(calls).toEqual({ verify: 0, artifact: 0, shield: 0, importKey: 0, recordOutcome: 0 });
  });

  it('answers a TERMINAL refusal when the row is consumed with NO recorded fingerprint', async () => {
    // Structural, not a policy choice: the fingerprint is stamped by the SAME
    // fenced statement that consumes the challenge, so a consumed row without
    // one is not a row this code wrote. There is nothing in flight to wait for.
    const row = freshRow();
    const { service } = serviceWithLosingFence(row);

    expect((await service.submitEnrollmentRequest(principal, submission())).outcome).toBe('UNKNOWN');
    row.submissionFingerprint = null;
    expect((await service.submitEnrollmentRequest(principal, submission())).outcome).toBe('REFUSED');
  });

  it('answers a TERMINAL refusal when the recorded attestation outcome is outside its contract (C18-R2)', async () => {
    const row = freshRow();
    const { service } = serviceWithLosingFence(row);

    expect((await service.submitEnrollmentRequest(principal, submission())).outcome).toBe('UNKNOWN');
    row.enrollmentRequestId = 'enrollment-request-race';
    row.enrollmentRequestFingerprint = 'fingerprint-race';
    row.keyStorage = 'HARDWARE_BACKED';

    for (const forged of ['TOTALLY_VERIFIED', 'verified', 'VERIFIED ', '', 'null']) {
      row.attestationOutcome = forged;
      const answer = await service.submitEnrollmentRequest(principal, submission());
      expect(answer.outcome, `stored outcome '${forged}'`).toBe('REFUSED');
    }

    // And the same for the other re-parsed column, so neither is alone.
    row.attestationOutcome = 'VERIFIED';
    row.keyStorage = 'STRONGBOX_OBVIOUSLY';
    expect((await service.submitEnrollmentRequest(principal, submission())).outcome).toBe('REFUSED');

    // Both valid again: it converges, so the refusals above were about the
    // stored values and not about anything else this fake did.
    row.keyStorage = 'SOFTWARE';
    expect((await service.submitEnrollmentRequest(principal, submission())).outcome).toBe('CONVERGED');
  });
});
