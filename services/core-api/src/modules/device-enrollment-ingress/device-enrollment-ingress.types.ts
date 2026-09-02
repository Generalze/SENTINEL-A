import type { DeviceKeyStorage } from '@sentinel/contracts';

/**
 * WP-26 device enrollment ingress result types.
 *
 * EVERY OUTCOME IS DATA, NEVER AN EXCEPTION — the WP-24 discipline, inherited
 * for the WP-24 reason. A thrown error carries a message, a message reaches a
 * log, and this surface sits in front of a security ceremony whose refusal
 * reasons would be an ORACLE if a device were ever handed one.
 *
 * NOTE WHAT THE REFUSED ARM DOES NOT CARRY: a reason. Shield keeps a granular
 * refusal vocabulary because a HUMAN operator reads it; this module's refused
 * shape has no reason field at all, because the only consumer of these values
 * is a controller that turns every one of them into the same external answer
 * (D25-13, applied to the pre-registration surface). The precise reason is
 * written to the internal reason log inside the service, where an operator can
 * read it and an attacker cannot — and it cannot travel outward through a
 * structure that has nowhere to put it.
 */
export interface IngressRefused {
  readonly outcome: 'REFUSED';
}

/**
 * D26-04A: an issued attestation challenge.
 *
 * `challengeValue` IS returned to the caller, and that is correct: it is a
 * freshness value, not a secret. The phone must embed it in the key it is about
 * to generate, so a server that would not hand it over could not use Key
 * Attestation at all. Everything that makes the ceremony safe — the grant
 * secret, the intended user's session, the StrongBox private key, the
 * independent commander's approval — is somewhere else.
 */
export type IssueAttestationChallengeOutcome =
  | {
      readonly outcome: 'ISSUED';
      readonly attestationChallengeId: string;
      /** >= 256 bits of server randomness, canonical unpadded base64url. */
      readonly challengeValue: string;
      /** EXCLUSIVE, and clamped so it can never outlive the bootstrap grant. */
      readonly expiresAt: Date;
    }
  | IngressRefused;

/**
 * The enrollment request Shield opened, as the phone may see it.
 *
 * `requestFingerprint` is here because the operative's own client legitimately
 * shows it: it is the value a commander will be asked to confirm out of band,
 * and a ceremony in which the two humans cannot compare the same value is a
 * ceremony in which the approval means less. It is not a credential — approving
 * it requires `device.enrollment.approve` at the site, a different human from
 * both the issuer and the intended user, and a Command-side route the phone
 * cannot reach.
 *
 * `keyStorage` is the SERVER's conclusion, echoed so the client can tell its
 * operative plainly that the device did not attest as StrongBox and will
 * therefore never be TRUSTED (D23-03/D26-02). There is no request field it
 * corresponds to.
 *
 * THE RAW CERTIFICATE CHAIN IS NOT HERE, AND CANNOT BE. Nothing in this type,
 * and nothing on any route in this module, can carry it.
 */
export type SubmitEnrollmentRequestOutcome =
  | {
      /** `REQUESTED`, or WP-24's `CONVERGED` arm for a byte-identical retry. */
      readonly outcome: 'REQUESTED' | 'CONVERGED';
      readonly enrollmentRequestId: string;
      readonly requestFingerprint: string;
      /** VERIFIED | NEGATIVE | INVALID | REVOKED | UNAVAILABLE, as the server concluded. */
      readonly attestationOutcome: string;
      readonly keyStorage: DeviceKeyStorage;
    }
  | IngressRefused;
