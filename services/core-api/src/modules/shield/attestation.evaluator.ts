import { Injectable } from '@nestjs/common';
import type { DeviceAttestationEvidence } from '@sentinel/contracts';

/**
 * WP-24/D24-07 — THE SERVER-OWNED ATTESTATION SEAM.
 *
 * THIS IS A SEAM, NOT A VENDOR INTEGRATION, AND NOT A FAKE ONE EITHER.
 *
 * The shape is `WhisperDeviceKeyResolver`'s and so is the honesty: no Play
 * Integrity, no App Attest, no DeviceCheck, and — the part that matters — no
 * default implementation that invents a positive result so the tests look
 * nicer. WP-24 builds the internal evaluation seam WP-25/WP-26 will feed, plus
 * the append-only observation persistence beside it. A default that returned
 * VERIFIED would mean every device enrolled in this work package started life
 * TRUSTED on evidence nobody produced, which is exactly the manufactured
 * hardware trust §62.1 exists to forbid.
 *
 * C14-05'S SPLIT IS THE REASON `UNAVAILABLE` IS THE RIGHT DEFAULT
 * --------------------------------------------------------------
 *     VERIFIED                       positive evidence
 *     NEGATIVE / INVALID / REVOKED   device evidence; may lower trust
 *     UNAVAILABLE                    NOT device evidence
 *
 * A provider outage is not a statement about a device, and there is no
 * provider here at all — which is the same epistemic position as an outage,
 * not the same as a failure. Returning NEGATIVE would quarantine every device
 * on the strength of our own missing integration; returning VERIFIED would
 * vouch for hardware nobody has looked at. `UNAVAILABLE` is the one answer
 * that is true.
 *
 * The consequence is ruled by the contracts, not by this file:
 * `evaluateAttestationStanding` maps UNAVAILABLE with no prior verified result
 * to `INELIGIBLE`, and `initialDeviceTrustOnEnrollment` maps INELIGIBLE to
 * `DEGRADED`. So a device enrolled against this default operates every
 * ordinary path and simply cannot be TRUSTED — it cannot fire Whisper — until
 * a real provider is wired in. That is the correct posture and it required no
 * policy to be written here.
 *
 * D23-14: there is nowhere in this interface to put a raw attestation token.
 * The evidence type carries an OUTCOME, a server evaluation instant and an
 * opaque correlation reference, and a structure with nowhere to put a blob
 * cannot leak one into a fingerprint or an audit row.
 */
export interface DeviceAttestationEvaluator {
  /**
   * The platform's judgement about one piece of hardware, right now.
   *
   * `now` is the AUTHORITATIVE SERVER CLOCK, passed in rather than read here,
   * for the reason every other WP-24 service takes its time from the
   * transaction: an evaluation instant sourced from a second clock could
   * disagree with the instant the enrollment was judged against, and C15-07's
   * fail-closed parser would then be comparing two different timelines.
   *
   * An implementation must never throw to mean "no answer": an unreachable
   * provider is `UNAVAILABLE`, which is a real value with defined meaning. A
   * throw would leave a caller unable to tell an outage from a defect, and the
   * two have opposite trust consequences.
   */
  evaluate(input: DeviceAttestationEvaluationInput): Promise<DeviceAttestationEvidence>;
}

export interface DeviceAttestationEvaluationInput {
  readonly organisationId: string;
  /** Present when the subject is an already-enrolled device; `null` at enrollment. */
  readonly deviceId: string | null;
  /** Present when the subject is an enrollment in progress. */
  readonly enrollmentRequestId: string | null;
  /** The canonical thumbprint of the key whose hardware is being attested. */
  readonly publicKeyThumbprint: string;
  /** The authoritative server clock, as an ISO-8601 instant. */
  readonly now: string;
  /**
   * WP-26/D26-04B — A SERVER-OWNED REFERENCE TO A SERVER-OWNED EVALUATION.
   *
   * THIS IS NOT A CLIENT AUTHORITY FIELD, AND IT CANNOT BECOME ONE.
   *
   * The seam still carries no vendor blob and no verdict: D23-14's rule is
   * intact, and a structure with nowhere to put a raw attestation token still
   * cannot leak one into a fingerprint or an audit row. What this field carries
   * is an OPAQUE HANDLE the SERVER minted, naming a restricted provider record
   * the SERVER wrote after verifying a certificate chain itself. There is no
   * HTTP field, no contract member and no client-reachable path that sets it.
   *
   * `null` is the ordinary value and means "no server evaluation accompanies
   * this subject". Every caller that predates WP-26 passes `null`, and an
   * implementation must answer `null` exactly as it would have answered before
   * the field existed — `UnavailableDeviceAttestationEvaluator` does.
   *
   * An implementation that resolves a reference MUST re-bind it to this input's
   * `organisationId` and `publicKeyThumbprint` before believing it, and MUST
   * treat an unresolvable reference as `UNAVAILABLE` rather than as evidence of
   * anything. A handle that cannot be resolved is not a statement about a
   * device.
   *
   * The SEMANTICS of this interface are unchanged (D26-04B permits extending
   * the runtime seam and forbids changing what it means): an evaluator is still
   * asked what the platform thinks of one piece of hardware right now, it still
   * returns the frozen `DeviceAttestationEvidence`, and `UNAVAILABLE` is still
   * not device evidence.
   */
  readonly attestationArtifactRef: string | null;
}

/**
 * The Nest injection token.
 *
 * An interface has no runtime identity, so the token is explicit and exported
 * — which is the whole reason the evaluator is an injected collaborator rather
 * than a function a service calls directly. A test provides an evaluator that
 * returns VERIFIED or NEGATIVE and observes what the REGISTRY does with it,
 * without any test ever being able to reach into the trust rules themselves.
 */
export const DEVICE_ATTESTATION_EVALUATOR = Symbol('DEVICE_ATTESTATION_EVALUATOR');

/**
 * D24-07: the default, and the only implementation this work package ships.
 *
 * It evaluates NOTHING, and says so. The parameters it does read are the two
 * the evidence structure itself requires — a server instant and nothing else —
 * so the code cannot read as though a lookup were being performed.
 *
 * `attestation_reference` is `null` rather than some generated handle: a
 * correlation reference points at a provider record, and there is no provider
 * record to point at. Minting one would be a fabricated audit trail.
 */
@Injectable()
export class UnavailableDeviceAttestationEvaluator implements DeviceAttestationEvaluator {
  async evaluate(input: DeviceAttestationEvaluationInput): Promise<DeviceAttestationEvidence> {
    return {
      outcome: 'UNAVAILABLE',
      evaluated_at: input.now,
      attestation_reference: null,
    };
  }
}
