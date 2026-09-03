import { Inject, Injectable } from '@nestjs/common';
import type { DeviceAttestationEvidence, DeviceAttestationOutcome } from '@sentinel/contracts';
import { DeviceAttestationOutcomeSchema } from '@sentinel/contracts';
import type { DeviceAttestationEvaluationInput, DeviceAttestationEvaluator } from '../shield/attestation.evaluator';
import { AndroidAttestationArtifactReader } from './android-attestation.artifact-reader';

/**
 * ============================================================================
 * WP-26/D26-04B — THE REAL PROVIDER BEHIND SHIELD'S ATTESTATION SEAM.
 *
 * `UnavailableDeviceAttestationEvaluator` said, in its own header, that it
 * evaluates nothing and returns `UNAVAILABLE` "precisely until a real provider
 * existed". This is that provider — and it is DELIBERATELY NOT the verifier.
 *
 * WHY THIS CLASS DOES NO CRYPTOGRAPHY
 * -----------------------------------
 * `DeviceAttestationEvaluationInput` carries an organisation, optional
 * identifiers, a public-key thumbprint and a server instant. It does not carry a
 * certificate chain, and D26-04B is explicit that this is NOT a gap to be fixed
 * by stuffing a base64 blob into a frozen contract. So the chain is verified
 * ONCE, at the ingress, before anything enters Shield; the result is persisted
 * as a server-owned `AndroidKeyAttestationArtifact`; and what crosses into
 * Shield is an OPAQUE SERVER-GENERATED REFERENCE. This class resolves that
 * reference back to the verdict the server itself reached.
 *
 * WHY THAT IS SAFE EVEN THOUGH THE REFERENCE IS A PARAMETER
 * ---------------------------------------------------------
 * `attestationArtifactRef` is a SERVER-OWNED field on a SERVER-INTERNAL input
 * type — there is no HTTP field, no contract member and no client-reachable
 * path that can set it. But the interesting question is what happens if a
 * future caller passes one anyway, so this class is written so that the answer
 * does not matter:
 *
 *   * a `null` reference returns EXACTLY what the default evaluator returns —
 *     `UNAVAILABLE`, no reference, the caller's own instant. Every existing
 *     Shield caller, including `DeviceTrustService`'s re-attestation path, is
 *     therefore unchanged, byte for byte;
 *   * a reference that is not a UUID resolves to nothing;
 *   * a reference belonging to ANOTHER TENANT resolves to nothing — the lookup
 *     is keyed on the organisation the caller is acting in (C17-02);
 *   * a reference minted for a DIFFERENT KEY resolves to nothing — the stored
 *     `public_key_thumbprint` is equality-bound against the thumbprint the
 *     evaluation is about (C15-02: the thumbprint is computed from the key,
 *     never believed);
 *   * "resolves to nothing" is `UNAVAILABLE`, never `VERIFIED` and never
 *     `NEGATIVE`. A reference we cannot resolve is not a statement about a
 *     device; it is the same epistemic position as an outage.
 *
 * So to obtain a VERIFIED out of this class you must present a reference to an
 * artifact THE SERVER ITSELF created, in THIS tenant, for THIS EXACT KEY — which
 * means the server already verified that key's chain against pinned trust
 * anchors and a fresh revocation snapshot. Holding the reference confers
 * nothing that was not already true.
 *
 * IT NEVER READS THE RAW CHAIN. `AndroidAttestationArtifactReader` does not select
 * `certificate_chain_der`. What cannot be loaded cannot be leaked into an
 * evidence structure, an audit payload or a log.
 *
 * IT NEVER THROWS TO MEAN "NO ANSWER" — the seam's own rule. A database fault
 * on this path is an outage, and an outage is `UNAVAILABLE`.
 * ============================================================================
 */
@Injectable()
export class AndroidKeyAttestationEvaluator implements DeviceAttestationEvaluator {
  constructor(@Inject(AndroidAttestationArtifactReader) private readonly artifacts: AndroidAttestationArtifactReader) {}

  async evaluate(input: DeviceAttestationEvaluationInput): Promise<DeviceAttestationEvidence> {
    const reference = input.attestationArtifactRef;

    // No server-owned artifact: the honest answer is the one WP-24 shipped.
    // `attestation_reference` stays NULL rather than becoming some generated
    // handle, because a correlation reference points at a provider record and
    // there is no provider record to point at. Minting one would be a fabricated
    // audit trail.
    // `typeof`, not `!== null`. The field is typed `string | null`, and this
    // path is reached from a JavaScript caller that may predate it — an absent
    // property arrives as `undefined`, and "the caller did not set it" must
    // answer exactly as "the caller set it to null" does. Anything that is not
    // a string is not a reference.
    if (typeof reference !== 'string') return unavailable(input.now);
    if (!isUuid(reference)) return unavailable(input.now);

    let artifact;
    try {
      artifact = await this.artifacts.readVerdict(input.organisationId, reference);
    } catch {
      return unavailable(input.now);
    }
    if (artifact === null) return unavailable(input.now);

    // THE RE-BINDING. An artifact is evidence about ONE key in ONE tenant, and
    // this is where that stops being a comment and becomes a comparison.
    if (artifact.publicKeyThumbprint !== input.publicKeyThumbprint) return unavailable(input.now);

    // The stored outcome is re-parsed against the FROZEN vocabulary rather than
    // cast. A column is storage; the contract is the authority. A value that is
    // not a member of `DeviceAttestationOutcomeSchema` is not an outcome to
    // interpret leniently — it is a row this code cannot read, which is an
    // outage of our own making and answers UNAVAILABLE.
    const parsed = DeviceAttestationOutcomeSchema.safeParse(artifact.outcome);
    if (!parsed.success) return unavailable(input.now);
    const outcome: DeviceAttestationOutcome = parsed.data;

    return {
      outcome,
      // THE CALLER'S INSTANT, not the artifact's. `evaluated_at` on the frozen
      // evidence means "the instant this evaluation was made against", and the
      // enrollment ceremony judges freshness against ONE clock — the one the
      // transaction handed in. Returning the artifact's own instant would put a
      // second timeline inside a structure C15-07's fail-closed parser compares
      // against the first. The artifact keeps its own `evaluated_at` column, so
      // nothing is lost: the two are available side by side to an auditor and
      // are never conflated in a decision.
      evaluated_at: input.now,
      attestation_reference: artifact.id,
    };
  }
}

function unavailable(now: string): DeviceAttestationEvidence {
  return { outcome: 'UNAVAILABLE', evaluated_at: now, attestation_reference: null };
}

/**
 * The canonical UUID shape.
 *
 * Checked before the query rather than after, because the artifact id column is
 * a Postgres `uuid` and handing the driver a non-UUID string is a FAULT rather
 * than a miss. A caller must not be able to turn "that reference is malformed"
 * into a thrown error inside a security ceremony.
 */
function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(value);
}
