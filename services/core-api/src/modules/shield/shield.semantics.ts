import { canonicalDeviceJson, deviceCanonicalDigest, type DeviceCustody } from '@sentinel/contracts';

/**
 * WP-24/C16-01 — THE APPROVED-SEMANTICS DIGEST, AND WHY WP-24 OWNS IT.
 *
 * THE HOLE IT CLOSES
 * ------------------
 * `custodyRegimeId` used to arrive as a parameter to `commitEnrollment`. The
 * human approval binds `deviceEnrollmentRequestFingerprint`, which is computed
 * over `DeviceEnrollmentRequestSchema` — and that frozen schema HAS NO REGIME
 * FIELD. It also records the custody MODE. So an approval said, precisely:
 *
 *     "I approve these exact request bytes, and this custody mode."
 *
 * and said nothing at all about WHICH controlled-shared regime would govern the
 * hand-over of the device that ceremony produced. A commit could therefore be
 * driven under a regime the approver never saw, and nothing in the ceremony
 * could detect it.
 *
 * WHY THE FIX IS NOT A CONTRACT CHANGE
 * ------------------------------------
 * WP-23 is CLOSED. Adding `custody_regime_id` to `DeviceEnrollmentRequestSchema`
 * would change a frozen fingerprint recipe, which is not a correction this work
 * package may make. So the binding is made at the layer that actually owns the
 * regime catalogue: WP-24 computes a SECOND digest that covers the frozen
 * fingerprint AND the regime, persists it on the request and on the approval,
 * and the commit requires the two to agree.
 *
 * It is DOMAIN-SEPARATED, like every other statement in this system. The domain
 * string is part of the canonical object, so this digest can never collide with
 * a WP-23 statement digest even if the remaining fields were somehow arranged
 * to match.
 *
 * IT USES THE CONTRACT'S CANONICALISATION, DELIBERATELY
 * ----------------------------------------------------
 * `canonicalDeviceJson`/`deviceCanonicalDigest` are imported rather than
 * reimplemented so this digest inherits WP-23's canonicalisation discipline
 * whole: recursive key sorting, preserved array order, and a REFUSAL rather
 * than a normalisation for anything not losslessly representable. A second,
 * WP-24-local JSON recipe would be a second canonicalisation nobody reviews as
 * one, and the two would drift the first time either changed.
 *
 * WHAT IT IS NOT
 * --------------
 * It is not a replacement for the frozen request fingerprint and it does not
 * re-derive one. It CONTAINS the fingerprint, so it can only ever be a
 * strictly narrower statement than the approval already made.
 */

/** The domain separator. Versioned, so a future shape is a new statement rather than a silent change. */
export const APPROVED_ENROLLMENT_SEMANTICS_DOMAIN = 'sentinel.shield.approved-enrollment-semantics.v1';

export interface ApprovedEnrollmentSemantics {
  /** The frozen `deviceEnrollmentRequestFingerprint` of the request being approved. */
  readonly enrollmentRequestFingerprint: string;
  readonly custody: DeviceCustody;
  /** CONTROLLED_SHARED only. `null` is a MEANINGFUL value here, not an absence. */
  readonly custodyRegimeId: string | null;
}

/**
 * The canonical object, exposed so a test (and an operator reading an audit)
 * can see exactly what is being digested rather than inferring it from a hash.
 * C15-05's rule, applied here: a hash is not an identity.
 */
export function canonicalApprovedEnrollmentSemantics(input: ApprovedEnrollmentSemantics): string {
  return canonicalDeviceJson({
    domain: APPROVED_ENROLLMENT_SEMANTICS_DOMAIN,
    enrollment_request_fingerprint: input.enrollmentRequestFingerprint,
    custody: input.custody,
    custody_regime_id: input.custodyRegimeId,
  });
}

/** SHA-256 hex over the canonical form above, via the contract's one digest recipe. */
export function approvedEnrollmentSemanticsDigest(input: ApprovedEnrollmentSemantics): string {
  return deviceCanonicalDigest({
    domain: APPROVED_ENROLLMENT_SEMANTICS_DOMAIN,
    enrollment_request_fingerprint: input.enrollmentRequestFingerprint,
    custody: input.custody,
    custody_regime_id: input.custodyRegimeId,
  });
}
