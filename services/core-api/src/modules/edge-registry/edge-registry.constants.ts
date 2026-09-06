import { DEVICE_SIGNATURE_PROFILES, type DeviceSignatureProfile } from '@sentinel/contracts';

/**
 * WP-29B / migration 26 — the Edge registry's named constants.
 *
 * Every timing ceiling this module obeys comes from `@sentinel/contracts`
 * (`EDGE_ENROLMENT_AUTHORITY_MAX_AGE_MS`, `EDGE_POSSESSION_CHALLENGE_MAX_AGE_MS`)
 * and is imported at the call site rather than restated here — a window this
 * service picked would be a security bound nobody reviews. What lives here is
 * the vocabulary: action strings, entropy sizes, ceremony labels and event
 * types.
 */

/**
 * THE TWO EDGE CAPABILITIES, AND THEY ARE NOT DEVICE CAPABILITIES.
 *
 * See the block in `identity/roles.ts`. Authorising a box that becomes the time
 * witness for a whole site is not the same power as issuing a phone grant, and
 * reusing `device.enrollment.issue` here would have handed it to everyone who
 * holds that.
 */
export const ACTION_EDGE_ENROLMENT_AUTHORISE = 'edge.enrolment.authorise';
export const ACTION_EDGE_REVOKE = 'edge.revoke';

/** >= 256 bits, base64url in transit, SHA-256 hex at rest. D24-03a's sizing. */
export const EDGE_AUTHORITY_SECRET_ENTROPY_BYTES = 32;
/** The one digest recipe for the enrolment secret. */
export const EDGE_AUTHORITY_SECRET_DIGEST_ALGORITHM = 'sha256';
/** base64url of 32 bytes -> 43 characters of unpredictable challenge. */
export const EDGE_CHALLENGE_NONCE_ENTROPY_BYTES = 32;

/**
 * Ceremony labels for `device_nonce_consumptions`. Shield's ONE anti-replay
 * store is reused with new labels rather than a second store being built
 * beside it (the WP-25/D25-10 precedent): the label is an operator's view of
 * which ceremony burned an identity and is deliberately NOT part of the
 * uniqueness, which is `(organisation_id, replay_identity_digest)`.
 */
export const CEREMONY_EDGE_ENROLMENT_AUTHORITY = 'EDGE_ENROLMENT_AUTHORITY';
export const CEREMONY_EDGE_POSSESSION_CHALLENGE = 'EDGE_POSSESSION_CHALLENGE';

/** SERVER-selected, and the only thing that ever selects a verifier (C15-01). */
export const EDGE_SERVER_SELECTED_SIGNATURE_PROFILE: DeviceSignatureProfile = DEVICE_SIGNATURE_PROFILES[0];

export const EDGE_SECURITY_EVENT_TYPES = [
  'EDGE_AUTHORITY_ISSUED',
  'EDGE_AUTHORITY_REVOKED',
  'EDGE_AUTHORITY_CONSUMED',
  'EDGE_AUTHORITY_REFUSED',
  'EDGE_ENROLMENT_REQUESTED',
  'EDGE_ENROLMENT_REFUSED',
  'EDGE_POSSESSION_VERIFIED',
  'EDGE_POSSESSION_REFUSED',
  'EDGE_ENROLLED',
  'EDGE_WITHDRAWN',
  'EDGE_REPLAY_CONFLICT',
] as const;
export type EdgeSecurityEventType = (typeof EDGE_SECURITY_EVENT_TYPES)[number];

/** `edges.enrolment_state`. The contract owns the vocabulary and the transitions. */
export const EDGE_STATE_PENDING = 'PENDING';
export const EDGE_STATE_ACTIVE = 'ACTIVE';
export const EDGE_STATE_WITHDRAWN = 'WITHDRAWN';

/** `edges.edge_trust` — the frozen `DeviceEdgeTrustStatusSchema` values. */
export const EDGE_TRUST_TRUSTED = 'TRUSTED';
export const EDGE_TRUST_SUSPENDED = 'SUSPENDED';
export const EDGE_TRUST_REVOKED = 'REVOKED';

/** `edge_enrolment_requests.state`. */
export const EDGE_REQUEST_STATE_PENDING = 'PENDING';
export const EDGE_REQUEST_STATE_ACTIVATED = 'ACTIVATED';
export const EDGE_REQUEST_STATE_REJECTED = 'REJECTED';
