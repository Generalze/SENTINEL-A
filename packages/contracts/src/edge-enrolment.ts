import { z } from 'zod';
import { canonicalDeviceJson, deviceCanonicalDigest } from './device-identity.js';
import { DeviceSignatureProfileSchema, type DeviceSignatureProfile } from './device-signature.js';

/**
 * WP-29B / migration 26 — THE EDGE ENROLMENT CEREMONY'S SIGNED BYTES.
 *
 * `device-offline.ts` froze what an Edge registry record IS
 * (`EdgeRegistryKeyRecordSchema`) and said nothing about how one comes to
 * exist, because WP-23 was contracts only. This module is the missing half:
 * the exact bytes an enrolling Edge signs, and the one-shot identities the
 * ceremony spends.
 *
 * WHY THIS IS NOT `canonicalDevicePossessionStatement`
 * ----------------------------------------------------
 * The device possession statement is the obvious thing to reuse, and reusing
 * it would be the defect. Its domain separator names a DEVICE enrolment; a
 * signature over those bytes proves possession in a ceremony that registers a
 * phone. If an Edge signed the same shape, then a signature captured from one
 * ceremony could be replayed into the other wherever the field names happen to
 * line up — which is the entire class of attack domain separation exists to
 * remove, and C11-01 is explicit that the tag lives INSIDE the signed bytes
 * rather than beside them.
 *
 * The two ceremonies also bind different facts. A device proves possession
 * inside a tenancy a human already fixed by approving the request. An Edge
 * proves possession of a key that is about to become a TIME WITNESS for one
 * site — so the site, the tenant and the Edge identity are all inside the
 * signed bytes, and a proof produced for site X cannot activate a registry
 * record for site Y even if every other value matched.
 */

const scopedId = z.string().min(1).max(256);

/** Domain separator for the Edge enrolment request's identity. */
export const EDGE_ENROLMENT_REQUEST_DOMAIN = 'sentinel.edge.enrolment-request.v1';

/** Domain separator for the possession statement an enrolling Edge signs. */
export const EDGE_ENROLMENT_POSSESSION_DOMAIN = 'sentinel.edge.enrolment-possession.v1';

/** Domain separator for the enrolment authority's one-shot identity. */
export const EDGE_ENROLMENT_AUTHORITY_REPLAY_IDENTITY_DOMAIN = 'sentinel.edge.enrolment-authority.replay-identity.v1';

/** Domain separator for the possession challenge's one-shot identity. */
export const EDGE_ENROLMENT_POSSESSION_REPLAY_IDENTITY_DOMAIN = 'sentinel.edge.enrolment-possession.replay-identity.v1';

/**
 * What an enrolment request IS, for fingerprinting purposes.
 *
 * The fingerprint is bound into the possession verdict, so a verdict produced
 * against one request cannot be presented for another — the C15-03 argument,
 * applied to Edge. Note what is absent: no instants, and nothing the requester
 * chose freely. Every field is either server-resolved or the key material
 * itself, so two requests with the same fingerprint really are the same
 * request.
 */
export const EdgeEnrolmentRequestIdentitySchema = z
  .object({
    schema_version: z.literal(1),
    organisation_id: scopedId,
    /** SERVER-resolved from the authority, never accepted from the Edge. */
    site_id: scopedId,
    authority_id: scopedId,
    edge_id: scopedId,
    /** The offered key, named by its computed digest rather than carried. */
    public_key_thumbprint: scopedId,
    /** SERVER-selected (C15-01). The Edge does not choose its verifier. */
    signature_profile: DeviceSignatureProfileSchema,
  })
  .strict();
export type EdgeEnrolmentRequestIdentity = z.infer<typeof EdgeEnrolmentRequestIdentitySchema>;

function edgeEnrolmentRequestObject(identity: EdgeEnrolmentRequestIdentity): Record<string, unknown> {
  return {
    domain: EDGE_ENROLMENT_REQUEST_DOMAIN,
    schema_version: identity.schema_version,
    organisation_id: identity.organisation_id,
    site_id: identity.site_id,
    authority_id: identity.authority_id,
    edge_id: identity.edge_id,
    public_key_thumbprint: identity.public_key_thumbprint,
    signature_profile: identity.signature_profile,
  };
}

/** Domain-tagged canonical JSON. C11-01: never a delimiter join. */
export function canonicalEdgeEnrolmentRequestStatement(identity: EdgeEnrolmentRequestIdentity): string {
  return canonicalDeviceJson(edgeEnrolmentRequestObject(identity));
}

export function edgeEnrolmentRequestFingerprint(identity: EdgeEnrolmentRequestIdentity): string {
  return deviceCanonicalDigest(edgeEnrolmentRequestObject(identity));
}

/**
 * EXACTLY what the enrolling Edge signs.
 *
 * Every field is a BINDING, and each closes a specific substitution:
 *
 *   `challenge_id` + `nonce`      — this challenge, which the SERVER chose. An
 *                                   Edge that could pick what it signs could
 *                                   pre-compute an answer.
 *   `enrolment_request_id`        — this ceremony. A proof for request A cannot
 *     + `..._fingerprint`           activate request B, and a request whose
 *                                   contents changed after the challenge was
 *                                   issued no longer matches its own
 *                                   fingerprint.
 *   `public_key_thumbprint`       — THIS key. A proof made with a different
 *                                   key names a different thumbprint, so a
 *                                   genuine proof of some other key cannot
 *                                   activate this registry record.
 *   `edge_id` + `organisation_id` — this principal, in this tenant, AT THIS
 *     + `site_id`                   SITE. The coordinate an Edge receipt is
 *                                   later judged against; binding it here is
 *                                   what makes "a proof from site X cannot
 *                                   produce a record for site Y" a property of
 *                                   the bytes rather than of a comparison.
 *   `signature_profile`           — C15-01: the SERVER's selected profile, so
 *                                   the statement means "signed under the
 *                                   profile the platform chose". A statement
 *                                   binding the Edge's claim would let it sign
 *                                   under one profile while the server verified
 *                                   under another.
 */
export interface EdgeEnrolmentPossessionStatementInput {
  readonly challenge_id: string;
  readonly enrolment_request_id: string;
  readonly enrolment_request_fingerprint: string;
  readonly nonce: string;
  readonly public_key_thumbprint: string;
  readonly edge_id: string;
  readonly organisation_id: string;
  readonly site_id: string;
  readonly signature_profile: DeviceSignatureProfile;
}

function edgeEnrolmentPossessionObject(input: EdgeEnrolmentPossessionStatementInput): Record<string, unknown> {
  return {
    domain: EDGE_ENROLMENT_POSSESSION_DOMAIN,
    challenge_id: input.challenge_id,
    enrolment_request_id: input.enrolment_request_id,
    enrolment_request_fingerprint: input.enrolment_request_fingerprint,
    nonce: input.nonce,
    public_key_thumbprint: input.public_key_thumbprint,
    edge_id: input.edge_id,
    organisation_id: input.organisation_id,
    site_id: input.site_id,
    signature_profile: input.signature_profile,
  };
}

export function canonicalEdgeEnrolmentPossessionStatement(input: EdgeEnrolmentPossessionStatementInput): string {
  return canonicalDeviceJson(edgeEnrolmentPossessionObject(input));
}

export function edgeEnrolmentPossessionStatementFingerprint(input: EdgeEnrolmentPossessionStatementInput): string {
  return deviceCanonicalDigest(edgeEnrolmentPossessionObject(input));
}

// ---------------------------------------------------------------------------
// The two one-shot identities (D24-11's machinery, reused)
// ---------------------------------------------------------------------------

/**
 * THE AUTHORITY'S ONE-SHOT IDENTITY.
 *
 * Spent once, in `DeviceNonceConsumption` under its own ceremony label, through
 * the SAME `DeviceReplayService` Shield already uses. There is deliberately no
 * second replay store: `classifyDeviceNonceConsumption`'s three outcomes are
 * what make an exact retry CONVERGE on the Edge that already enrolled instead
 * of minting a second, and a parallel implementation would be a second copy of
 * that rule in a place nobody reviews as one.
 *
 * The identity is the (tenant, site, authority) coordinate rather than the
 * request id, because the question it answers is "has this authority already
 * been spent?" — and a second request under one authority must collide with
 * the first even though it carries a brand-new request id.
 */
export interface EdgeEnrolmentAuthorityReplayIdentity {
  readonly organisation_id: string;
  readonly site_id: string;
  readonly authority_id: string;
}

export function edgeEnrolmentAuthorityReplayKey(identity: EdgeEnrolmentAuthorityReplayIdentity): string {
  return canonicalDeviceJson({
    domain: EDGE_ENROLMENT_AUTHORITY_REPLAY_IDENTITY_DOMAIN,
    organisation_id: identity.organisation_id,
    site_id: identity.site_id,
    authority_id: identity.authority_id,
  });
}

/**
 * THE CHALLENGE'S ONE-SHOT IDENTITY.
 *
 * The nonce is inside it, so re-issuing a challenge after a dropped connection
 * produces a genuinely different identity and does not collide with the first.
 * Answering ONE challenge twice does collide, which is the point.
 */
export interface EdgeEnrolmentPossessionReplayIdentity {
  readonly organisation_id: string;
  readonly site_id: string;
  readonly enrolment_request_id: string;
  readonly challenge_id: string;
  readonly nonce: string;
}

export function edgeEnrolmentPossessionReplayKey(identity: EdgeEnrolmentPossessionReplayIdentity): string {
  return canonicalDeviceJson({
    domain: EDGE_ENROLMENT_POSSESSION_REPLAY_IDENTITY_DOMAIN,
    organisation_id: identity.organisation_id,
    site_id: identity.site_id,
    enrolment_request_id: identity.enrolment_request_id,
    challenge_id: identity.challenge_id,
    nonce: identity.nonce,
  });
}

// ---------------------------------------------------------------------------
// Lifecycle vocabulary
// ---------------------------------------------------------------------------

/**
 * A ROW IS NOT A TRUSTED EDGE.
 *
 * PENDING is created by the ceremony and confers nothing: no key exists in the
 * registry, so no receipt it signs can verify. ACTIVE means possession was
 * proved against an authority a human issued. WITHDRAWN is terminal for this
 * identity — re-admitting a box we withdrew is a NEW enrolment producing a new
 * `edge_id`, following D23-09's rule that a re-provisioned credential is a new
 * identity rather than a rehabilitated one.
 */
export const EdgeEnrolmentStateSchema = z.enum(['PENDING', 'ACTIVE', 'WITHDRAWN']);
export type EdgeEnrolmentState = z.infer<typeof EdgeEnrolmentStateSchema>;

/** Terminal states an Edge never leaves. */
export const TERMINAL_EDGE_ENROLMENT_STATES: readonly EdgeEnrolmentState[] = ['WITHDRAWN'];

export const ALLOWED_EDGE_ENROLMENT_TRANSITIONS: Readonly<Record<EdgeEnrolmentState, readonly EdgeEnrolmentState[]>> = {
  /** A PENDING Edge may activate, or be withdrawn without ever activating. */
  PENDING: ['ACTIVE', 'WITHDRAWN'],
  ACTIVE: ['WITHDRAWN'],
  WITHDRAWN: [],
};

export function canTransitionEdgeEnrolment(from: EdgeEnrolmentState, to: EdgeEnrolmentState): boolean {
  return ALLOWED_EDGE_ENROLMENT_TRANSITIONS[from].includes(to);
}

/**
 * The enrolment AUTHORITY's standing, judged at an explicit instant.
 *
 * The instants are the record; this function reads them. `CONSUMED` and
 * `REVOKED` are checked BEFORE expiry so a burned authority reads as burned
 * rather than as merely old — the audit distinction matters most when the
 * second use is an attacker's.
 *
 * C15-07: expiry is EXCLUSIVE, and an unreadable instant answers
 * `TIME_NOT_AUTHORITATIVE`, which is not `USABLE`, so every caller's
 * `!== 'USABLE'` test fails closed on it.
 */
export const EdgeEnrolmentAuthorityStandingSchema = z.enum(['USABLE', 'NOT_YET_VALID', 'EXPIRED', 'CONSUMED', 'REVOKED', 'TIME_NOT_AUTHORITATIVE']);
export type EdgeEnrolmentAuthorityStanding = z.infer<typeof EdgeEnrolmentAuthorityStandingSchema>;

export function classifyEdgeEnrolmentAuthority(
  authority: {
    readonly issued_at: string;
    readonly expires_at: string;
    readonly consumed_at: string | null;
    readonly revoked_at: string | null;
  },
  at: string,
): EdgeEnrolmentAuthorityStanding {
  if (authority.revoked_at !== null) return 'REVOKED';
  if (authority.consumed_at !== null) return 'CONSUMED';
  const now = Date.parse(at);
  const issued = Date.parse(authority.issued_at);
  const expires = Date.parse(authority.expires_at);
  if (!Number.isFinite(now) || !Number.isFinite(issued) || !Number.isFinite(expires)) return 'TIME_NOT_AUTHORITATIVE';
  if (now < issued) return 'NOT_YET_VALID';
  if (now >= expires) return 'EXPIRED';
  return 'USABLE';
}

/**
 * HOW LONG AN ENROLMENT AUTHORITY LIVES.
 *
 * Ten minutes, matching `DEVICE_ENROLLMENT_BOOTSTRAP_MAX_AGE_MS`, and for the
 * same reason: the window is the time it takes a human standing next to the
 * hardware to complete a ceremony, not a convenience for whoever forgot to
 * finish one. A MAXIMUM, not a setting — a runtime may be stricter, and
 * raising it is a change to the security contract.
 */
export const EDGE_ENROLMENT_AUTHORITY_MAX_AGE_MS = 600_000;

/**
 * HOW LONG AN EDGE POSSESSION CHALLENGE LIVES.
 *
 * Two minutes, matching `DEVICE_POSSESSION_CHALLENGE_MAX_AGE_MS`. It is a
 * SEPARATE constant even though the two are numerically equal today, following
 * D24-10A's rule that two ceremonies' policies must not become silently
 * coupled: changing what a phone gets must not silently change what a site
 * appliance gets.
 */
export const EDGE_POSSESSION_CHALLENGE_MAX_AGE_MS = 120_000;
