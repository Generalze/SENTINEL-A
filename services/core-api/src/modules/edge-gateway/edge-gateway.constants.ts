/**
 * WP-29B EDGE-B — the Edge transport boundary's named constants.
 *
 * Every timing ceiling and every canonical rule this module obeys comes from
 * `@sentinel/contracts` and is imported at the call site rather than restated
 * here — a window or a route rule that a service picked is a security bound
 * nobody reviews. What lives here is the vocabulary.
 */

/**
 * The ceremony label the Edge request proof's one-shot identity is spent under.
 *
 * Sentinel's ONE anti-replay store (`device_nonce_consumptions`) is reused with
 * a new label rather than a second store being built beside it — the
 * WP-25/D25-10 precedent, and the WP-29B/round-3 precedent for the two
 * enrolment ceremonies. The label is an operator's view of WHICH ceremony
 * burned an identity and is deliberately NOT part of the uniqueness, which
 * stays `(organisation_id, replay_identity_digest)`.
 */
export const CEREMONY_EDGE_REQUEST = 'EDGE_REQUEST';

/**
 * EVERY WAY THE EDGE TRANSPORT BOUNDARY CAN REFUSE — INTERNAL VOCABULARY ONLY.
 *
 * D25-13, restated where it is enforced: these names exist for the audit trail
 * and for this module's own tests. The external answer is ONE flat refusal for
 * every entry below, because a caller able to tell "no such key" from "another
 * tenant's key" from "your Edge is suspended" from "that signature is wrong"
 * holds an oracle over the estate's Edge inventory and its trust state.
 *
 * The two that matter most for that property are `EDGE_KEY_NOT_RESOLVED` and
 * `EDGE_IDENTITY_MISMATCH`. A key that does not exist, a key belonging to a
 * tenant this proof has nothing to do with, and an ambiguous resolution all
 * produce the FIRST one, from one query, with no branch in which they could
 * diverge — an enumeration oracle is built out of branches, so there are none.
 */
export type EdgeAuthenticationRefusal =
  /** The proof is not the shape the frozen contract admits. */
  | 'PROOF_MALFORMED'
  /** The proof binds a method or a route that is not the request being made. */
  | 'REQUEST_BINDING_MISMATCH'
  /** The actual route is not in the one canonical spelling, so nothing can bind it. */
  | 'ROUTE_NOT_CANONICAL'
  /** No key, a foreign key, an ambiguous key, or an Edge that has vanished. ONE code. */
  | 'EDGE_KEY_NOT_RESOLVED'
  /** The proof names an Edge that is not the one this key belongs to. */
  | 'EDGE_IDENTITY_MISMATCH'
  /** The registry record does not satisfy its own frozen contract. No evidence, not weak evidence. */
  | 'EDGE_RECORD_NOT_REPRESENTABLE'
  /** ROTATED, REVOKED or COMPROMISED, or a revocation instant is set. */
  | 'EDGE_KEY_NOT_USABLE'
  /** The key is fine; the Edge principal is SUSPENDED or REVOKED (C15-02's split). */
  | 'EDGE_NOT_TRUSTED'
  /** The Edge is PENDING or WITHDRAWN — enrolment state, which is a third question again. */
  | 'EDGE_NOT_ACTIVE'
  /** `authorised_site_ids` is not exactly the one site the Edge row is deployed at. */
  | 'EDGE_SITE_BINDING_INVALID'
  /** The claimed profile is not the server-resolved one (C15-01). */
  | 'SIGNATURE_PROFILE_CLAIM_MISMATCH'
  /** The digest of the REAL request bytes is not the digest the Edge signed. */
  | 'BODY_DIGEST_MISMATCH'
  /** The signature does not verify against the registered key. */
  | 'POSSESSION_NOT_PROVEN'
  /** A signed trusted-time claim central can see is false. */
  | 'TRUSTED_TIME_CLAIM_NOT_PLAUSIBLE'
  /** This one-shot request identity has already been spent. */
  | 'REQUEST_REPLAYED'
  /** C15-R1: the replay store's fact is not a shape this module can act on. Fails CLOSED. */
  | 'REPLAY_FACT_INCONSISTENT'
  /** C15-07: an instant this decision depends on is unreadable. */
  | 'TIME_NOT_AUTHORITATIVE';

/**
 * Every way an Edge receipt can be refused ONCE ITS BEARER IS ALREADY
 * AUTHENTICATED. Internal vocabulary, collapsed externally exactly as above.
 *
 * `CALLER_NOT_AUTHENTICATED` is first in the list because it is first in the
 * code, and it is the whole point of the layer: a receipt that verifies
 * perfectly is refused before it is even parsed when nobody authenticated
 * ceremony brought it.
 */
export type EdgeWitnessRefusal =
  | 'CALLER_NOT_AUTHENTICATED'
  | 'RECEIPT_MALFORMED'
  | 'RECEIPT_EDGE_NOT_CALLER'
  | 'EDGE_KEY_NOT_RESOLVED'
  | 'EDGE_IDENTITY_MISMATCH'
  | 'EDGE_KEY_NOT_USABLE'
  | 'EDGE_NOT_TRUSTED'
  | 'SIGNATURE_PROFILE_CLAIM_MISMATCH'
  | 'RECEIPT_SIGNATURE_NOT_VERIFIED';
