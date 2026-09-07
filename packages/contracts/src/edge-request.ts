import { createHash } from 'node:crypto';
import { z } from 'zod';
import { DeviceSignatureProfileSchema, DeviceSignatureSchema, type DeviceSignatureProfile } from './device-signature.js';
import {
  canonicalDeviceJson,
  deviceCanonicalDigest,
  DeviceDigestSchema,
  DeviceNonceSchema,
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
  DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS,
  DEVICE_TIME_NOT_AUTHORITATIVE,
  parseAuthoritativeInstant,
} from './device-identity.js';

/**
 * ============================================================================
 * WP-29B — THE EDGE→CENTRAL REQUEST PROOF.
 *
 * THE LOCKED INVARIANT
 * --------------------
 * > AN EDGE PROVES POSSESSION OF ITS REGISTERED PRIVATE KEY ON EVERY REQUEST,
 * > AND PROVES NOTHING ELSE. IT NEVER NAMES ITS OWN TENANT, ITS OWN SITE, OR
 * > ITS OWN TRUST.
 *
 * This is `device-context.ts` restated for a box in a wiring closet, and the
 * differences are all in the same direction — Edge is trusted with LESS:
 *
 *   A device carries an `AuthenticatedDeviceContext` issued against a human
 *   session. An Edge has no human on the line at 03:00, so there is no
 *   session, no context and no token: the proof IS the whole credential, which
 *   is exactly why it must be sender-constrained on every single request.
 *
 *   A device proof binds `organisation_id`, `site_id` and `actor_user_id`,
 *   which the server then equality-binds against a persisted context. THIS
 *   PROOF BINDS NONE OF THEM. There is no context row to compare against, so a
 *   tenant field here would be a tenant field that SELECTS a lookup — the
 *   exact defect C17-02 corrected on the device side. Central derives the
 *   tenant and the site from the Edge registry record it resolved by
 *   `registry_key_id`, and there is deliberately no field in this schema
 *   through which a caller could offer a different answer.
 *
 *   A device proof carries `issued_at` and is judged stale against a server
 *   clock. THIS PROOF CARRIES NO MINT TIME, because the whole WP-29B argument
 *   is that an Edge's clock is not authoritative — see `edge-trusted-time.ts`.
 *   Freshness is therefore delivered by the ONE-SHOT `request_id` and the
 *   anti-replay store, not by arithmetic on a number the Edge chose. The
 *   trusted-time pair below travels as a CLAIM and is never converted into a
 *   time central acts on.
 *
 * WHAT IS DELIBERATELY ABSENT
 * ---------------------------
 * No token. No bearer secret. No `authorization` string. No `organisation_id`,
 * no `site_id`, no `edge_trust`, no `authorised_site_ids`. `.strict()` is the
 * enforcement rather than this paragraph: adding any of them is a parse
 * failure, not a review comment.
 * ============================================================================
 */

const scopedId = z.string().min(1).max(256);
const timestamp = z.string().datetime();

// ---------------------------------------------------------------------------
// Domain separators
// ---------------------------------------------------------------------------

/**
 * Domain separator, DISTINCT from every other statement Sentinel verifies.
 *
 * `sentinel.device.request-proof.v1` signs a device's request;
 * `sentinel.device.edge-receipt.v1` signs an Edge's witness of somebody else's
 * work; this signs an Edge's OWN request. A signature minted for one must
 * never verify as another, and a shared tag would make that possible the
 * moment two statements happened to share a shape. The Edge receipt tag is the
 * one that matters most here: an Edge signs both with the SAME registered key,
 * so without separate domains a captured receipt signature could be presented
 * as authentication for a request — which is precisely the two-layer collapse
 * this work package exists to prevent.
 */
export const EDGE_REQUEST_PROOF_DOMAIN = 'sentinel.edge.request.v1';

/** Domain separator for the replay identity, distinct from the statement domain. */
export const EDGE_REQUEST_PROOF_REPLAY_IDENTITY_DOMAIN = 'sentinel.edge.request.replay-identity.v1';

// ---------------------------------------------------------------------------
// Purpose
// ---------------------------------------------------------------------------

/**
 * The allowlisted purposes an Edge may mint a proof for.
 *
 * An enum rather than a free string, for the W21-10 reason restated: an Edge
 * that could invent its own purpose could sign a statement whose meaning the
 * platform never reviewed, and a proof captured on one surface could then be
 * presented on another. Adding an entry is a visible diff that has to argue
 * for itself.
 */
export const EDGE_REQUEST_PURPOSES = [
  /** Ask central to sign a trusted-time anchor (`edge-trusted-time.ts`). */
  'TRUSTED_TIME_ANCHOR',
  /** Forward device-signed queued work, with or without an Edge receipt. */
  'OFFLINE_OPERATION_INGRESS',
  /** Report liveness and queue depth. Carries no authority of any kind. */
  'EDGE_HEARTBEAT',
  /** Present a new public key for the registry. Still a possession proof under the OLD key. */
  'EDGE_KEY_ROTATION',
] as const;
export const EdgeRequestPurposeSchema = z.enum(EDGE_REQUEST_PURPOSES);
export type EdgeRequestPurpose = z.infer<typeof EdgeRequestPurposeSchema>;

// ---------------------------------------------------------------------------
// Method and route
// ---------------------------------------------------------------------------

/**
 * The HTTP verbs a proof may bind, as an ALLOWLIST IN ONE CASE.
 *
 * `POST` and `post` name the same verb to a router and are two different byte
 * strings to a signature, so a free string would let one signed statement be
 * re-presented under a spelling the canonical statement never covered. The
 * enum removes the alias rather than asking a verifier to normalise — the same
 * single-representation rule `device-signature.ts` applies to signature bytes.
 */
export const EDGE_REQUEST_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
export const EdgeRequestMethodSchema = z.enum(EDGE_REQUEST_METHODS);
export type EdgeRequestMethod = z.infer<typeof EdgeRequestMethodSchema>;

/** Every way a route can fail to be the one canonical form. Internal audit granularity. */
export const EdgeRequestRouteRejectionSchema = z.enum([
  'NOT_ABSOLUTE',
  'TOO_LONG',
  'CARRIES_QUERY',
  'CARRIES_FRAGMENT',
  'CARRIES_WHITESPACE',
  'CARRIES_PERCENT_ENCODING',
  'EMPTY_SEGMENT',
  'DOT_SEGMENT',
  'TRAILING_SLASH',
  'NOT_PRINTABLE_ASCII',
]);
export type EdgeRequestRouteRejection = z.infer<typeof EdgeRequestRouteRejectionSchema>;

export type EdgeRequestRouteCheck = { readonly ok: true } | { readonly ok: false; readonly rejection: EdgeRequestRouteRejection };

/** 512 characters is far beyond any route this estate serves and far below anything worth buffering. */
export const EDGE_REQUEST_ROUTE_MAX_LENGTH = 512;

/**
 * ONE ROUTE, ONE SPELLING.
 *
 * A signature binds bytes; a router matches paths; the gap between those two
 * is where request-binding fails. `/edge/v1/anchor`, `/edge/v1/anchor/`,
 * `/edge//v1/anchor`, `/edge/v1/./anchor` and `/edge/v1/%61nchor` are ONE route
 * to most routers and FIVE distinct signed statements, so a proof minted for a
 * harmless route could be re-presented against a dangerous one whose canonical
 * spelling happened to differ. Every one of those forms is refused here, and
 * the request path is compared against the signed value as bytes.
 *
 * Percent-encoding is refused outright rather than decoded. Decoding would
 * mean this module owns an unescaper — a second, unreviewed implementation of
 * the one the HTTP layer already has, and the two disagreeing is the whole bug
 * class. `%2F` is a slash to one and a literal to the other; neither answer is
 * safe to guess.
 *
 * A QUERY STRING IS NOT PART OF THE ROUTE AND IS NOT COVERED BY THIS FIELD.
 * That is not an omission to be fixed by a lenient parse: an Edge request
 * carries its parameters in the body, which IS bound by `body_digest`, and a
 * surface that needed signed query parameters would have to say so in a
 * visible diff rather than by quietly admitting a `?`.
 */
export function checkCanonicalEdgeRequestRoute(value: string): EdgeRequestRouteCheck {
  if (value.length > EDGE_REQUEST_ROUTE_MAX_LENGTH) return { ok: false, rejection: 'TOO_LONG' };
  if (!value.startsWith('/')) return { ok: false, rejection: 'NOT_ABSOLUTE' };
  // Printable ASCII only. A control character or a non-ASCII byte has more than
  // one wire encoding, and "which encoding did the router see?" is not a
  // question a signature can answer.
  if (!/^[\x21-\x7e]*$/u.test(value)) return { ok: false, rejection: 'NOT_PRINTABLE_ASCII' };
  if (/\s/u.test(value)) return { ok: false, rejection: 'CARRIES_WHITESPACE' };
  if (value.includes('?')) return { ok: false, rejection: 'CARRIES_QUERY' };
  if (value.includes('#')) return { ok: false, rejection: 'CARRIES_FRAGMENT' };
  if (value.includes('%')) return { ok: false, rejection: 'CARRIES_PERCENT_ENCODING' };
  if (value !== '/' && value.endsWith('/')) return { ok: false, rejection: 'TRAILING_SLASH' };
  if (value === '/') return { ok: true };
  for (const segment of value.slice(1).split('/')) {
    if (segment.length === 0) return { ok: false, rejection: 'EMPTY_SEGMENT' };
    if (segment === '.' || segment === '..') return { ok: false, rejection: 'DOT_SEGMENT' };
  }
  return { ok: true };
}

/** The route wire form, branded so a parsed route provably passed the canonical check. */
export const EdgeRequestRouteSchema = z
  .string()
  .superRefine((value, context) => {
    const checked = checkCanonicalEdgeRequestRoute(value);
    if (checked.ok) return;
    context.addIssue({
      code: z.ZodIssueCode.custom,
      message: `route is not a canonical Edge request route: ${checked.rejection}`,
      params: { rejection: checked.rejection },
    });
  })
  .brand<'CanonicalEdgeRequestRoute'>();
export type CanonicalEdgeRequestRoute = z.infer<typeof EdgeRequestRouteSchema>;

// ---------------------------------------------------------------------------
// The body digest
// ---------------------------------------------------------------------------

/**
 * SHA-256 hex over the EXACT REQUEST BYTES, and never over a re-serialisation.
 *
 * This is the one recipe both sides run. It deliberately does NOT canonicalise
 * JSON: `canonicalDeviceJson` is right for a statement Sentinel assembles from
 * typed fields, and wrong for a body, because the server would then be
 * digesting a value produced by ITS parser rather than the bytes that arrived.
 * A parser that drops a duplicate key, coerces a big integer or reorders
 * anything is a parser that makes the digest agree with a body the Edge never
 * sent. Bytes in, digest out.
 */
export function edgeRequestBodyDigest(body: Uint8Array | string): string {
  const bytes = typeof body === 'string' ? Buffer.from(body, 'utf8') : Buffer.from(body);
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * The ONE legal digest for a request with no body.
 *
 * A nullable `body_digest` would be a branch, and a branch in a binding is a
 * place where "no body" and "a body I chose not to bind" become
 * indistinguishable. A bodyless request binds the digest of zero bytes, which
 * is a value both sides compute identically and neither can opt out of.
 */
export const EDGE_REQUEST_EMPTY_BODY_DIGEST = edgeRequestBodyDigest('');

// ---------------------------------------------------------------------------
// The proof
// ---------------------------------------------------------------------------

/**
 * The proof that accompanies EVERY Edge request.
 *
 * `body_digest` is a DIGEST, never the body: the proof binds the request's
 * contents without carrying them, so a proof travelling through a log or an
 * audit row discloses nothing about what was sent (D23-14's rule, applied to
 * Edge).
 */
export const EdgeRequestProofSchema = z
  .object({
    schema_version: z.literal(1),
    /**
     * The Edge principal this proof claims to be.
     *
     * It is a CLAIM and it is equality-bound against the Edge the resolved
     * registry key actually belongs to. It is bound into the signed statement
     * anyway — a proof that named only the key would be replayable against any
     * Edge whose key id an attacker learned, and binding both makes a
     * disagreement a cryptographic contradiction rather than a lookup somebody
     * could skip.
     */
    edge_id: scopedId,
    /**
     * WHICH REGISTERED KEY VERIFIES THIS PROOF — the registry's `edge_key_id`.
     *
     * There is deliberately no `edge_key_version` beside it. A version is a
     * FUNCTION of this id: `edge_registry_key_id_key` makes the id resolve to
     * exactly one key row, and that row carries the version. Binding a
     * client-supplied copy of a server-derived fact creates a second place the
     * two can disagree and nothing whatsoever that a disagreement would catch.
     */
    registry_key_id: scopedId,
    /**
     * THE ONE-SHOT IDENTITY OF THIS REQUEST, and the only freshness this proof
     * has.
     *
     * Typed with the device nonce bounds because that is what it is: it must
     * be unpredictable and it is spent exactly once. It is per-ATTEMPT, not
     * per-intent — a transport retry is a new request and mints a new id.
     * Domain idempotency is the domain's business and is carried by the signed
     * payload's own identifiers, never by this field; conflating the two would
     * let a replayed transport frame re-enter a decision that was already
     * taken.
     */
    request_id: DeviceNonceSchema,
    /** The verb, in the one accepted spelling. */
    method: EdgeRequestMethodSchema,
    /** The path, in the one accepted spelling. No query, no fragment, no escapes. */
    route: EdgeRequestRouteSchema,
    /** SHA-256 hex over the exact request bytes; `EDGE_REQUEST_EMPTY_BODY_DIGEST` when there are none. */
    body_digest: DeviceDigestSchema,
    /** Allowlisted. An Edge cannot invent the meaning of its own request. */
    purpose: EdgeRequestPurposeSchema,
    /**
     * THE TRUSTED-TIME PAIR, AND IT IS A CLAIM ON BOTH HALVES.
     *
     * An Edge that holds a live central-signed anchor may say so, and both
     * halves are SIGNED so neither can be stripped or swapped in transit. What
     * central does with them is bounded by `classifyEdgeRequestTrustedTimeClaim`
     * below: they are evidence about the Edge's own standing and they are never
     * converted into an instant central acts on. Central has its own clock and
     * needs no help.
     *
     * `null`/`null` is the ordinary case for an Edge that has not anchored
     * since boot, and it is admissible: an Edge without trusted time can still
     * authenticate, it simply cannot witness time-bounded work. The refinement
     * below refuses a HALF-present pair, because a timestamp without the anchor
     * that vouches for it is a bare clock reading dressed as evidence.
     */
    trusted_time_anchor_id: z.string().uuid().nullable(),
    edge_trusted_timestamp: timestamp.nullable(),
    /**
     * C15-01: Edge does not choose its profile either. The claim is
     * equality-bound to the profile on the registry key record BEFORE the
     * signature is verified, so no caller can steer the verifier.
     */
    claimed_signature_profile: DeviceSignatureProfileSchema,
    /** C15-01: branded; a malformed, non-canonical or HIGH-S signature cannot reach a parsed proof. */
    signature: DeviceSignatureSchema,
  })
  .strict()
  .superRefine((value, context) => {
    if ((value.trusted_time_anchor_id === null) !== (value.edge_trusted_timestamp === null)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['edge_trusted_timestamp'],
        message: 'trusted_time_anchor_id and edge_trusted_timestamp are present together or not at all',
      });
    }
  });
export type EdgeRequestProof = z.infer<typeof EdgeRequestProofSchema>;

/**
 * The fields an Edge request proof must NEVER be able to carry, enumerated so a
 * test can prove each one is refused rather than trusting a reviewer to notice.
 *
 * The first group are the identity fields central resolves for itself: an Edge
 * that could name its tenant or its site could ask to be authenticated into
 * somebody else's. The second are the ways of saying "I am trustworthy", which
 * is the platform's judgement about a box and never the box's own (D23-05,
 * applied to Edge). The third are bearer material, which this credential does
 * not have and must not grow.
 */
export const EDGE_REQUEST_PROOF_FORBIDDEN_FIELDS = [
  'organisation_id',
  'organization_id',
  'tenant_id',
  'site_id',
  'authorised_site_ids',
  'authorized_site_ids',
  'edge_trust',
  'trust_assertion',
  'trusted',
  'authorises_operation',
  'authorizes_operation',
  'device_trust',
  'policy_override',
  'token',
  'context_token',
  'authorization',
  'secret',
  'private_key',
  'signing_key',
] as const;

// ---------------------------------------------------------------------------
// The canonical statement
// ---------------------------------------------------------------------------

/**
 * C15-01: what the Edge signs is built from the proof MINUS its claim, PLUS the
 * server's resolved profile. The type makes that substitution mandatory — an
 * `EdgeRequestProof` is not assignable here, so no caller can accidentally sign
 * or fingerprint the client's claimed profile.
 */
export type EdgeRequestStatementInput = Omit<EdgeRequestProof, 'signature' | 'claimed_signature_profile'> & {
  /** SERVER-selected, from the registry key record. Never `claimed_signature_profile`. */
  readonly signature_profile: DeviceSignatureProfile;
};

/**
 * Build the statement input by REPLACING the client's claim with the server's
 * answer.
 *
 * Every field is listed rather than spread-minus-two, so what the Edge signs is
 * legible in one place and a field added to the proof cannot slip into the
 * signed bytes without someone deciding it should be there.
 */
export function edgeRequestStatementInput(proof: EdgeRequestProof, serverResolvedProfile: DeviceSignatureProfile): EdgeRequestStatementInput {
  return {
    schema_version: proof.schema_version,
    edge_id: proof.edge_id,
    registry_key_id: proof.registry_key_id,
    request_id: proof.request_id,
    method: proof.method,
    route: proof.route,
    body_digest: proof.body_digest,
    purpose: proof.purpose,
    trusted_time_anchor_id: proof.trusted_time_anchor_id,
    edge_trusted_timestamp: proof.edge_trusted_timestamp,
    signature_profile: serverResolvedProfile,
  };
}

/**
 * C11-01: EXACTLY what the Edge signs, canonically.
 *
 * Domain-tagged canonical JSON, not a delimiter-joined string — every field is
 * a caller-supplied value that may itself contain the delimiter, so route
 * `"/a\nb"` with purpose `"c"` and route `"/a"` with purpose `"b\nc"` would
 * otherwise produce identical bytes and one signature would verify for two
 * different requests.
 *
 * The bound set is the complete request-binding minimum:
 *
 *   who        edge_id + registry_key_id
 *   what       method + route + body_digest + purpose
 *   once       request_id
 *   claimed    trusted_time_anchor_id + edge_trusted_timestamp
 *   how        signature_profile (the SERVER's, never the claim)
 *
 * `signature` is excluded for the obvious reason: it is the output. Tenant and
 * site are excluded because they are not the Edge's to say — see this module's
 * header.
 */
function edgeRequestStatementObject(input: EdgeRequestStatementInput): Record<string, unknown> {
  return {
    domain: EDGE_REQUEST_PROOF_DOMAIN,
    schema_version: input.schema_version,
    edge_id: input.edge_id,
    registry_key_id: input.registry_key_id,
    request_id: input.request_id,
    method: input.method,
    route: input.route,
    body_digest: input.body_digest,
    purpose: input.purpose,
    trusted_time_anchor_id: input.trusted_time_anchor_id,
    edge_trusted_timestamp: input.edge_trusted_timestamp,
    signature_profile: input.signature_profile,
  };
}

export function canonicalEdgeRequestStatement(input: EdgeRequestStatementInput): string {
  return canonicalDeviceJson(edgeRequestStatementObject(input));
}

/**
 * SHA-256 over the canonical statement. The digest an audit row may carry.
 *
 * Both this and the statement builder read from ONE object literal, so the
 * signed bytes and the fingerprinted bytes cannot drift apart in a future edit
 * — a drift that would let a signature cover something the fingerprint does not.
 */
export function edgeRequestFingerprint(input: EdgeRequestStatementInput): string {
  return deviceCanonicalDigest(edgeRequestStatementObject(input));
}

// ---------------------------------------------------------------------------
// Replay identity
// ---------------------------------------------------------------------------

/**
 * THE TENANT IS NOT IN THE PROOF, SO IT IS A SEPARATE ARGUMENT.
 *
 * The replay identity must be tenant-scoped — `device_nonce_consumptions` is
 * keyed `(organisation_id, replay_identity_digest)` and a slot burned in one
 * tenant must say nothing about another. But `EdgeRequestProof` has no
 * `organisation_id`, deliberately, so the caller has to supply it from the
 * registry record it resolved. The TYPE is what enforces that: this function
 * cannot be handed a proof, and there is no field on a proof it could read the
 * tenant from even if a future edit tried.
 */
export interface EdgeRequestReplayIdentity {
  readonly organisation_id: string;
  readonly edge_id: string;
  readonly registry_key_id: string;
  readonly request_id: string;
}

/**
 * C15-05, mirroring `deviceRequestProofReplayIdentity` exactly.
 *
 * SCOPED, and deliberately NOT the statement fingerprint. The two answer
 * different questions: the fingerprint asks "are these the same bytes?", the
 * replay identity asks "is this the same one-shot slot?". Collapsing them would
 * make every distinct request its own slot, which is no replay protection at
 * all; keeping them separate is what lets the store tell an exact re-presentation
 * (same slot, same bytes) from a substitution (same slot, different bytes).
 *
 * `registry_key_id` is in the identity because a rotation is a new credential,
 * and a slot spent under the old key says nothing about the new one.
 *
 * WP-29B persistence enforces uniqueness with the existing composite key over
 * `(organisation_id, replay_identity_digest)` — a hash of this canonical key,
 * in Sentinel's ONE anti-replay store, under a new ceremony label. There is no
 * second store.
 */
export function edgeRequestReplayIdentity(input: EdgeRequestReplayIdentity): EdgeRequestReplayIdentity {
  return {
    organisation_id: input.organisation_id,
    edge_id: input.edge_id,
    registry_key_id: input.registry_key_id,
    request_id: input.request_id,
  };
}

/** C11-01: canonical JSON, never a delimiter join. */
export function edgeRequestReplayKey(input: EdgeRequestReplayIdentity): string {
  return canonicalDeviceJson({
    domain: EDGE_REQUEST_PROOF_REPLAY_IDENTITY_DOMAIN,
    ...edgeRequestReplayIdentity(input),
  });
}

// ---------------------------------------------------------------------------
// The trusted-time claim
// ---------------------------------------------------------------------------

/**
 * How much an Edge's claimed trusted time may lead the server's own clock
 * before the claim stops being a plausible reading and starts being a lie.
 *
 * It is `DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS`, imported rather than
 * restated: "how far into the future may a client's instant be?" is one
 * question, and it already has one answer in this contracts package.
 */
export const EDGE_TRUSTED_TIME_CLAIM_MAX_FUTURE_SKEW_MS = DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS;

/**
 * How far behind the server clock a claim may be before it is STALE.
 *
 * `DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS` is the anchor's own ceiling — see
 * `EDGE_TRUSTED_TIME_ANCHOR_LIFETIME_MS` — so a claim older than this cannot
 * be backed by a live anchor whatever the Edge says about it.
 */
export const EDGE_TRUSTED_TIME_CLAIM_MAX_AGE_MS = DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS;

/**
 * WHAT CENTRAL MAY CONCLUDE ABOUT AN EDGE'S TIME CLAIM, AND IT IS NEVER "the time".
 *
 * `NONE` and `STALE` are two different facts with the SAME operational
 * consequence — central holds no usable trusted time from this Edge — and they
 * are kept apart because an operator investigating a site full of refused
 * witness evidence needs to know whether the Edge never anchored or anchored
 * and drifted. `NOT_AUTHORITATIVE` is C15-07's rule: an instant that will not
 * parse is not a shrug, it is an unanswerable question, and it gets no number.
 */
export const EdgeTrustedTimeClaimStandingSchema = z.enum(['NONE', 'CLAIMED', 'STALE', 'FUTURE_SKEWED', DEVICE_TIME_NOT_AUTHORITATIVE]);
export type EdgeTrustedTimeClaimStanding = z.infer<typeof EdgeTrustedTimeClaimStandingSchema>;

/**
 * Classifies the claim against the SERVER's instant. Pure, so the whole rule is
 * testable without a database and without a clock.
 *
 * It returns a standing, never an instant. There is deliberately no
 * `trusted_now` in the result and no way to obtain one from this module: the
 * moment central could derive a time from an Edge's claim, a compromised Edge
 * could move central's clock, which is the exact inversion `edge-trusted-time.ts`
 * exists to prevent.
 */
export function classifyEdgeRequestTrustedTimeClaim(
  proof: Pick<EdgeRequestProof, 'trusted_time_anchor_id' | 'edge_trusted_timestamp'>,
  serverNow: string,
): EdgeTrustedTimeClaimStanding {
  if (proof.trusted_time_anchor_id === null || proof.edge_trusted_timestamp === null) return 'NONE';
  const claimed = parseAuthoritativeInstant(proof.edge_trusted_timestamp);
  const now = parseAuthoritativeInstant(serverNow);
  if (claimed === null || now === null) return DEVICE_TIME_NOT_AUTHORITATIVE;
  if (claimed - now > EDGE_TRUSTED_TIME_CLAIM_MAX_FUTURE_SKEW_MS) return 'FUTURE_SKEWED';
  if (now - claimed > EDGE_TRUSTED_TIME_CLAIM_MAX_AGE_MS) return 'STALE';
  return 'CLAIMED';
}

/**
 * True only for the one standing under which central may treat the Edge as
 * holding live trusted time.
 *
 * A predicate rather than an `=== 'CLAIMED'` at each call site, so adding a
 * standing later cannot silently widen what counts as trusted — a new enum
 * member is refused by this function until somebody edits it on purpose.
 */
export function edgeTrustedTimeClaimIsLive(standing: EdgeTrustedTimeClaimStanding): boolean {
  return standing === 'CLAIMED';
}
