import { z } from 'zod';
import {
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
  canonicalDeviceJson,
  deviceCanonicalDigest,
  refineDeviceInstantWindow,
} from './device-identity.js';
import { DeviceSignatureSchema } from './device-signature.js';

/**
 * WP-29B / FW2-11 RULING — THE CENTRALLY SIGNED TRUSTED-TIME ANCHOR.
 *
 * WHAT THIS CLOSES
 * ----------------
 * Round 1 stopped here. Edge's whole security purpose is to be a time witness,
 * and every `edge_trusted_time` it ever emits grows from one anchor. An anchor
 * persisted as plain JSON — or as JSON beside an unkeyed digest of itself —
 * hands anyone who can write that file the power to choose what time Edge
 * believes it is: back-date `server_issued_at`, match the monotonic reading,
 * and every subsequent receipt is genuinely signed by a genuinely TRUSTED Edge,
 * placing operations inside whatever lease window the attacker picked. Central
 * cannot detect it, because nothing in the receipt is wrong.
 *
 * The ruling closes it by having CENTRAL sign the anchor. Edge verifies and
 * adds no cryptography of its own.
 *
 * WHY THE MONOTONIC READING IS *INSIDE* THE SIGNATURE
 * ---------------------------------------------------
 * This is the load-bearing decision of the whole module, and the obvious
 * cheaper design is the one that fails.
 *
 * Signing only central's wall time and keeping `monotonic_at_issue` in an
 * unsigned local field looks sufficient — the authoritative instant is
 * protected, after all. It is not sufficient, because trusted time is
 * DERIVED: `trusted_now = server_time + (monotonic_now − monotonic_at_issue)`.
 * An attacker who cannot touch `server_time` but CAN edit the local monotonic
 * field simply lowers it, and every derived instant moves forward by however
 * much they chose. The signature would be intact and the answer would be a lie.
 *
 * So the subtrahend is signed with the minuend. Central signs `edge_boot_id`
 * and `edge_monotonic_at_anchor` — facts Edge supplied during the authenticated
 * exchange — TOGETHER WITH its own authoritative time, and Edge may derive only
 * after verifying the whole statement as one object.
 *
 * WHAT EDGE SUPPLIES, AND WHAT IT DOES NOT
 * ----------------------------------------
 * Exactly two fields originate at Edge: `edge_boot_id` and
 * `edge_monotonic_at_anchor`. Both are facts only Edge can know, and NEITHER IS
 * A TIME — one is an opaque identity, the other a counter. `edge_id`,
 * `organisation_id` and `site_id` are resolved by central from the
 * authenticated exchange, never taken from the requester's word, because an
 * Edge that could name its own tenant could ask for an anchor bound to someone
 * else's. And every instant in the statement is central's.
 *
 * PURPOSE SEPARATION
 * ------------------
 * `signer_key_id` names a key used for THIS STATEMENT TYPE AND NOTHING ELSE.
 * It is deliberately not the Android device key, not the Edge enrolment key,
 * not a TLS key and not a Whisper key. Those all point the other way — they
 * are keys Sentinel VERIFIES, belonging to principals it does not control.
 * This one is a key Sentinel SIGNS with, and a key that both signs central's
 * assertions and appears in a verification path for someone else's is a key
 * whose compromise means two different things at once. The domain separator
 * below is the second half of the same argument: even holding this key, an
 * attacker cannot produce anything that verifies as a device operation, an Edge
 * receipt, or a request proof, because none of those statements begin with
 * these bytes.
 */

const scopedId = z.string().min(1).max(256);
const timestamp = z.string().datetime();

/**
 * Domain separator, distinct from `DEVICE_OFFLINE_OPERATION_DOMAIN`,
 * `DEVICE_EDGE_RECEIPT_DOMAIN`, `DEVICE_REQUEST_PROOF_DOMAIN` and the Whisper
 * domains. The `.v1` is not decoration: THE VERSION FIXES THE ALGORITHM at
 * P-256 ECDSA SHA-256, which is why this statement carries no signature-profile
 * field. A profile field would be a negotiation surface, and the ruling
 * authorised exactly one algorithm — an anchor signed with anything else is not
 * a weaker anchor, it is a different statement type that does not exist.
 */
export const EDGE_TRUSTED_TIME_ANCHOR_DOMAIN = 'sentinel.edge.trusted-time-anchor.v1';

/**
 * The two facts Edge contributes, and the only two.
 *
 * `edge_monotonic_at_anchor` is a MILLISECOND READING of a counter that only
 * moves forward within one boot, not the receipt's `edge_monotonic_position`
 * counter — a different quantity with a different ceiling, so it is bounded by
 * the largest integer JavaScript can represent exactly rather than by
 * `MAX_OFFLINE_DEVICE_SEQUENCE`. Beyond `MAX_SAFE_INTEGER` the arithmetic that
 * derives trusted time silently stops being exact, which is the one thing this
 * module cannot tolerate.
 */
export const EdgeTrustedTimeAnchorClaimSchema = z
  .object({
    edge_boot_id: scopedId,
    edge_monotonic_at_anchor: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  })
  .strict();
export type EdgeTrustedTimeAnchorClaim = z.infer<typeof EdgeTrustedTimeAnchorClaimSchema>;

/**
 * EXACTLY WHAT CENTRAL SIGNS.
 *
 * `.strict()` is the enforcement. There is no field in which central could
 * grant Edge a longer holdover than the ceiling, tell it to accept an untrusted
 * clock, assert anything about Edge's trust, or carry key material —
 * `EDGE_TRUSTED_TIME_ANCHOR_FORBIDDEN_FIELDS` names the shapes the Crucible
 * proves are refused.
 *
 * The lifetime ceiling is `refineDeviceInstantWindow` against the FROZEN
 * `DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS`, the same rule a policy lease, a
 * bootstrap grant and a device context are all judged by — so an over-long
 * anchor is refused at the parse boundary, on both sides, by the one piece of
 * code that decides what an impossible window is. It cannot be signed into
 * existence: central's own signer parses before it signs.
 */
export const EdgeTrustedTimeAnchorStatementSchema = z
  .object({
    schema_version: z.literal(1),
    /** This anchor's identity, for audit and for telling two anchors apart. */
    anchor_id: z.string().uuid(),
    /** Central-resolved from the authenticated exchange. Never the requester's claim. */
    edge_id: scopedId,
    organisation_id: scopedId,
    /**
     * The site this anchor is evidence FOR.
     *
     * Time is not site-specific; the BINDING is. An anchor names the Edge, the
     * tenant and the site it was issued to, so a statement captured from one
     * deployment cannot be replanted in another — the verifier compares all
     * three against its own identity before it will derive anything.
     */
    site_id: scopedId,
    /** Edge-supplied. The boot this anchor belongs to; see the note above. */
    edge_boot_id: scopedId,
    /** Edge-supplied, and SIGNED, because it is the subtrahend of the derivation. */
    edge_monotonic_at_anchor: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
    /** Central's authoritative instant. The one wall-clock reading in the system. */
    server_issued_at: timestamp,
    /** Central's chosen expiry. Bounded by the frozen ceiling, and may be sooner. */
    server_valid_until: timestamp,
    /** Which deployment-pinned key signed this. Resolved against Edge's keyring. */
    signer_key_id: scopedId,
  })
  .strict()
  .superRefine((value, context) => {
    // The one lifetime rule, reused rather than restated. The field names here
    // are central-flavoured (`server_*`), so the shared refinement is called
    // through an adapter and its issues are re-pathed onto the real field —
    // one source of truth for "impossible window", no misleading error path.
    refineDeviceInstantWindow(
      { issued_at: value.server_issued_at, expires_at: value.server_valid_until },
      {
        ...context,
        addIssue: (issue) => context.addIssue({ ...issue, path: ['server_valid_until'] }),
      },
      DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
      'trusted-time anchor',
    );
  });
export type EdgeTrustedTimeAnchorStatement = z.infer<typeof EdgeTrustedTimeAnchorStatementSchema>;

/**
 * Shapes an anchor statement must never be able to carry. Each is a way of
 * saying "ignore a rule you would otherwise apply", which is exactly what a
 * signed instruction from central must not be able to express — a compromised
 * signing key would otherwise be able to disable Edge's own defences rather
 * than merely lie about the time.
 */
export const EDGE_TRUSTED_TIME_ANCHOR_FORBIDDEN_FIELDS = [
  'holdover_ms',
  'holdover_extension',
  'max_lifetime_override',
  'allow_wall_clock',
  'allow_untrusted_time',
  'fallback_time',
  'edge_trust',
  'trust_assertion',
  'device_trust',
  'authorises_operation',
  'policy_override',
  'private_key',
  'signing_key',
  'key_material',
] as const;

function edgeTrustedTimeAnchorStatementObject(statement: EdgeTrustedTimeAnchorStatement): Record<string, unknown> {
  return {
    domain: EDGE_TRUSTED_TIME_ANCHOR_DOMAIN,
    schema_version: statement.schema_version,
    anchor_id: statement.anchor_id,
    edge_id: statement.edge_id,
    organisation_id: statement.organisation_id,
    site_id: statement.site_id,
    edge_boot_id: statement.edge_boot_id,
    edge_monotonic_at_anchor: statement.edge_monotonic_at_anchor,
    server_issued_at: statement.server_issued_at,
    server_valid_until: statement.server_valid_until,
    signer_key_id: statement.signer_key_id,
  };
}

/**
 * The exact bytes central signs and Edge verifies.
 *
 * Domain-tagged canonical JSON for the C11-01 reason: a delimiter-joined string
 * lets a field containing the delimiter forge a different identity tuple under
 * one signature. Every field of the statement appears, so there is no part of
 * the anchor an attacker could alter while leaving the signature valid.
 *
 * Both this and the fingerprint below read from ONE object literal, so the
 * signed bytes and the fingerprinted bytes cannot drift apart in a future edit.
 */
export function canonicalEdgeTrustedTimeAnchorStatement(statement: EdgeTrustedTimeAnchorStatement): string {
  return canonicalDeviceJson(edgeTrustedTimeAnchorStatementObject(statement));
}

/** The anchor's identity as a digest, for audit rows that must not carry the anchor. */
export function edgeTrustedTimeAnchorFingerprint(statement: EdgeTrustedTimeAnchorStatement): string {
  return deviceCanonicalDigest(edgeTrustedTimeAnchorStatementObject(statement));
}

/**
 * WHAT EDGE PERSISTS: the statement and the signature, together, and nothing
 * derived from them.
 *
 * The ruling is explicit that a reconstructed derivative must never be stored,
 * and this type is why. Anything Edge computed — a cached `trusted_now`, a
 * remembered expiry, a pre-parsed offset — is a value produced by verification
 * that would then be trusted WITHOUT verification after a restart. Storing only
 * the signed original means every restart re-runs the whole chain, and there is
 * no shortcut for a future edit to reach for.
 *
 * `signature` is branded by `DeviceSignatureSchema`, so a malformed, padded,
 * wrong-length or HIGH-S signature cannot reach a parsed anchor at all.
 */
export const SignedEdgeTrustedTimeAnchorSchema = z
  .object({
    statement: EdgeTrustedTimeAnchorStatementSchema,
    signature: DeviceSignatureSchema,
  })
  .strict();
export type SignedEdgeTrustedTimeAnchor = z.infer<typeof SignedEdgeTrustedTimeAnchorSchema>;

/**
 * M3B §7 — THE EVIDENCE THAT LETS CENTRAL VERIFY, RATHER THAN BELIEVE, A TIME.
 *
 * WHAT WAS WRONG
 * --------------
 * `classifyEdgeRequestTrustedTimeClaim` in `edge-request.ts` decides whether an
 * Edge's claimed `edge_trusted_time` is PLAUSIBLE: not stale, not implausibly
 * future. That is a useful triage and it is not proof of anything. A compromised
 * Edge that simply asserts a well-shaped, recent timestamp passes it, because
 * nothing in that path ever asks the question that matters:
 *
 *     did CENTRAL sign the anchor this time was derived from?
 *
 * Until something asks that, an Edge-claimed instant must not influence whether
 * a time-bounded offline operation is admissible.
 *
 * WHY THIS IS A SEPARATE STRUCTURE AND NOT A RECEIPT FIELD
 * -------------------------------------------------------
 * `DeviceEdgeReceiptSchema` is v1 and FROZEN. It is also the wrong home: the
 * receipt is the EDGE's statement about a device operation, signed by the Edge,
 * and the device may hold it across an outage. This evidence is about the
 * EDGE's own clock provenance, is meaningful only to central, and is produced
 * at forwarding time — a different author, a different audience and a different
 * lifetime. Folding it into the receipt would also mean re-signing a frozen
 * artefact to add a field that the device can neither produce nor check.
 *
 * So it travels BESIDE the receipt in the Edge -> central request body. The
 * outer authenticated Edge request proof binds the exact body digest
 * (`edgeRequestBodyDigest`), so this evidence cannot be swapped, stripped or
 * replanted in transit without invalidating the request itself. It needs no
 * signature of its own: the anchor inside it is already signed by central, and
 * the two unsigned readings beside it are bound by that outer proof.
 *
 * WHY THE TWO EXTRA FIELDS EXIST
 * ------------------------------
 * The anchor alone cannot produce a current time. It fixes one point --
 * `server_issued_at` at `edge_monotonic_at_anchor` -- and central derives
 * forward from it:
 *
 *     expected = server_issued_at
 *              + (edge_monotonic_at_observation - edge_monotonic_at_anchor)
 *
 * `edge_monotonic_at_observation` is the minuend of that subtraction, so it
 * must be transmitted. `edge_boot_id` must be transmitted separately from the
 * anchor's copy so central can require them EQUAL: a monotonic counter is only
 * comparable within one boot, and an observation from a later boot measured
 * against an earlier boot's anchor is arithmetic on unrelated origins. Central
 * checks that rather than trusting the Edge to have noticed.
 *
 * NOTHING HERE IS TRUSTED ON ARRIVAL. This schema's job is to carry the claim
 * intact; `VerifiedEdgeTrustedTimeEvidence` on the server is what a verified
 * one becomes, and only the central verifier can construct that.
 */
export const EDGE_TRUSTED_TIME_EVIDENCE_DOMAIN = 'sentinel.edge.trusted-time-evidence.v1';

export const EdgeTrustedTimeEvidenceSchema = z
  .object({
    schema_version: z.literal(1),
    /**
     * Central's own signed statement, returned to it. The signature over this
     * is the only reason anything else in this object is worth reading.
     */
    signed_anchor: SignedEdgeTrustedTimeAnchorSchema,
    /**
     * The boot the OBSERVATION was taken in. Compared for equality against
     * `signed_anchor.statement.edge_boot_id`; a mismatch means the monotonic
     * readings have different origins and no derivation is possible.
     */
    edge_boot_id: scopedId,
    /**
     * The monotonic reading at the moment the receipt was witnessed. Must be
     * at or after the anchor's reading -- a counter that went backwards inside
     * one boot is not a counter, and central refuses rather than taking an
     * absolute value.
     */
    edge_monotonic_at_observation: z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER),
  })
  .strict();
export type EdgeTrustedTimeEvidence = z.infer<typeof EdgeTrustedTimeEvidenceSchema>;

/**
 * Shapes this evidence must never carry.
 *
 * Same reasoning as `EDGE_TRUSTED_TIME_ANCHOR_FORBIDDEN_FIELDS`: every one of
 * these is a way of saying "accept this without doing the derivation". A
 * verifier that reads a field like `verified: true` from the thing it is
 * verifying has stopped being a verifier. `.strict()` already rejects unknown
 * keys, so these are asserted by test as a statement of intent -- the list
 * exists so a future author has to argue with it.
 */
export const EDGE_TRUSTED_TIME_EVIDENCE_FORBIDDEN_FIELDS = [
  'verified',
  'trusted',
  'skip_verification',
  'derived_time',
  'edge_trusted_time',
  'server_signature_optional',
] as const;
