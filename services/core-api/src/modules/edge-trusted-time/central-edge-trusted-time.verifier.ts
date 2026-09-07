import { Injectable, Logger } from '@nestjs/common';
import {
  EdgeTrustedTimeEvidenceSchema,
  canonicalEdgeTrustedTimeAnchorStatement,
  edgeTrustedTimeAnchorFingerprint,
  type EdgeTrustedTimeAnchorStatement,
  type EdgeTrustedTimeEvidence,
} from '@sentinel/contracts';
import type { AuthenticatedEdgeContext } from '../edge-gateway/edge-authentication.service';
import { P256KeyImporter } from '../shield/p256-key.importer';
import {
  CentralTrustedTimeKeyringProvider,
  type CentralTrustedTimeKeyring,
} from './central-trusted-time-verification.keyring';

/**
 * M3B §7 — CENTRAL VERIFIES ITS OWN ANCHOR BEFORE ANY EDGE TIME MEANS ANYTHING.
 *
 * WHAT THIS REPLACES
 * ------------------
 * `classifyEdgeRequestTrustedTimeClaim` decides whether an Edge's claimed
 * `edge_trusted_time` is PLAUSIBLE -- recent enough, not implausibly future.
 * That is useful triage and it is not proof of anything. An Edge that has been
 * compromised and simply asserts a well-shaped recent timestamp passes it,
 * because nothing in that path ever asks the only question that matters:
 *
 *     did CENTRAL sign the anchor this time was derived from?
 *
 * Until something asks that, an Edge-claimed instant must not influence whether
 * a time-bounded offline operation is admissible. This asks it.
 *
 * THE OUTPUT IS A TYPE, NOT A BOOLEAN
 * -----------------------------------
 * Verification does not return `true`; it returns a
 * `VerifiedEdgeTrustedTimeEvidence`, which only this file can construct. The
 * admissibility path accepts that type and has no overload taking a raw
 * timestamp. So "forgot to check" is not a code review question -- it does not
 * compile. This is the same technique `AuthenticatedEdgeContext` already uses,
 * and it is used here for the same reason: the check and the permission it
 * grants must be one object, not two steps a caller can perform out of order.
 *
 * NOTHING HERE TRUSTS THE EDGE'S ARITHMETIC. Central does not read a derived
 * time off the wire and confirm it looks right; it DERIVES the value itself
 * from central's own signed `server_issued_at` and the two monotonic readings,
 * then requires the receipt to match what central computed. An Edge that sends
 * a correct-looking time it did not actually derive still fails.
 */

const VERIFIED_EDGE_TRUSTED_TIME_BRAND: unique symbol = Symbol('sentinel.edge.verified-trusted-time.v1');

/**
 * The profile a central trusted-time anchor is signed under.
 *
 * Central signs its anchors with a deployment-pinned P-256 key, so there is
 * exactly one profile and no negotiation. Named as a constant so the two
 * arguments to the profile binding below are visibly the SAME value rather
 * than two literals that could drift apart.
 */
const ANCHOR_SIGNATURE_PROFILE = 'P256_ECDSA_SHA256' as const;

/**
 * A trusted-time reading central has independently established.
 *
 * SERVER-OWNED IN EVERY FIELD. `verifiedTrustedTime` is what central computed,
 * not what the Edge sent; the two are required equal, and the one recorded is
 * central's.
 */
export interface VerifiedEdgeTrustedTimeEvidence {
  readonly [VERIFIED_EDGE_TRUSTED_TIME_BRAND]: true;
  /** The anchor that made this derivable, for provenance in the observation record. */
  readonly anchorId: string;
  readonly anchorFingerprint: string;
  readonly signerKeyId: string;
  /** DERIVED BY CENTRAL. Never the Edge's claim, even though they must be equal. */
  readonly verifiedTrustedTime: Date;
  /** The Edge's monotonic position at observation, carried for the audit record. */
  readonly edgeMonotonicPosition: number;
}

/**
 * Why central could not establish a trustworthy time.
 *
 * Every one of these is a fail-closed outcome, and none of them is an error in
 * the HTTP sense -- an Edge with no anchor yet is behaving correctly. The codes
 * are granular for OPERATORS, because "your keyring is missing the id this
 * anchor names" and "this signature does not verify" demand very different
 * responses, and a single opaque code would leave a real compromise looking
 * like a rotation that went wrong.
 */
export type EdgeTrustedTimeVerificationRefusal =
  | 'EVIDENCE_ABSENT'
  | 'EVIDENCE_MALFORMED'
  | 'KEYRING_UNAVAILABLE'
  | 'SIGNER_KEY_UNKNOWN'
  | 'ANCHOR_SIGNATURE_INVALID'
  | 'ANCHOR_EDGE_MISMATCH'
  | 'ANCHOR_ORGANISATION_MISMATCH'
  | 'ANCHOR_SITE_MISMATCH'
  | 'ANCHOR_BOOT_MISMATCH'
  | 'MONOTONIC_WENT_BACKWARDS'
  | 'DERIVED_TIME_AFTER_ANCHOR_EXPIRY'
  | 'RECEIPT_TIME_DISAGREES_WITH_DERIVATION';

export type EdgeTrustedTimeVerification =
  | { readonly ok: true; readonly evidence: VerifiedEdgeTrustedTimeEvidence }
  | { readonly ok: false; readonly refusal: EdgeTrustedTimeVerificationRefusal };

function refused(refusal: EdgeTrustedTimeVerificationRefusal): EdgeTrustedTimeVerification {
  return { ok: false, refusal };
}

@Injectable()
export class CentralEdgeTrustedTimeVerifier {
  private readonly logger = new Logger(CentralEdgeTrustedTimeVerifier.name);
  private keyring: CentralTrustedTimeKeyring | null = null;

  constructor(
    private readonly keyrings: CentralTrustedTimeKeyringProvider,
    private readonly keys: P256KeyImporter,
  ) {}

  private resolveKeyring(): CentralTrustedTimeKeyring {
    // The SAME crypto seam every other signature check in this service uses.
    // A second, private P-256 implementation living beside the first is how
    // two verifiers end up disagreeing about what a valid key is.
    this.keyring ??= this.keyrings.load((publicKey) => this.keys.isRuntimeValidPublicKey(publicKey));
    return this.keyring;
  }

  /**
   * The §7 sequence, in order, refusing at the first failure.
   *
   * `claimedReceiptTrustedTime` is the receipt's own `edge_trusted_time`. It is
   * passed in rather than read from the evidence because it lives on the
   * FROZEN receipt, and the final step of this sequence is precisely to check
   * that the frozen artefact agrees with what central derived.
   */
  verify(
    context: AuthenticatedEdgeContext,
    evidence: unknown,
    claimedReceiptTrustedTime: string | null,
  ): EdgeTrustedTimeVerification {
    if (evidence === null || evidence === undefined) return refused('EVIDENCE_ABSENT');

    const parsed = EdgeTrustedTimeEvidenceSchema.safeParse(evidence);
    if (!parsed.success) return refused('EVIDENCE_MALFORMED');
    const value: EdgeTrustedTimeEvidence = parsed.data;
    const statement: EdgeTrustedTimeAnchorStatement = value.signed_anchor.statement;

    const keyring = this.resolveKeyring();
    if (!keyring.configured) return refused('KEYRING_UNAVAILABLE');

    // Resolve BY ID. Never "try every key": a ring that tries them all cannot
    // retire a compromised key, because anything naming a different id keeps
    // working.
    const key = keyring.resolve(statement.signer_key_id);
    if (key === null) return refused('SIGNER_KEY_UNKNOWN');

    // The signature is checked over the CANONICAL bytes central would have
    // signed, recomputed here from the parsed statement rather than taken from
    // the wire -- so a re-ordered or re-encoded JSON body cannot verify.
    const canonical = canonicalEdgeTrustedTimeAnchorStatement(statement);
    const verified = this.keys.verifySignature({
      registeredPublicKey: key.public_key,
      message: canonical,
      signature: value.signed_anchor.signature,
      // C15-01's profile binding exists to stop a CLIENT choosing the profile
      // its own signature is checked under. There is no client claim here --
      // the signer is central, and the key came from central's own keyring --
      // so both sides are the one server-owned value. Passing the same
      // constant satisfies the binding truthfully rather than bypassing it.
      serverResolvedProfile: ANCHOR_SIGNATURE_PROFILE,
      claimedProfile: ANCHOR_SIGNATURE_PROFILE,
    });
    if (!verified) return refused('ANCHOR_SIGNATURE_INVALID');

    // The anchor is now known to be central's. It still has to be about THIS
    // caller: a genuine anchor issued to another Edge, tenant or site is a
    // real central signature over a statement that says nothing about the
    // request being served.
    if (statement.edge_id !== context.edgeId) return refused('ANCHOR_EDGE_MISMATCH');
    if (statement.organisation_id !== context.organisationId) return refused('ANCHOR_ORGANISATION_MISMATCH');
    if (statement.site_id !== context.siteId) return refused('ANCHOR_SITE_MISMATCH');

    // A monotonic counter is comparable only within one boot. An observation
    // from a later boot measured against an earlier boot's anchor is
    // arithmetic on unrelated origins, and would produce a confident, wrong
    // instant rather than an obvious failure.
    if (value.edge_boot_id !== statement.edge_boot_id) return refused('ANCHOR_BOOT_MISMATCH');
    if (value.edge_monotonic_at_observation < statement.edge_monotonic_at_anchor) {
      return refused('MONOTONIC_WENT_BACKWARDS');
    }

    // CENTRAL DERIVES. The elapsed term comes from the Edge's two readings, but
    // the origin is central's own signed instant, so the Edge can only ever
    // move the result FORWARD from a point central fixed -- and only as far as
    // the anchor's own expiry allows.
    const elapsedMs = value.edge_monotonic_at_observation - statement.edge_monotonic_at_anchor;
    const derivedMs = Date.parse(statement.server_issued_at) + elapsedMs;
    const validUntilMs = Date.parse(statement.server_valid_until);

    // The anchor's expiry is the ceiling on how far forward it can carry a
    // derivation. Without this an Edge could hold one anchor and keep counting
    // indefinitely, which is exactly the holdover the anchor design refuses.
    if (derivedMs > validUntilMs) return refused('DERIVED_TIME_AFTER_ANCHOR_EXPIRY');

    // The frozen receipt has to AGREE with the derivation. This is the step
    // that makes the receipt's own timestamp meaningful: it is no longer a
    // value the Edge chose, it is a value central recomputed and matched.
    if (claimedReceiptTrustedTime === null) return refused('RECEIPT_TIME_DISAGREES_WITH_DERIVATION');
    if (Date.parse(claimedReceiptTrustedTime) !== derivedMs) {
      return refused('RECEIPT_TIME_DISAGREES_WITH_DERIVATION');
    }

    return {
      ok: true,
      evidence: {
        [VERIFIED_EDGE_TRUSTED_TIME_BRAND]: true,
        anchorId: statement.anchor_id,
        anchorFingerprint: edgeTrustedTimeAnchorFingerprint(statement),
        signerKeyId: statement.signer_key_id,
        // Central's own computation, not the Edge's claim, even though the two
        // were just required equal. If they ever diverge, the record must show
        // what central established.
        verifiedTrustedTime: new Date(derivedMs),
        edgeMonotonicPosition: value.edge_monotonic_at_observation,
      },
    };
  }
}

/**
 * Runtime guard for callers that reach this boundary through `unknown` -- a
 * queue payload, a deserialised job. The compiler cannot help there, and this
 * gives the same answer it would have.
 */
export function isVerifiedEdgeTrustedTimeEvidence(value: unknown): value is VerifiedEdgeTrustedTimeEvidence {
  return typeof value === 'object' && value !== null && VERIFIED_EDGE_TRUSTED_TIME_BRAND in value;
}
