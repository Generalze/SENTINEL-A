import { Inject, Injectable } from '@nestjs/common';
import {
  DEVICE_TIME_NOT_AUTHORITATIVE,
  SignedEdgeTrustedTimeAnchorSchema,
  canonicalEdgeTrustedTimeAnchorStatement,
  type EdgeIdentityContext,
  type SignedEdgeTrustedTimeAnchor,
} from '@sentinel/contracts';
import { EdgeTrustedTimeAnchor, type EdgeMonotonicReading } from './edge-trusted-time.anchor';
import { EDGE_TRUSTED_TIME_KEYRING, type EdgeTrustedTimeKeyring } from './edge-trusted-time.keyring';
import { P256AnchorSignatureVerifier } from './p256-anchor.verifier';

/**
 * Why an anchor was refused. Every member is a DISTINCT fact, because an
 * operator staring at an Edge that will not witness needs to know whether the
 * machine rebooted, the keyring is unconfigured, or somebody edited a file.
 *
 * None of them is ever returned to a caller over the wire — this is Edge's own
 * internal vocabulary, in the `DeviceP256PublicKeyRejection` spirit: available
 * to audit at the parse boundary, not surfaced as an oracle.
 */
export type EdgeTrustedTimeAnchorRefusal =
  /** Nothing persisted, or nothing offered. The ordinary cold-start state. */
  | 'NO_ANCHOR'
  /** The bytes on disk are not a signed anchor: truncated, corrupt, or rewritten. */
  | 'ANCHOR_MALFORMED'
  /** The statement does not re-canonicalise to itself; the stored bytes were reshaped. */
  | 'ANCHOR_NOT_CANONICAL'
  /** No pinned keyring at all, or one that refused to load. */
  | 'KEYRING_UNAVAILABLE'
  /** The statement names a `signer_key_id` this deployment has not pinned. */
  | 'SIGNER_KEY_UNKNOWN'
  /** The signature does not verify under the named key. */
  | 'SIGNATURE_NOT_VERIFIED'
  /** The anchor was issued to a different Edge, tenant, or site. */
  | 'ANCHOR_BINDING_MISMATCH'
  /** The host rebooted. FW2-10: the anchor is invalid whatever the file says. */
  | 'BOOT_IDENTITY_CHANGED'
  /** The monotonic clock is behind the signed reading, so it is not monotonic. */
  | 'MONOTONIC_WENT_BACKWARDS'
  /** `server_valid_until` has been reached, measured on the monotonic interval. */
  | 'ANCHOR_EXPIRED'
  /** C15-07: an instant this decision depends on is unreadable. */
  | typeof DEVICE_TIME_NOT_AUTHORITATIVE;

export type EdgeTrustedTimeAnchorAdmission =
  | { readonly admitted: true; readonly anchor: EdgeTrustedTimeAnchor; readonly trusted_now: string }
  | { readonly admitted: false; readonly refusal: EdgeTrustedTimeAnchorRefusal };

/**
 * ============================================================================
 * WP-29B / FW2-11 — THE ORDERED VERIFICATION CHAIN.
 *
 * This is the one place a persisted or freshly received anchor becomes usable,
 * and it FAILS CLOSED AT EVERY STEP with no wall-clock fallback anywhere. There
 * is no branch in this file that produces trusted time from anything except a
 * statement whose signature verified.
 *
 * THE ORDER, AND WHY EACH STEP IS WHERE IT IS
 * -------------------------------------------
 *   1. LOAD                 — bytes from wherever they were kept.
 *   2. PARSE THE STATEMENT  — strict shape, and the six-hour ceiling via the
 *                             frozen refinement. An over-long anchor dies here
 *                             even if it is perfectly signed, so a compromised
 *                             signing key cannot mint a week-long one.
 *   3. RE-CANONICALISE      — the stored statement must reproduce itself. Any
 *                             store that reshaped the JSON changed the bytes
 *                             the signature covers, and the failure would
 *                             otherwise present as "bad signature" and send
 *                             somebody hunting for a key problem.
 *   4. RESOLVE signer_key_id— BY ID, against the pinned keyring. This must come
 *                             before the signature check for the plain reason
 *                             that a signature cannot be verified against a key
 *                             nobody has resolved. Trying every pinned key
 *                             until one verified would make the statement's own
 *                             `signer_key_id` decorative, and would admit an
 *                             anchor signed by a key the statement did not
 *                             name. The two are reported as SEPARATE refusals
 *                             so audit can tell "we have never heard of that
 *                             key" from "that key did not sign this".
 *   5. VERIFY THE SIGNATURE — the whole statement, as one object, including the
 *                             monotonic reading. Nothing below this line is
 *                             trusted until this passes.
 *   6. BINDING              — edge_id, organisation_id, site_id against Edge's
 *                             OWN identity. A validly signed anchor issued to a
 *                             different Edge is not a weaker anchor, it is
 *                             somebody else's, and replanting one is exactly
 *                             what an attacker with two deployments would try.
 *   7. BOOT IDENTITY        — current boot must equal the signed boot. A reboot
 *                             invalidates the anchor however pristine the file
 *                             and however recent the signature.
 *   8. MONOTONIC            — current reading must be at or after the signed
 *                             one. Behind means the source is not monotonic.
 *   9. LIFETIME             — derived instant against `server_valid_until`.
 *  10. DERIVE               — and only now.
 *
 * WHY THE HOST CLOCK APPEARS NOWHERE
 * ----------------------------------
 * Not once in this chain is a wall-clock reading consulted — not for expiry,
 * not for freshness, not as a sanity check. That is what makes an NTP rollback
 * and a wall-clock jump both non-events: the only quantity that advances is the
 * monotonic reading, and the only authoritative instant is the signed one.
 * ============================================================================
 */
@Injectable()
export class EdgeTrustedTimeAnchorVerifier {
  constructor(
    @Inject(EDGE_TRUSTED_TIME_KEYRING) private readonly keyring: EdgeTrustedTimeKeyring,
    @Inject(P256AnchorSignatureVerifier) private readonly signatures: P256AnchorSignatureVerifier,
  ) {}

  /**
   * Admits an anchor, or refuses it and names why.
   *
   * `candidate` is `unknown` on purpose: it comes off a disk, or off a wire,
   * and typing it as the parsed shape would mean somebody had already trusted
   * it. The parse IS the first gate.
   */
  admit(input: {
    readonly candidate: unknown;
    readonly identity: EdgeIdentityContext;
    readonly reading: EdgeMonotonicReading;
  }): EdgeTrustedTimeAnchorAdmission {
    const { candidate, identity, reading } = input;

    // 1-2. LOAD AND PARSE.
    if (candidate === null || candidate === undefined) return { admitted: false, refusal: 'NO_ANCHOR' };
    const parsed = SignedEdgeTrustedTimeAnchorSchema.safeParse(candidate);
    // The strict shape, the branded low-S signature and the six-hour lifetime
    // ceiling all live in this one call.
    if (!parsed.success) return { admitted: false, refusal: 'ANCHOR_MALFORMED' };
    const signed: SignedEdgeTrustedTimeAnchor = parsed.data;
    const statement = signed.statement;

    // 3. THE STORED STATEMENT MUST REPRODUCE ITSELF.
    //
    // `canonicalEdgeTrustedTimeAnchorStatement` sorts keys and refuses anything
    // not losslessly representable, so this cannot fail for a statement that
    // merely arrived with its keys in a different order. What it catches is a
    // store that normalised numbers, dropped a field into a different type, or
    // otherwise reshaped the JSON — a class of corruption that would otherwise
    // surface as a signature failure and send an operator looking for a key
    // problem that does not exist.
    let statementBytes: string;
    try {
      statementBytes = canonicalEdgeTrustedTimeAnchorStatement(statement);
    } catch {
      return { admitted: false, refusal: 'ANCHOR_NOT_CANONICAL' };
    }

    // 4. RESOLVE THE SIGNER, BY ID.
    if (!this.keyring.configured) return { admitted: false, refusal: 'KEYRING_UNAVAILABLE' };
    const signerKey = this.keyring.resolve(statement.signer_key_id);
    if (signerKey === null) return { admitted: false, refusal: 'SIGNER_KEY_UNKNOWN' };

    // 5. VERIFY. Everything below this line depends on this having passed.
    const verified = this.signatures.verifyAnchorSignature({
      publicKey: signerKey.public_key,
      message: statementBytes,
      signature: signed.signature,
    });
    if (!verified) return { admitted: false, refusal: 'SIGNATURE_NOT_VERIFIED' };

    // 6. BINDING. A genuine anchor for a different Edge is somebody else's.
    //
    // The site check reads `authorised_site_ids.includes(...)` rather than an
    // equality against one site, because an Edge may legitimately serve several
    // and the anchor names the one it was issued for. Central holds the
    // authoritative list and refuses EDGE_SITE_NOT_AUTHORISED against its own
    // copy, so this local check can only narrow.
    if (
      statement.edge_id !== identity.edge_id ||
      statement.organisation_id !== identity.organisation_id ||
      !identity.authorised_site_ids.includes(statement.site_id)
    ) {
      return { admitted: false, refusal: 'ANCHOR_BINDING_MISMATCH' };
    }

    // 7. BOOT IDENTITY. FW2-10, and it runs before any arithmetic on the
    // counter for the reason the anchor class gives: across a reboot the signed
    // monotonic reading refers to a counter that no longer exists, and the
    // difference is not merely wrong but arbitrarily wrong.
    if (statement.edge_boot_id !== reading.boot_id) return { admitted: false, refusal: 'BOOT_IDENTITY_CHANGED' };

    // 8. MONOTONIC. Within one boot a genuine source cannot be behind the
    // signed reading, so observing it means the source is not what it claims.
    if (reading.monotonic_ms < statement.edge_monotonic_at_anchor) {
      return { admitted: false, refusal: 'MONOTONIC_WENT_BACKWARDS' };
    }

    // 9-10. LIFETIME, THEN DERIVE — delegated to the anchor, which owns the one
    // formula and the exclusive expiry boundary. Note the direction: the
    // verifier does not compute an instant and hand it to the anchor to check;
    // it constructs the anchor and asks. There is no second implementation of
    // the arithmetic here to drift from that one.
    const anchor = new EdgeTrustedTimeAnchor(statement);
    const standing = anchor.classify(reading);
    if (standing === 'ANCHOR_EXPIRED') return { admitted: false, refusal: 'ANCHOR_EXPIRED' };
    if (standing === 'BOOT_IDENTITY_CHANGED') return { admitted: false, refusal: 'BOOT_IDENTITY_CHANGED' };
    if (standing === 'MONOTONIC_NOT_MONOTONIC') return { admitted: false, refusal: 'MONOTONIC_WENT_BACKWARDS' };
    if (standing !== 'VALID') return { admitted: false, refusal: DEVICE_TIME_NOT_AUTHORITATIVE };

    const trustedNow = anchor.trustedNow(reading);
    // Unreachable while `classify` answers VALID. Kept because the alternative
    // to a guard here is a `null!` assertion, and this file must not contain a
    // single place where a missing instant becomes a present one.
    if (trustedNow === null) return { admitted: false, refusal: DEVICE_TIME_NOT_AUTHORITATIVE };

    return { admitted: true, anchor, trusted_now: trustedNow };
  }
}
