import { randomUUID } from 'node:crypto';
import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
  EdgeTrustedTimeAnchorStatementSchema,
  SignedEdgeTrustedTimeAnchorSchema,
  canonicalEdgeTrustedTimeAnchorStatement,
  edgeTrustedTimeAnchorFingerprint,
  type EdgeTrustedTimeAnchorClaim,
  type SignedEdgeTrustedTimeAnchor,
} from '@sentinel/contracts';
import {
  EDGE_TRUSTED_TIME_SIGNING_KEY_PROVIDER,
  type EdgeTrustedTimeAnchorStatementBytes,
  type EdgeTrustedTimeSigningKeyProvider,
} from './edge-trusted-time-signing-key.provider';

/**
 * HOW LONG AN ANCHOR LASTS, AND WHY IT IS NOT CONFIGURABLE.
 *
 * The ceiling is `DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS`, imported rather than
 * restated: beyond the longest life a policy lease can have, an anchor cannot
 * place any operation inside any lease, so a longer one buys nothing and only
 * lengthens the window in which stale trusted time is vouched for.
 *
 * Central issues AT the ceiling and the ruling permits shorter. Shortening it
 * is a one-line diff here — visible, reviewed, estate-wide — and deliberately
 * not an environment variable: a per-site holdover is a per-site answer to "how
 * stale may our evidence be", set by whoever last edited a file in a wiring
 * closet's deployment config.
 */
export const EDGE_TRUSTED_TIME_ANCHOR_LIFETIME_MS = DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS;

/**
 * What central needs to issue an anchor.
 *
 * READ THE SPLIT. `claim` is the two facts Edge supplied over the authenticated
 * exchange — its boot identity and its monotonic reading, neither of which is a
 * time. `edge_id`, `organisation_id` and `site_id` are SEPARATE fields because
 * central resolves them from the authentication, never from the requester's
 * body: an Edge that could name its own tenant could ask for an anchor bound to
 * someone else's, and a caller that could pass them inside `claim` would be
 * exactly that. The type makes the two sources impossible to confuse.
 *
 * `now` is the server receipt clock, passed in rather than read, so this whole
 * service is testable without one and so the instant it stamps is the same
 * instant the rest of the request used.
 */
export interface EdgeTrustedTimeAnchorRequest {
  readonly claim: EdgeTrustedTimeAnchorClaim;
  readonly edge_id: string;
  readonly organisation_id: string;
  readonly site_id: string;
  readonly now: Date;
}

/** Why central could not issue. Never surfaced as a signature. */
export type EdgeTrustedTimeSigningRefusal =
  /** No signing key: unconfigured deployment, unreadable material, or wrong key type. */
  | 'SIGNING_KEY_UNAVAILABLE'
  /** The statement central assembled does not satisfy its own contract. Refused before signing. */
  | 'ANCHOR_NOT_REPRESENTABLE'
  /** The signing operation itself failed. Not evidence of anything except a fault. */
  | 'SIGNING_FAILED';

/**
 * TRUTHFUL UNAVAILABILITY IS A FIRST-CLASS ANSWER.
 *
 * There is no third arm to this union in which an anchor exists without a
 * signature, and there is deliberately no `signature: string | null`. An
 * unsigned anchor, a placeholder signature or a "degraded" anchor would each be
 * a value Edge could persist and later verify-by-not-verifying; the shape
 * refuses to be able to express one.
 */
export type EdgeTrustedTimeAnchorIssuance =
  | { readonly outcome: 'ISSUED'; readonly anchor: SignedEdgeTrustedTimeAnchor; readonly anchor_fingerprint: string }
  | { readonly outcome: 'SIGNING_UNAVAILABLE'; readonly reason: EdgeTrustedTimeSigningRefusal };

/**
 * ============================================================================
 * WP-29B / FW2-11 — THE ONLY THING SENTINEL SIGNS.
 *
 * THIS IS NOT A SIGNING SERVICE. It is a trusted-time anchor issuer that
 * happens to sign, and the difference is enforced rather than described:
 *
 *   - the ONLY public method takes `EdgeTrustedTimeAnchorRequest` and returns
 *     an anchor. There is no `sign(bytes)`, no `sign(unknown)`, and no
 *     "sign this canonical statement for me" entry point;
 *   - the key provider's own method takes a BRANDED type that only this file
 *     can mint, so even a future author inside this module cannot casually
 *     route other bytes through it;
 *   - the module exports this class and NOT the provider, so no other module
 *     can inject the key at all.
 *
 * A general signing service would be the obvious next step and it is the one
 * that must not be taken. The moment this key can sign a second statement type,
 * its compromise stops being bounded by "an attacker can lie about the time for
 * six hours" and becomes "an attacker can assert whatever the second statement
 * type asserts".
 *
 * WHY THE STATEMENT IS PARSED BEFORE IT IS SIGNED
 * -----------------------------------------------
 * `EdgeTrustedTimeAnchorStatementSchema` carries the six-hour lifetime ceiling,
 * via the same `refineDeviceInstantWindow` a policy lease is judged by. Parsing
 * first means CENTRAL CANNOT SIGN AN OVER-LONG ANCHOR EVEN BY MISTAKE — the
 * ceiling is not merely something Edge checks on receipt, it is something that
 * never acquires a signature. A bug in the lifetime arithmetic here becomes a
 * refusal at issuance rather than an anchor in the field that Edge rejects six
 * hours of Field work later.
 * ============================================================================
 */
@Injectable()
export class CentralTrustedTimeAnchorSigner {
  private readonly logger = new Logger(CentralTrustedTimeAnchorSigner.name);

  constructor(
    @Inject(EDGE_TRUSTED_TIME_SIGNING_KEY_PROVIDER) private readonly keyProvider: EdgeTrustedTimeSigningKeyProvider,
  ) {}

  /**
   * Issues one signed trusted-time anchor, or says truthfully that it cannot.
   *
   * The order is the argument:
   *
   *  1. resolve the key FIRST. If this deployment cannot sign, nothing else is
   *     worth doing and the caller learns it without a statement having been
   *     assembled — no half-built anchor exists to be logged or reused;
   *  2. assemble the statement from central's own values and the two Edge
   *     facts, stamping `signer_key_id` from the RESOLVED key rather than from
   *     configuration, so the field always names the key that actually signed;
   *  3. PARSE it, which applies the six-hour ceiling and the strict shape;
   *  4. only then compute the canonical bytes and sign them;
   *  5. parse the signed pair, so an implementation that somehow produced a
   *     non-canonical or high-S signature is caught here rather than on Edge.
   */
  async issueTrustedTimeAnchor(request: EdgeTrustedTimeAnchorRequest): Promise<EdgeTrustedTimeAnchorIssuance> {
    const key = await this.keyProvider.resolve();
    if (key === null) return { outcome: 'SIGNING_UNAVAILABLE', reason: 'SIGNING_KEY_UNAVAILABLE' };

    // C15-07's discipline applied to the SERVER clock. `Date.prototype.toISOString`
    // THROWS on an invalid Date rather than returning something unusable, so an
    // unreadable receipt clock would otherwise become an exception on the
    // issuance path instead of a refusal. Central not knowing what time it is
    // must produce a truthful "cannot sign", never a crash and never a guess.
    if (!Number.isFinite(request.now.getTime())) {
      this.logger.error('edge trusted-time anchor refused before signing: the server receipt clock is not authoritative');
      return { outcome: 'SIGNING_UNAVAILABLE', reason: 'ANCHOR_NOT_REPRESENTABLE' };
    }

    const parsedStatement = EdgeTrustedTimeAnchorStatementSchema.safeParse({
      schema_version: 1,
      anchor_id: randomUUID(),
      edge_id: request.edge_id,
      organisation_id: request.organisation_id,
      site_id: request.site_id,
      // The two Edge-supplied facts, carried through unaltered and into the
      // signature. Central does not "correct" them: a monotonic reading central
      // adjusted would be a subtrahend Edge never observed.
      edge_boot_id: request.claim.edge_boot_id,
      edge_monotonic_at_anchor: request.claim.edge_monotonic_at_anchor,
      server_issued_at: request.now.toISOString(),
      server_valid_until: new Date(request.now.getTime() + EDGE_TRUSTED_TIME_ANCHOR_LIFETIME_MS).toISOString(),
      signer_key_id: key.signerKeyId,
    });
    if (!parsedStatement.success) {
      // Reason code only. The statement is not logged: it names a tenant, a
      // site and an Edge, and a refusal is not a reason to widen what a log line
      // discloses.
      this.logger.error('edge trusted-time anchor refused before signing: the assembled statement is not representable');
      return { outcome: 'SIGNING_UNAVAILABLE', reason: 'ANCHOR_NOT_REPRESENTABLE' };
    }

    // The one place a value of the branded type is created, from bytes that are
    // provably a parsed anchor statement.
    const statementBytes = canonicalEdgeTrustedTimeAnchorStatement(parsedStatement.data) as EdgeTrustedTimeAnchorStatementBytes;

    let signature: string;
    try {
      signature = await key.signAnchorStatement(statementBytes);
    } catch {
      // A crypto-layer fault is not evidence of anything, and above all it is
      // not a reason to emit an anchor without a signature.
      this.logger.error('edge trusted-time anchor signing failed');
      return { outcome: 'SIGNING_UNAVAILABLE', reason: 'SIGNING_FAILED' };
    }

    const signed = SignedEdgeTrustedTimeAnchorSchema.safeParse({ statement: parsedStatement.data, signature });
    if (!signed.success) {
      // Unreachable while the signer canonicalises low-S. Kept because the
      // alternative to catching it here is Edge refusing every anchor from a
      // subtly broken signer, with the reason six hours away.
      this.logger.error('edge trusted-time anchor signing produced a non-canonical signature');
      return { outcome: 'SIGNING_UNAVAILABLE', reason: 'SIGNING_FAILED' };
    }

    return {
      outcome: 'ISSUED',
      anchor: signed.data,
      // A DIGEST, for the audit trail. The anchor itself is evidence a caller
      // may hold; a log line is not, and `edgeTrustedTimeAnchorFingerprint`
      // exists so an audit row can name an anchor without carrying one.
      anchor_fingerprint: edgeTrustedTimeAnchorFingerprint(signed.data.statement),
    };
  }
}
