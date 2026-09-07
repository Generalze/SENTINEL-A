import { createPrivateKey, createSign, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { Injectable, Logger } from '@nestjs/common';
import {
  EDGE_REQUEST_EMPTY_BODY_DIGEST,
  EdgeRequestRouteSchema,
  P256_CURVE_ORDER,
  P256_HALF_CURVE_ORDER,
  canonicalEdgeRequestStatement,
  edgeRequestBodyDigest,
  encodeCanonicalP256Signature,
  type EdgeRequestPurpose,
} from '@sentinel/contracts';
import { EdgeConfigService } from '../../config/config.service';

/**
 * M3B — THE EDGE'S OWN SIGNING IDENTITY.
 *
 * WHY A FILE PATH AND NEVER THE KEY ITSELF
 * ----------------------------------------
 * A key in an environment variable is a key in every process listing, every
 * crash dump and every `docker inspect`. This reads a mounted PKCS#8 file, the
 * same shape central uses for its trusted-time signing key, and holds the
 * result as a `KeyObject` that has no export path out of this class.
 *
 * THE CUSTODY STORY THAT DID NOT EXIST BEFORE
 * -------------------------------------------
 * `env.schema.ts` previously refused to name this key at all, because WP-29B
 * had no ruling on where it lives. M3B §6 supplied one: Edge state sits on a
 * LUKS/dm-crypt volume that `scripts/edge-storage-preflight.sh` proves before
 * the Edge starts, and that preflight also refuses if key-shaped files are
 * inside the volume they unlock. So the key file has somewhere to be that is
 * checked rather than assumed.
 *
 * PURPOSE SEPARATION. This is the APPLICATION key -- it signs statements. The
 * TLS key that terminates Field connections is a different keypair (M3B §2),
 * so a stolen TLS key is not also a valid receipt signer, and a TLS rotation
 * does not invalidate the Edge's registry identity.
 *
 * NO KEY IS A VALID STATE. `resolve()` returns `null` for an Edge that has not
 * been given one. Such an Edge still queues Field work; it simply cannot
 * forward. Refusing to BOOT would be worse -- a site that cannot reach central
 * is exactly the site that most needs its Edge running.
 */
@Injectable()
export class EdgeRequestSigner {
  private readonly logger = new Logger(EdgeRequestSigner.name);
  private key: KeyObject | null | undefined;

  constructor(private readonly config: EdgeConfigService) {}

  /** `null` when this Edge has no signing identity configured or loadable. */
  private resolve(): KeyObject | null {
    if (this.key !== undefined) return this.key;

    const path = this.config.values.EDGE_SIGNING_KEY_FILE;
    if (path === undefined) {
      this.key = null;
      return null;
    }

    try {
      const pem = readFileSync(path, 'utf8');
      const key = createPrivateKey({ key: pem, format: 'pem' });
      // A key of the wrong curve would fail later inside a signature the
      // registry cannot verify, which reads as an authentication fault rather
      // than as the configuration fault it is.
      if (key.asymmetricKeyType !== 'ec') {
        this.logger.error('edge signing key is not an EC key');
        this.key = null;
        return null;
      }
      this.key = key;
    } catch (error) {
      // The PATH may appear in the log. The CONTENTS never can, and there is
      // no branch here that could put them there.
      this.logger.error(`edge signing key unreadable: ${error instanceof Error ? error.name : 'unknown'}`);
      this.key = null;
    }
    return this.key;
  }

  canSign(): boolean {
    return this.resolve() !== null;
  }

  /**
   * Signs one Edge request proof.
   *
   * A FRESH `request_id` EVERY TIME, minted here rather than accepted from a
   * caller. §9's rule that a lost response is retried with a NEW transport
   * identity depends on this being impossible to get wrong: a caller that
   * could supply the id could reuse one, and transport anti-replay would
   * silently stop working while every response still looked correct.
   */
  sign(input: {
    readonly method: 'POST';
    readonly route: string;
    readonly body: string;
    readonly purpose: EdgeRequestPurpose;
  }): Record<string, unknown> | null {
    const key = this.resolve();
    if (key === null) return null;

    const values = this.config.values;
    const statementInput = {
      schema_version: 1 as const,
      edge_id: values.EDGE_ID,
      registry_key_id: values.EDGE_KEY_ID,
      request_id: randomUUID().replace(/-/gu, ''),
      method: input.method,
      route: EdgeRequestRouteSchema.parse(input.route),
      body_digest: input.body === '' ? EDGE_REQUEST_EMPTY_BODY_DIGEST : edgeRequestBodyDigest(input.body),
      purpose: input.purpose,
      // The Edge does not assert a trusted time on the REQUEST. Its time
      // evidence travels in the body, where central verifies it against a
      // signed anchor -- a timestamp asserted on the envelope would be exactly
      // the unverified claim M3B §7 exists to stop trusting.
      trusted_time_anchor_id: null,
      edge_trusted_timestamp: null,
      signature_profile: 'P256_ECDSA_SHA256' as const,
    };

    const signature = this.signCanonical(key, canonicalEdgeRequestStatement(statementInput));

    return {
      schema_version: statementInput.schema_version,
      edge_id: statementInput.edge_id,
      registry_key_id: statementInput.registry_key_id,
      request_id: statementInput.request_id,
      method: statementInput.method,
      route: statementInput.route as string,
      body_digest: statementInput.body_digest,
      purpose: statementInput.purpose,
      trusted_time_anchor_id: null,
      edge_trusted_timestamp: null,
      claimed_signature_profile: statementInput.signature_profile,
      signature,
    };
  }

  /**
   * Canonical low-S IEEE-P1363, because the contract brands only low-S.
   *
   * `createSign` emits S or n-S at random. Skipping this canonicalisation
   * would produce a signature central refuses roughly half the time, and the
   * failure would look like an intermittent network or registry fault rather
   * than the encoding bug it is (C14-01).
   */
  private signCanonical(key: KeyObject, message: string): string {
    const signer = createSign('sha256');
    signer.update(Buffer.from(message, 'utf8'));
    signer.end();
    const raw = signer.sign({ key, dsaEncoding: 'ieee-p1363' });
    const r = BigInt(`0x${raw.subarray(0, 32).toString('hex')}`);
    const rawS = BigInt(`0x${raw.subarray(32, 64).toString('hex')}`);
    const s = rawS > P256_HALF_CURVE_ORDER ? P256_CURVE_ORDER - rawS : rawS;
    return encodeCanonicalP256Signature(r, s);
  }
}
