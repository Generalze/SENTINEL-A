import { readFile } from 'node:fs/promises';
import { createPrivateKey, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { Injectable, Logger, type Provider } from '@nestjs/common';
import {
  P256_SCALAR_BYTES,
  encodeCanonicalP256Signature,
  lowSCanonicaliseForSigning,
} from '@sentinel/contracts';
import { AppConfigService } from '../../config/config.service';
import type { AppConfig } from '../../config/env.schema';

/**
 * ============================================================================
 * WP-29B / FW2-11 — KEY CUSTODY FOR THE ONE THING SENTINEL SIGNS.
 *
 * Until this file, every cryptographic operation in this service was
 * VERIFICATION: `P256KeyImporter` checks a device's signature,
 * `WhisperSignatureVerifier` checks a Whisper action, `AndroidKeyAttestationVerifier`
 * checks a chain against pinned public roots. Sentinel held no private key at
 * all, and that was a real security property — there was nothing to steal.
 *
 * The FW2-11 ruling changes that for EXACTLY ONE STATEMENT TYPE, and this file
 * is the boundary that keeps it exactly one.
 *
 * WHY THE KEY IS NOT IN POSTGRES AND NOT IN A MIGRATION
 * -----------------------------------------------------
 * `DeviceKey` is a tenant-scoped table of PUBLIC keys — material that is
 * worthless to an attacker and meaningless outside a tenant. This key is
 * neither. It is deployment-level trust material: one key for the whole
 * installation, whose compromise is an installation-level event, and whose
 * lifecycle is a deployment act rather than a tenant operation. Putting it in
 * the database would put it in every backup, every replica, every dump taken
 * for a support ticket, and inside the blast radius of any SQL injection — for
 * a value that no query ever needs to join against.
 *
 * WHY IT IS NOT A RAW PEM IN ORDINARY ENV CONFIG
 * ----------------------------------------------
 * The `ANDROID_ATTESTATION_*` block puts trust material inline in the
 * environment, and that is correct there because every byte of it is PUBLIC.
 * Inverting that for a private key would put it in `docker inspect`, in
 * `/proc/<pid>/environ`, in a crash dump, in a CI log that echoed the
 * environment, and in the shell history of whoever set it. So the environment
 * carries a PATH, and the bytes live wherever the deployment's secret manager
 * mounts them.
 *
 * THE CUSTODY CHAIN, IN PREFERENCE ORDER
 * --------------------------------------
 *   1. MANAGED KMS / HSM — the key never exists as bytes in this process; the
 *      provider holds a handle and the sign operation happens elsewhere. This
 *      is the destination and the interface below is shaped for it: the
 *      provider returns an object that SIGNS, never one that yields a key.
 *      There is no KMS integration in this repository, so no such provider
 *      ships here — an unimplemented one would be a class nobody could tell
 *      from a working one.
 *   2. SECRET-MANAGER-MOUNTED MATERIAL — what ships. A PKCS#8 P-256 private key
 *      at a deployment-supplied path, read ONCE at construction, converted
 *      immediately to a `KeyObject`, and never held as a string.
 *   3. FAIL CLOSED — the default. A deployment that has configured nothing
 *      cannot sign, and central answers `SIGNING_UNAVAILABLE` rather than
 *      producing an unsigned anchor.
 *
 * WHAT NEVER HAPPENS TO THIS KEY
 * ------------------------------
 * It is never logged (not even a length), never returned by any API, never
 * placed in an audit row, never serialised, and never handed to a caller. The
 * only thing that escapes this file is a signature over bytes the type system
 * proves are a trusted-time anchor statement.
 * ============================================================================
 */

declare const edgeTrustedTimeAnchorStatementBytesBrand: unique symbol;

/**
 * THE COMPILER IS THE LOCK.
 *
 * The signing key's only method takes this branded string, and nothing in the
 * codebase can mint one except `edge-trusted-time-anchor.signer.ts`, which
 * produces it from `canonicalEdgeTrustedTimeAnchorStatement` over a statement
 * that has already parsed.
 *
 * This is the ruling's "do not expose `sign(bytes)`" requirement expressed as a
 * type rather than as a convention. A future author who wants to sign something
 * else with this key cannot simply call the provider — there is no value of
 * this type to pass, and manufacturing one requires an explicit cast in a diff
 * that says exactly what it is doing.
 */
export type EdgeTrustedTimeAnchorStatementBytes = string & {
  readonly [edgeTrustedTimeAnchorStatementBytesBrand]: 'EdgeTrustedTimeAnchorStatementBytes';
};

/**
 * A resolved signing capability. Note what it does NOT expose: no key, no
 * `export()`, no PEM, no `KeyObject`. A holder of this object can produce
 * trusted-time anchor signatures and can do nothing else with the key.
 */
export interface EdgeTrustedTimeSigningKey {
  /** Which key this is, for the `signer_key_id` field Edge resolves against its keyring. */
  readonly signerKeyId: string;
  /** Signs EXACTLY a canonical trusted-time anchor statement. Returns the canonical low-S wire form. */
  signAnchorStatement(statementBytes: EdgeTrustedTimeAnchorStatementBytes): Promise<string>;
}

/** The custody seam. `null` means this deployment cannot sign, which is a valid state. */
export interface EdgeTrustedTimeSigningKeyProvider {
  resolve(): Promise<EdgeTrustedTimeSigningKey | null>;
}

/** DI token. Bound in `edge-trusted-time.module.ts`, injected only by the signer. */
export const EDGE_TRUSTED_TIME_SIGNING_KEY_PROVIDER = Symbol('EDGE_TRUSTED_TIME_SIGNING_KEY_PROVIDER');

/** Every configuration key this provider reads. Named once so nothing drifts. */
export const EDGE_TRUSTED_TIME_SIGNING_KEYS = [
  'EDGE_TRUSTED_TIME_SIGNER_KEY_ID',
  'EDGE_TRUSTED_TIME_SIGNING_KEY_FILE',
] as const satisfies readonly (keyof AppConfig)[];

/**
 * Has this deployment SAID ANYTHING about a signing key?
 *
 * ANY key present counts, following the `ANDROID_ATTESTATION_*` rule and for
 * the same reason: a deployment that set one of the two has ATTEMPTED to
 * configure signing and got it wrong, and it must learn that from a named
 * refusal rather than from a silent fall back to "we don't sign" as though it
 * had never tried.
 */
export function edgeTrustedTimeSigningIsConfigured(config: AppConfig): boolean {
  return EDGE_TRUSTED_TIME_SIGNING_KEYS.some((key) => config[key] !== undefined);
}

/**
 * THE DEFAULT, AND THE SAFE ONE.
 *
 * A deployment that has configured nothing simply cannot sign. Central then
 * answers `SIGNING_UNAVAILABLE`, Edge continues on an anchor it already holds
 * if it has one, and no operation is ever admitted on an unsigned anchor.
 */
@Injectable()
export class UnavailableEdgeTrustedTimeSigningKeyProvider implements EdgeTrustedTimeSigningKeyProvider {
  async resolve(): Promise<EdgeTrustedTimeSigningKey | null> {
    return null;
  }
}

/**
 * Custody level 2: material a secret manager mounted into the container.
 *
 * READ ONCE, AT FIRST USE, AND CACHED AS A `KeyObject`. Re-reading per request
 * would put the key bytes on the heap once per anchor issued; converting
 * immediately to a `KeyObject` means the only long-lived representation is the
 * provider's opaque handle rather than a string that could end up in a heap
 * dump next to its own variable name.
 *
 * Every failure — missing file, wrong permissions, an RSA key, an Ed25519 key,
 * a key on the wrong curve, a public key where a private one was expected —
 * resolves to `null`, with a REASON CODE logged and never the material. The
 * `P256KeyImporter` discipline, from the signing side: a caller able to
 * distinguish "no file" from "wrong curve" learns about the deployment's
 * secret storage, and the only safe action for all of them is identical.
 */
@Injectable()
/**
 * WHAT THIS CUSTODY BOUNDARY IS, AND WHAT IT IS NOT.
 *
 * Recorded on CTO instruction, because the easy way to describe these
 * mechanisms overstates them and an overstated defence is worse than a
 * documented limit.
 *
 * 1. ZEROING THE SOURCE BUFFER IS HYGIENE, NOT ERASURE. It removes one
 *    readable copy of the PEM. It does not erase the signing key from process
 *    memory: the imported `KeyObject` necessarily retains usable secret state
 *    for as long as this provider can sign, which is the whole point of
 *    caching it.
 *
 * 2. `#key` IS NOT A MEMORY-EXTRACTION DEFENCE. A true private field prevents
 *    ordinary JavaScript exposure — `Object.keys`, spread, `JSON.stringify`,
 *    a log line that interpolates the object. It does nothing against anything
 *    that can read the process's memory, and it is not offered as though it
 *    did.
 *
 * 3. KEY ROTATION REQUIRES A CONTROLLED RESTART. The key is read once, at
 *    first signer use, and cached. Replacing the mounted file does not reload
 *    it. Rotating the signing key therefore means a deliberate process
 *    restart, unless and until a separately governed reload mechanism is
 *    added — which would be its own ruling, because a reload path is a second
 *    way for key material to enter a running process.
 *
 * This is the first production path in core-api that reads a file from disk.
 * That is inherent to secret-manager-mounted material rather than incidental,
 * and it is why the read is confined to this class.
 */
export class MountedEdgeTrustedTimeSigningKeyProvider implements EdgeTrustedTimeSigningKeyProvider {
  private readonly logger = new Logger(MountedEdgeTrustedTimeSigningKeyProvider.name);
  private resolved: Promise<EdgeTrustedTimeSigningKey | null> | null = null;

  constructor(private readonly config: AppConfig) {}

  async resolve(): Promise<EdgeTrustedTimeSigningKey | null> {
    this.resolved ??= this.load();
    return this.resolved;
  }

  private async load(): Promise<EdgeTrustedTimeSigningKey | null> {
    // ALL OR NOTHING, exactly as the trust-material provider does it. A key
    // file with no `signer_key_id` produces anchors Edge cannot resolve against
    // its keyring, which is a silent failure six hours later rather than a loud
    // one at boot.
    const incomplete = EDGE_TRUSTED_TIME_SIGNING_KEYS.some((key) => {
      const value = this.config[key];
      return typeof value !== 'string' || value.trim().length === 0;
    });
    if (incomplete) return this.refuse('SIGNING_MATERIAL_INCOMPLETE');

    const signerKeyId = (this.config.EDGE_TRUSTED_TIME_SIGNER_KEY_ID as string).trim();
    const path = (this.config.EDGE_TRUSTED_TIME_SIGNING_KEY_FILE as string).trim();

    let material: Buffer;
    try {
      material = await readFile(path);
    } catch {
      return this.refuse('SIGNING_KEY_FILE_UNREADABLE');
    }

    let key: KeyObject;
    try {
      key = createPrivateKey(material);
    } catch {
      return this.refuse('SIGNING_KEY_UNPARSEABLE');
    } finally {
      // The bytes are no longer needed. Zeroing a Buffer is not a guarantee —
      // Node may have copied it — but leaving a readable private key sitting in
      // a live Buffer for the process lifetime is a choice, and this is the
      // cheap half of not making it.
      material.fill(0);
    }

    // The same three post-import assertions `P256KeyImporter` makes, from the
    // signing side. A key is re-checked for what it IS rather than trusted to
    // be what the file was named. The version in the domain separator fixes the
    // algorithm at P-256 ECDSA SHA-256, so anything else is not a weaker key —
    // it is a key for a statement type that does not exist.
    if (key.type !== 'private') return this.refuse('SIGNING_KEY_NOT_PRIVATE');
    if (key.asymmetricKeyType !== 'ec') return this.refuse('SIGNING_KEY_WRONG_ALGORITHM');
    if (key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') return this.refuse('SIGNING_KEY_WRONG_CURVE');

    this.logger.log(`edge trusted-time signing key loaded: signer_key_id=${signerKeyId}`);
    return new KeyObjectEdgeTrustedTimeSigningKey(signerKeyId, key);
  }

  private refuse(reason: string): null {
    // A REASON CODE ONLY. Never the path, never the material, never a length.
    this.logger.error(
      `edge trusted-time signing key NOT USABLE: reason=${reason}. ` +
        'Trusted-time anchors will be refused as SIGNING_UNAVAILABLE until this is corrected.',
    );
    return null;
  }
}

/**
 * The sign operation itself, and the only place the key is touched.
 *
 * `lowSCanonicaliseForSigning` is the contract's SIGNER-side helper, used here
 * for the reason the contract gives: Node can emit a mathematically equivalent
 * high-S signature, and a signer holding the key may legitimately choose which
 * of two equivalent forms to send. `decodeCanonicalP256Signature` — which
 * `DeviceSignatureSchema` runs on Edge — REFUSES high-S, so without this every
 * anchor would intermittently be unparseable at the far end.
 *
 * The recipe is `signCanonicalStatement` in `shield.test-support.ts`, which
 * until now existed only to stand in for device hardware. It is reproduced here
 * rather than imported because that file is test support and importing it into
 * a production path would make it production code by accident.
 */
class KeyObjectEdgeTrustedTimeSigningKey implements EdgeTrustedTimeSigningKey {
  /**
   * A TRUE ECMAScript PRIVATE FIELD, not a TypeScript `private`.
   *
   * The difference is not stylistic and it was found by a test. A TS `private`
   * is an own ENUMERABLE property at runtime: it shows up in `Object.keys`, in
   * a spread, in `JSON.stringify`, and therefore in any diagnostic that
   * serialises this object or any log line that interpolates it. `#key` is
   * unreachable from outside the class by construction — it cannot be
   * enumerated, spread, or serialised at all. For the only private key this
   * system holds, the stronger of the two is the only defensible choice.
   */
  readonly #key: KeyObject;

  constructor(
    readonly signerKeyId: string,
    key: KeyObject,
  ) {
    this.#key = key;
  }

  async signAnchorStatement(statementBytes: EdgeTrustedTimeAnchorStatementBytes): Promise<string> {
    const raw = cryptoSign('sha256', Buffer.from(statementBytes, 'utf8'), { key: this.#key, dsaEncoding: 'ieee-p1363' });
    const r = BigInt(`0x${raw.subarray(0, P256_SCALAR_BYTES).toString('hex')}`);
    const s = BigInt(`0x${raw.subarray(P256_SCALAR_BYTES).toString('hex')}`);
    return encodeCanonicalP256Signature(r, lowSCanonicaliseForSigning(s));
  }
}

/**
 * THE BINDING, in the file the module imports, so a spec can exercise the
 * SHIPPING WIRING rather than an override — the C18-01 argument applied to the
 * signing side.
 *
 * A future KMS provider is bound here, ahead of the mounted one, and nothing
 * else in the codebase changes: the signer depends on the interface.
 */
export const EDGE_TRUSTED_TIME_SIGNING_KEY_PROVIDER_BINDING: Provider = {
  provide: EDGE_TRUSTED_TIME_SIGNING_KEY_PROVIDER,
  inject: [AppConfigService],
  useFactory: (config: AppConfigService): EdgeTrustedTimeSigningKeyProvider =>
    edgeTrustedTimeSigningIsConfigured(config.values)
      ? new MountedEdgeTrustedTimeSigningKeyProvider(config.values)
      : new UnavailableEdgeTrustedTimeSigningKeyProvider(),
};
