import { Injectable, Logger, type Provider } from '@nestjs/common';
import { z } from 'zod';
import { DeviceP256PublicKeySchema } from '@sentinel/contracts';
import { EdgeConfigService } from '../../config/config.service';
import { P256AnchorSignatureVerifier } from './p256-anchor.verifier';
import type { EdgeConfig } from '../../config/env.schema';

/**
 * ============================================================================
 * WP-29B / FW2-11 — THE DEPLOYMENT-PINNED VERIFICATION KEYRING.
 *
 * WHY THIS IS PINNED CONFIGURATION AND NOT A TABLE
 * ------------------------------------------------
 * The ruling reserves migration #26 for the Edge registry and says explicitly
 * that this is deployment-level trust material, not tenant state. It would also
 * be circular to fetch it: Edge needs to verify an anchor precisely when it
 * cannot reach central, so a keyring Edge downloads is a keyring that is
 * unavailable exactly when it is needed. And a keyring Edge downloaded ONCE and
 * cached would be a file on the same disk as the anchor — an attacker who can
 * rewrite the anchor could rewrite the key it verifies against, and the whole
 * signature would prove nothing.
 *
 * So the public keys arrive the way the pinned Google attestation roots arrive:
 * as configuration, supplied by a deployment act, absent by default.
 *
 * FAIL CLOSED, ALL OR NOTHING — the `ANDROID_ATTESTATION_*` rules, restated
 * because each one is a way this could fail open:
 *
 *   1. ALL OR NOTHING. A keyring with no version, or a version with no keys, is
 *      `configured: false`. Trust material is a conjunction, and a conjunction
 *      missing a term is not a weaker conjunction — it is no answer at all.
 *   2. NEVER SILENTLY SUBSTITUTE. No default keyring, no built-in key, no
 *      "development" fallback. A wrong pinned key fails OPEN; a missing one
 *      fails closed, and Edge simply holds no trusted time.
 *   3. A MALFORMED ENTRY POISONS THE WHOLE SET. Not "keep the keys that
 *      parsed": a set that quietly shrank is a set nobody chose, and the entry
 *      that failed to parse may be the ACTIVE one — leaving Edge silently
 *      unable to verify anything current while appearing configured.
 *   4. DUPLICATE IDS POISON THE SET. Two entries claiming one `signer_key_id`
 *      make "which key verifies this anchor" ambiguous, and an ambiguity
 *      resolved by iteration order is an ambiguity resolved by accident.
 *
 * ROTATION: ONE ACTIVE, OPTIONALLY ONE PREVIOUS
 * ---------------------------------------------
 * Central signs with one key. Edge may hold that key and the one before it, and
 * no more. The bound is not arbitrary — it falls out of the six-hour ceiling.
 * Every anchor a key could have signed expires at most six hours after that key
 * stopped being used, so a previous key becomes droppable six hours after the
 * rotation and never needs to be kept longer. A keyring that accumulated
 * historic keys would be a growing set of things that can still vouch for time,
 * which is the opposite of what rotation is for.
 *
 * The role is recorded but is NOT a verification input: an anchor signed by the
 * previous key verifies exactly as one signed by the active key does, and is
 * then judged on its own `server_valid_until` like any other. Refusing PREVIOUS
 * at verification time would break every in-flight anchor at the instant of
 * rotation, which is the outage rotation exists to avoid.
 * ============================================================================
 */

/** Which key central signs with now, and which one it signed with before. */
export const EdgeTrustedTimeKeyRoleSchema = z.enum(['ACTIVE', 'PREVIOUS']);
export type EdgeTrustedTimeKeyRole = z.infer<typeof EdgeTrustedTimeKeyRoleSchema>;

/**
 * One pinned verification key. PUBLIC MATERIAL ONLY — the schema is strict and
 * there is no field a private key could arrive in, so a deployment that
 * mistakenly pasted a private key gets a parse failure rather than a running
 * Edge holding central's signing key on a customer LAN.
 */
export const EdgeTrustedTimeVerificationKeySchema = z
  .object({
    signer_key_id: z.string().min(1).max(256),
    /** Canonical uncompressed SEC1 P-256 point, base64url. Curve-checked at load. */
    public_key: DeviceP256PublicKeySchema,
    role: EdgeTrustedTimeKeyRoleSchema,
  })
  .strict();
export type EdgeTrustedTimeVerificationKey = z.infer<typeof EdgeTrustedTimeVerificationKeySchema>;

const EdgeTrustedTimeKeyringSchema = z.array(EdgeTrustedTimeVerificationKeySchema).min(1).max(2);

/** Why the configured keyring could not be used. Logged as a code, never with material. */
export type EdgeTrustedTimeKeyringRefusal =
  | 'KEYRING_INCOMPLETE'
  | 'KEYRING_UNPARSEABLE'
  | 'KEYRING_EMPTY'
  | 'KEYRING_DUPLICATE_SIGNER_KEY_ID'
  | 'KEYRING_NO_ACTIVE_KEY'
  | 'KEYRING_MULTIPLE_ACTIVE_KEYS'
  | 'KEYRING_KEY_NOT_ON_CURVE';

export type EdgeTrustedTimeKeyring =
  | { readonly configured: false; readonly reason: EdgeTrustedTimeKeyringRefusal }
  | {
      readonly configured: true;
      readonly version: string;
      /** Resolve by id. Absent id means "we cannot verify this anchor", never "try them all". */
      resolve(signerKeyId: string): EdgeTrustedTimeVerificationKey | null;
    };

/** Every configuration key the keyring reads. Named once so nothing drifts. */
export const EDGE_TRUSTED_TIME_KEYRING_KEYS = [
  'EDGE_TRUSTED_TIME_VERIFICATION_KEYS',
  'EDGE_TRUSTED_TIME_KEYRING_VERSION',
] as const satisfies readonly (keyof EdgeConfig)[];

/** DI token for the keyring. */
export const EDGE_TRUSTED_TIME_KEYRING = Symbol('EDGE_TRUSTED_TIME_KEYRING');

/**
 * Has this deployment SAID ANYTHING about a keyring? ANY key present counts, so
 * a half-configured deployment learns from a named refusal rather than from a
 * silent fall back to "unconfigured" as though it had never tried.
 */
export function edgeTrustedTimeKeyringIsConfigured(config: EdgeConfig): boolean {
  return EDGE_TRUSTED_TIME_KEYRING_KEYS.some((key) => config[key] !== undefined);
}

/** The safe default: pins nothing, verifies nothing, and says so. */
export function unconfiguredEdgeTrustedTimeKeyring(): EdgeTrustedTimeKeyring {
  return { configured: false, reason: 'KEYRING_INCOMPLETE' };
}

/**
 * Parses configuration into a usable keyring, or names the reason it could not.
 *
 * Exported so the rules above are testable as RULES rather than only through a
 * booted injector — the `loadConfiguredTrustMaterial` precedent.
 *
 * `isOnCurve` is injected rather than imported so this stays a pure function
 * over configuration: the curve check is `P256AnchorSignatureVerifier`'s, and
 * running it HERE rather than at first verification means a deployment learns
 * at boot that it pinned an unusable point.
 */
export function loadEdgeTrustedTimeKeyring(config: EdgeConfig, isOnCurve: (publicKey: string) => boolean): EdgeTrustedTimeKeyring {
  const incomplete = EDGE_TRUSTED_TIME_KEYRING_KEYS.some((key) => {
    const value = config[key];
    return typeof value !== 'string' || value.trim().length === 0;
  });
  if (incomplete) return { configured: false, reason: 'KEYRING_INCOMPLETE' };

  let json: unknown;
  try {
    json = JSON.parse(config.EDGE_TRUSTED_TIME_VERIFICATION_KEYS as string);
  } catch {
    return { configured: false, reason: 'KEYRING_UNPARSEABLE' };
  }

  const parsed = EdgeTrustedTimeKeyringSchema.safeParse(json);
  // Rule 3: ANY malformed entry refuses the WHOLE set. The entry that failed to
  // parse may be the active one, and an Edge silently reduced to a previous key
  // would stop being able to verify anything current while appearing healthy.
  if (!parsed.success) return { configured: false, reason: Array.isArray(json) && json.length === 0 ? 'KEYRING_EMPTY' : 'KEYRING_UNPARSEABLE' };

  const entries = parsed.data;
  if (new Set(entries.map((entry) => entry.signer_key_id)).size !== entries.length) {
    return { configured: false, reason: 'KEYRING_DUPLICATE_SIGNER_KEY_ID' };
  }

  const active = entries.filter((entry) => entry.role === 'ACTIVE');
  // Exactly one ACTIVE. Zero means nothing central signs today can be verified;
  // two means the keyring is describing a rotation that never completed, and
  // "which key is current" would be answered by whichever appeared first.
  if (active.length === 0) return { configured: false, reason: 'KEYRING_NO_ACTIVE_KEY' };
  if (active.length > 1) return { configured: false, reason: 'KEYRING_MULTIPLE_ACTIVE_KEYS' };

  // The curve check at LOAD. A structurally perfect off-curve point parses
  // cleanly at every contract boundary; only the runtime import refuses it, and
  // finding out at boot beats finding out when an anchor arrives.
  if (entries.some((entry) => !isOnCurve(entry.public_key))) return { configured: false, reason: 'KEYRING_KEY_NOT_ON_CURVE' };

  const byId = new Map(entries.map((entry) => [entry.signer_key_id, entry]));
  return {
    configured: true,
    version: (config.EDGE_TRUSTED_TIME_KEYRING_VERSION as string).trim(),
    // BY ID, never by trial. Trying every key until one verifies would make the
    // statement's own `signer_key_id` decorative, and a signature that verifies
    // under a key the statement did not name is not the statement central made.
    resolve: (signerKeyId) => byId.get(signerKeyId) ?? null,
  };
}

/**
 * THE BINDING, in the file the module imports, so a spec exercises the SHIPPING
 * WIRING rather than an override.
 */
@Injectable()
export class EdgeTrustedTimeKeyringProvider {
  private readonly logger = new Logger(EdgeTrustedTimeKeyringProvider.name);
  readonly keyring: EdgeTrustedTimeKeyring;

  constructor(config: EdgeConfig, isOnCurve: (publicKey: string) => boolean) {
    this.keyring = edgeTrustedTimeKeyringIsConfigured(config) ? loadEdgeTrustedTimeKeyring(config, isOnCurve) : unconfiguredEdgeTrustedTimeKeyring();
    if (!this.keyring.configured) {
      // A REASON CODE ONLY. No key material, no configuration values.
      this.logger.error(
        `edge trusted-time keyring NOT USABLE: reason=${this.keyring.reason}. ` +
          'Every persisted anchor will be refused and Edge will hold no trusted time until this is corrected.',
      );
    }
  }
}

export const EDGE_TRUSTED_TIME_KEYRING_BINDING: Provider = {
  provide: EDGE_TRUSTED_TIME_KEYRING,
  inject: [EdgeConfigService, P256AnchorSignatureVerifier],
  useFactory: (config: EdgeConfigService, verifier: P256AnchorSignatureVerifier): EdgeTrustedTimeKeyring =>
    new EdgeTrustedTimeKeyringProvider(config.values, (publicKey) => verifier.isRuntimeValidPublicKey(publicKey)).keyring,
};
