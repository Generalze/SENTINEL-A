import { Injectable, Logger, type Provider } from '@nestjs/common';
import { DeviceP256PublicKeySchema } from '@sentinel/contracts';
import { z } from 'zod';
import { AppConfigService } from '../../config/config.service';
import type { AppConfig } from '../../config/env.schema';

/**
 * M3B §7 — CENTRAL'S OWN VERIFICATION KEYRING.
 *
 * WHY CENTRAL NEEDS ONE AT ALL, WHEN IT HOLDS THE SIGNING KEY
 * ----------------------------------------------------------
 * The obvious shortcut is to derive the public key from the private key
 * central already has. It is wrong for one specific reason: an anchor minted
 * BEFORE a key rotation was signed by the PREVIOUS key, and an Edge may
 * legitimately still be holding it -- anchors live up to the six-hour offline
 * ceiling. A verifier that could only check the currently-active key would
 * begin silently refusing every in-flight anchor the moment a rotation
 * happened, and the failure would look like Edge misbehaviour rather than a
 * central configuration event.
 *
 * So central resolves BY `signer_key_id`, exactly as Edge does, against the
 * same list. This is intentionally a mirror of
 * `services/edge-runtime/src/modules/trusted-time/edge-trusted-time.keyring.ts`
 * -- same JSON, same roles, same refusal vocabulary. Two ends of one
 * agreement, and a reader who has understood one has understood the other.
 *
 * NEVER "TRY THEM ALL". `resolve` returns `null` for an unknown id rather than
 * attempting each key in turn. Trying every key would mean a signature made by
 * ANY key in the ring is accepted regardless of which one the statement claims
 * -- which quietly destroys the ability to retire a key, because a compromised
 * PREVIOUS key would keep working for anything that simply named a different id.
 *
 * PUBLIC MATERIAL ONLY. The entry schema is strict and declares no field a
 * private key could arrive in, so a deployment that pasted the wrong half of a
 * keypair gets a parse failure instead of a running service.
 */

export const CentralTrustedTimeKeyRoleSchema = z.enum(['ACTIVE', 'PREVIOUS']);
export type CentralTrustedTimeKeyRole = z.infer<typeof CentralTrustedTimeKeyRoleSchema>;

export const CentralTrustedTimeVerificationKeySchema = z
  .object({
    signer_key_id: z.string().min(1).max(256),
    /** Canonical uncompressed SEC1 P-256 point, base64url. Curve-checked at load. */
    public_key: DeviceP256PublicKeySchema,
    role: CentralTrustedTimeKeyRoleSchema,
  })
  .strict();
export type CentralTrustedTimeVerificationKey = z.infer<typeof CentralTrustedTimeVerificationKeySchema>;

/**
 * At most two: one ACTIVE and one PREVIOUS. A ring that could grow without
 * bound would let retired keys accumulate forever, and "how many keys can sign
 * a trusted time" is exactly the number that should stay small and boring.
 */
const CentralTrustedTimeKeyringSchema = z.array(CentralTrustedTimeVerificationKeySchema).min(1).max(2);

/** Why the configured keyring could not be used. A code, never material. */
export type CentralTrustedTimeKeyringRefusal =
  | 'KEYRING_NOT_CONFIGURED'
  | 'KEYRING_UNPARSEABLE'
  | 'KEYRING_EMPTY'
  | 'KEYRING_DUPLICATE_SIGNER_KEY_ID'
  | 'KEYRING_NO_ACTIVE_KEY'
  | 'KEYRING_MULTIPLE_ACTIVE_KEYS'
  | 'KEYRING_KEY_NOT_ON_CURVE';

export type CentralTrustedTimeKeyring =
  | { readonly configured: false; readonly reason: CentralTrustedTimeKeyringRefusal }
  | {
      readonly configured: true;
      /** Resolve by id. An absent id means "we cannot verify this", never "try another". */
      resolve(signerKeyId: string): CentralTrustedTimeVerificationKey | null;
    };

export const CENTRAL_TRUSTED_TIME_KEYRING = Symbol('CENTRAL_TRUSTED_TIME_KEYRING');

export const CENTRAL_TRUSTED_TIME_KEYRING_KEYS = [
  'EDGE_TRUSTED_TIME_VERIFICATION_KEYS',
] as const satisfies readonly (keyof AppConfig)[];

export function centralTrustedTimeKeyringIsConfigured(config: AppConfig): boolean {
  return CENTRAL_TRUSTED_TIME_KEYRING_KEYS.some((key) => config[key] !== undefined);
}

/**
 * Loads and validates the ring.
 *
 * `isOnCurve` is injected rather than imported so this stays a pure function
 * that a test can drive with a stub. The curve check is not decoration: a point
 * that is not on P-256 is not a key, and accepting one would mean a signature
 * check that can never succeed but also never says why.
 */
export function loadCentralTrustedTimeKeyring(
  config: AppConfig,
  isOnCurve: (publicKey: string) => boolean,
): CentralTrustedTimeKeyring {
  const raw = config.EDGE_TRUSTED_TIME_VERIFICATION_KEYS;
  if (raw === undefined) return { configured: false, reason: 'KEYRING_NOT_CONFIGURED' };

  let parsedJson: unknown;
  try {
    parsedJson = JSON.parse(raw);
  } catch {
    return { configured: false, reason: 'KEYRING_UNPARSEABLE' };
  }

  const parsed = CentralTrustedTimeKeyringSchema.safeParse(parsedJson);
  if (!parsed.success) {
    // An empty array and a malformed entry are different operator mistakes and
    // are reported differently, because "you configured nothing" and "you
    // configured something wrong" lead to different next actions.
    return {
      configured: false,
      reason: Array.isArray(parsedJson) && parsedJson.length === 0 ? 'KEYRING_EMPTY' : 'KEYRING_UNPARSEABLE',
    };
  }

  const keys = parsed.data;

  const ids = new Set(keys.map((key) => key.signer_key_id));
  if (ids.size !== keys.length) return { configured: false, reason: 'KEYRING_DUPLICATE_SIGNER_KEY_ID' };

  const active = keys.filter((key) => key.role === 'ACTIVE');
  if (active.length === 0) return { configured: false, reason: 'KEYRING_NO_ACTIVE_KEY' };
  // Two ACTIVE keys is an ambiguity, and this codebase refuses ambiguities
  // rather than picking one -- the same rule the transport identity index
  // enforces in the database.
  if (active.length > 1) return { configured: false, reason: 'KEYRING_MULTIPLE_ACTIVE_KEYS' };

  if (keys.some((key) => !isOnCurve(key.public_key))) {
    return { configured: false, reason: 'KEYRING_KEY_NOT_ON_CURVE' };
  }

  const byId = new Map(keys.map((key) => [key.signer_key_id, key]));
  return {
    configured: true,
    resolve: (signerKeyId: string): CentralTrustedTimeVerificationKey | null => byId.get(signerKeyId) ?? null,
  };
}

@Injectable()
export class CentralTrustedTimeKeyringProvider {
  private readonly logger = new Logger(CentralTrustedTimeKeyringProvider.name);

  constructor(private readonly config: AppConfigService) {}

  load(isOnCurve: (publicKey: string) => boolean): CentralTrustedTimeKeyring {
    const keyring = loadCentralTrustedTimeKeyring(this.config.values, isOnCurve);
    if (!keyring.configured) {
      // Logged at warn, not error, and WITHOUT the material. An unconfigured
      // ring is a legitimate state for a deployment that does not yet verify
      // Edge time evidence; what must never happen silently is a MISconfigured
      // one being treated as absent.
      this.logger.warn(`central trusted-time verification keyring unavailable: ${keyring.reason}`);
    }
    return keyring;
  }
}

export const CENTRAL_TRUSTED_TIME_KEYRING_PROVIDER: Provider = {
  provide: CentralTrustedTimeKeyringProvider,
  useClass: CentralTrustedTimeKeyringProvider,
};
