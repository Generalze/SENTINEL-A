import { Inject, Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { WHISPER_DEVICE_ACTION_V2_PROFILE, type WhisperDeviceActionV2RegistryFacts } from '@sentinel/contracts';
import { DeviceRegistryService } from '../shield/device-registry.service';
import { ShieldRepository } from '../shield/shield.repository';

/**
 * WP-27 — V2 KEY RESOLUTION, FROM THE SHIELD ENROLLED-DEVICE REGISTRY ONLY.
 *
 * THIS IS NOT THE WHISPER v1 RESOLVER, AND IT MAY NEVER BECOME ONE.
 * `WhisperDeviceKeyResolver` / `FailClosedWhisperDeviceKeyResolver` verify
 * Ed25519 under the FROZEN v1 contract and are not imported, referenced or
 * subclassed anywhere in this module. There is no `Ed25519 | P256` union and no
 * path by which a v1 resolver could be handed a P-256 key or a v2 resolver an
 * Ed25519 one. The two are separate implementations of separate contracts,
 * which is what "versioned forward" means.
 *
 * THE KEY IS NEVER TAKEN FROM THE REQUEST, AND THE LOOKUP IS NEVER STEERED BY IT
 * -----------------------------------------------------------------------------
 * The resolution starts from the DEVICE ROW's own current key pointer —
 * `device.currentKeyId`, inside the organisation the SERVER established — and
 * not from the `key_id` the statement names. That ordering is deliberate and is
 * WP-25's, quoted: a lookup keyed on a client-supplied identifier is a lookup a
 * client can steer, and the only safe use of a claimed key id is to be
 * EQUALITY-BOUND against what the registry independently resolved. That binding
 * happens in the frozen evaluator
 * (`evaluateWhisperDeviceActionV2Admissibility`, steps 2 and 3), so a statement
 * naming another device's key, an older version, or a key that does not exist
 * is a refusal rather than a different verification.
 *
 * THERE IS NO FALLBACK. Not to another key, not to another version, not to
 * another profile, not to a "historical verification" key. A key that does not
 * resolve, does not carry `P256_ECDSA_SHA256`, does not permit new operations,
 * or whose device or key has been withdrawn produces `null` here and a REFUSAL
 * there. `null` is the only fail-closed answer, and it is deliberately the same
 * answer for every cause: a caller able to distinguish "no such device" from
 * "rotated" from "revoked" holds an oracle over the registry.
 *
 * D24-09 / C15-R4-final: THE TWO WITHDRAWALS ARE ASKED INDEPENDENTLY.
 * `DeviceRegistryService.credentialWithdrawal` returns both halves separately
 * and this resolver passes both through, unfused, to the contract. The device
 * row and the key row move at different times by different paths — `STOLEN`
 * withdraws at the device level while the key row may still say `CURRENT` for
 * an instant; a leaked key is withdrawn on its own with the device row
 * untouched — so no caller may assume they moved together.
 *
 * NO CRYPTOGRAPHY IS IMPLEMENTED HERE. The point arithmetic, the curve check
 * and the signature verification are `P256KeyImporter`'s, which is OpenSSL's.
 */

export interface ResolvedWhisperDeviceActionKey {
  /** The canonical uncompressed SEC1 point, from the SERVER registry. */
  readonly publicKey: string;
  /** The CURRENT registry facts, with both withdrawals kept separate. */
  readonly registered: WhisperDeviceActionV2RegistryFacts;
}

@Injectable()
export class WhisperDeviceActionKeyResolver {
  constructor(
    @Inject(DeviceRegistryService) private readonly registry: DeviceRegistryService,
    @Inject(ShieldRepository) private readonly shield: ShieldRepository,
  ) {}

  /**
   * Resolves the registry facts for `deviceId` inside `organisationId`, or
   * `null`.
   *
   * `tx` is NOT optional decoration (C17-04). A caller inside a final effect
   * transaction that resolved the registry on the base client would be reading
   * a row nothing is holding still, in the transaction that commits on it.
   */
  async resolve(
    organisationId: string,
    deviceId: string,
    tx: Prisma.TransactionClient,
  ): Promise<ResolvedWhisperDeviceActionKey | null> {
    const device = await this.shield.findDevice(organisationId, deviceId, tx);
    if (device === null) return null;
    if (device.currentKeyId === null) return null;

    const keyRecord = await this.registry.resolveRegistryKeyRecord(organisationId, device.currentKeyId, tx);
    if (keyRecord === null) return null;
    // The record must be about THIS device. `findDeviceKeyByKeyId` is keyed on
    // (organisation, key id), and the device row's pointer is what selected it —
    // but a registry whose two rows disagree is a registry this module refuses
    // to act on rather than one it reconciles.
    if (keyRecord.device_id !== device.id) return null;

    const withdrawal = await this.registry.credentialWithdrawal(organisationId, device.id, tx);
    if (withdrawal === null) return null;

    // C16-R5: the EFFECTIVE standing, not the persisted column. A device whose
    // attestation aged out of its grace while nothing was observing it still
    // reads TRUSTED in the database, and reading that column here is exactly
    // what would let it keep firing the covert channel.
    const trust = await this.registry.effectiveDeviceTrust(organisationId, device.id, tx);
    if (trust === null) return null;

    return {
      publicKey: keyRecord.public_key,
      registered: {
        organisation_id: keyRecord.organisation_id,
        device_id: keyRecord.device_id,
        key_id: keyRecord.key_id,
        key_version: keyRecord.key_version,
        signature_profile: keyRecord.signature_profile,
        key_state: keyRecord.status,
        // The two halves, passed through UNFUSED. Collapsing them here would
        // undo D24-09 one layer below the contract that asks for both.
        device_revoked: withdrawal.deviceLevelWithdrawn,
        key_revoked: withdrawal.keyLevelWithdrawn,
        revocation_disposition: keyRecord.revocation_disposition,
        trust,
      },
    };
  }

  /**
   * The profile a v2 statement may be verified under, exposed so a caller can
   * gate BEFORE it reaches a verifier rather than discovering the mismatch
   * inside one.
   */
  supportsProfile(profile: string): boolean {
    return profile === WHISPER_DEVICE_ACTION_V2_PROFILE;
  }
}
