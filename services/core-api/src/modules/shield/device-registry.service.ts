import { Inject, Injectable } from '@nestjs/common';
import {
  DeviceRegistryKeyRecordSchema,
  deviceKeyStatePermitsNewOperations,
  type DeviceCustody,
  type DeviceKeyLifecycleState,
  type DeviceKeyStorage,
  type DeviceRegistryKeyRecord,
  type DeviceRevocationDisposition,
  type DeviceTrust,
} from '@sentinel/contracts';
import type { Principal } from '../../common/security/principal';
import { checkDeviceAuthority, readableSiteIds } from './shield.authority';
import { ACTION_DEVICE_REGISTRY_READ } from './shield.constants';
import { ShieldRepository, type DeviceKeyRow, type DeviceRow } from './shield.repository';
import type { DeviceStanding, ListDevicesOutcome, ReadDeviceStandingOutcome } from './shield.types';

/**
 * WP-24 — the registry's READ side, and the one question every later work
 * package will ask it.
 *
 * D24-09: DEVICE-LEVEL AND KEY-LEVEL WITHDRAWAL ARE INDEPENDENT CHECKS.
 *
 * This is C15-R4-final's rule applied to the device side of the same problem,
 * and it is the reason `admitsNewOperations` exists as a computed field rather
 * than as something each caller assembles. The two rows move at different
 * times and by different paths:
 *
 *   - `COMPROMISED_KEY` marks the KEY compromised and the DEVICE compromised,
 *     but they are two writes, and a reader can observe the world between them;
 *   - `STOLEN` revokes the credential at the DEVICE level while the key row
 *     may still say `CURRENT` for an instant;
 *   - a key can be withdrawn on its own — a leaked credential on a device we
 *     otherwise still trust — with the device row untouched by design.
 *
 * So no caller may assume both rows moved together. EITHER one saying the
 * credential is gone is sufficient on its own, and the two half-answers are
 * exposed separately (`deviceLevelWithdrawn`, `keyLevelWithdrawn`) precisely so
 * a future reader cannot quietly start consulting one of them alone.
 */
@Injectable()
export class DeviceRegistryService {
  constructor(@Inject(ShieldRepository) private readonly repository: ShieldRepository) {}

  /**
   * One device's standing, for a human holding `device.registry.read`.
   *
   * ISOLATION: a device in another tenant and a device id that never existed
   * both answer `DEVICE_NOT_FOUND`, and so does a device at a site outside the
   * reader's scope. Any distinction between those would be a cross-tenant or
   * cross-site existence oracle over the hardware roster, which is exactly the
   * kind of reconnaissance a device registry must not offer.
   */
  async readDeviceStanding(
    principal: Principal,
    input: { organisationId: string; deviceId: string },
  ): Promise<ReadDeviceStandingOutcome> {
    if (checkDeviceAuthority(principal, ACTION_DEVICE_REGISTRY_READ, input.organisationId, null) !== null) {
      return { outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' };
    }
    const device = await this.repository.findDevice(input.organisationId, input.deviceId);
    if (device === null) return { outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' };

    const siteIds = await this.repository.listDeviceSiteIds(input.organisationId, device.id);
    const scope = readableSiteIds(principal, ACTION_DEVICE_REGISTRY_READ);
    // Site narrowing applied to the ANSWER, not only to the query: a
    // site-scoped reader must not learn that a device exists at a site they do
    // not hold, and the refusal must be the same one they get for an invented
    // id.
    if (scope !== null && !siteIds.some((siteId) => scope.includes(siteId))) {
      return { outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' };
    }

    return { outcome: 'FOUND', standing: await this.buildStanding(device, siteIds) };
  }

  /** The roster, organisation-scoped and narrowed to the reader's granted sites. */
  async listDevices(principal: Principal, input: { organisationId: string }): Promise<ListDevicesOutcome> {
    if (checkDeviceAuthority(principal, ACTION_DEVICE_REGISTRY_READ, input.organisationId, null) !== null) {
      return { outcome: 'REFUSED', refusal: 'NOT_AUTHORISED' };
    }
    const rows = await this.repository.listDevices(input.organisationId, readableSiteIds(principal, ACTION_DEVICE_REGISTRY_READ));
    const devices: DeviceStanding[] = [];
    for (const row of rows) {
      devices.push(await this.buildStanding(row, await this.repository.listDeviceSiteIds(input.organisationId, row.id)));
    }
    return { outcome: 'FOUND', devices };
  }

  /**
   * D24-02's third rule, as a SEPARATE METHOD THAT TAKES NO PRINCIPAL.
   *
   * "When WP-25's gateway later resolves a registry record to authenticate an
   * incoming device, that is an internal service call, not a
   * `device.registry.read` performed by a person, and it must not be modelled
   * as one." Modelling it as one would mean minting a synthetic principal to
   * satisfy a guard, and a synthetic principal in a security module is a
   * standing invitation to hand it to something else.
   *
   * The lookup is keyed by ORGANISATION AND key id together, for the reason the
   * Whisper resolver gives: a key id is a registry identifier, not a global
   * secret, so keying by id alone would let one tenant's registered key be
   * selected by another tenant's context.
   *
   * The record is returned ONLY when it parses as a `DeviceRegistryKeyRecord`,
   * which re-derives the thumbprint from the key and refuses a row whose
   * status and timestamps tell different stories. A registry row that cannot
   * satisfy its own contract is not handed to a verifier.
   */
  async resolveRegistryKeyRecord(organisationId: string, keyId: string): Promise<DeviceRegistryKeyRecord | null> {
    const key = await this.repository.findDeviceKeyByKeyId(organisationId, keyId);
    if (key === null) return null;
    const parsed = DeviceRegistryKeyRecordSchema.safeParse({
      schema_version: 1,
      organisation_id: key.organisationId,
      device_id: key.deviceId,
      key_id: key.keyId,
      key_version: key.keyVersion,
      public_key: key.publicKey,
      public_key_thumbprint: key.publicKeyThumbprint,
      signature_profile: key.signatureProfile,
      key_storage: key.keyStorage,
      status: key.status,
      registered_at: key.registeredAt.toISOString(),
      rotated_at: key.rotatedAt === null ? null : key.rotatedAt.toISOString(),
      revoked_at: key.revokedAt === null ? null : key.revokedAt.toISOString(),
      revocation_disposition: key.revocationDisposition,
    });
    return parsed.success ? parsed.data : null;
  }

  /**
   * "May this device do new work?" — the helper D24-09 requires, consulting
   * BOTH rows and assuming nothing about whether they moved together.
   *
   * Returns `false` for an unknown device, which is the only fail-closed
   * answer: a caller that cannot find a device has not established that it may
   * act, and treating "not found" as anything but a refusal would make the
   * whole registry optional.
   */
  async deviceAdmitsNewOperations(organisationId: string, deviceId: string): Promise<boolean> {
    const device = await this.repository.findDevice(organisationId, deviceId);
    if (device === null) return false;
    const key = device.currentKeyId === null ? null : await this.repository.findDeviceKeyByKeyId(organisationId, device.currentKeyId);
    return !this.deviceLevelWithdrawn(device) && !this.keyLevelWithdrawn(key);
  }

  private async buildStanding(device: DeviceRow, siteIds: string[]): Promise<DeviceStanding> {
    const key =
      device.currentKeyId === null ? null : await this.repository.findDeviceKeyByKeyId(device.organisationId, device.currentKeyId);
    const deviceLevelWithdrawn = this.deviceLevelWithdrawn(device);
    const keyLevelWithdrawn = this.keyLevelWithdrawn(key);
    return {
      deviceId: device.id,
      organisationId: device.organisationId,
      custody: device.custody as DeviceCustody,
      trust: device.trust as DeviceTrust,
      revocationDisposition: device.revocationDisposition as DeviceRevocationDisposition | null,
      revokedAt: device.revokedAt,
      sequenceNamespaceId: device.sequenceNamespaceId,
      currentKeyId: device.currentKeyId,
      currentKeyVersion: device.currentKeyVersion,
      currentKeyStatus: key === null ? null : (key.status as DeviceKeyLifecycleState),
      currentKeyStorage: key === null ? null : (key.keyStorage as DeviceKeyStorage),
      currentKeyRevokedAt: key === null ? null : key.revokedAt,
      siteIds,
      deviceLevelWithdrawn,
      keyLevelWithdrawn,
      // The AND is the only thing a caller should gate new work on, and it is
      // computed here rather than left to each caller for exactly the reason
      // C15-R4-final gives: the caller who forgets one half is the caller who
      // admits a compromised credential.
      admitsNewOperations: !deviceLevelWithdrawn && !keyLevelWithdrawn,
    };
  }

  /**
   * DEVICE-level withdrawal, asked on its own.
   *
   * A revocation instant OR a terminal trust state. `COMPROMISED` counts
   * without a `revoked_at` because D23-05 makes it terminal for the identity —
   * a device we believe is in an attacker's hands does no new work whether or
   * not a revocation column has caught up with that belief yet.
   */
  private deviceLevelWithdrawn(device: DeviceRow): boolean {
    return device.revokedAt !== null || device.trust === 'COMPROMISED';
  }

  /**
   * KEY-level withdrawal, asked on its own.
   *
   * `deviceKeyStatePermitsNewOperations` is the CONTRACT's answer to which of
   * the four lifecycle states may authorise new work, and it is called rather
   * than restated — the four-state machine is not collapsed into a boolean
   * here any more than it is in the schema (D24-01). A missing key row is
   * withdrawal too: a device whose current key cannot be found has no
   * credential to act with.
   */
  private keyLevelWithdrawn(key: DeviceKeyRow | null): boolean {
    if (key === null) return true;
    if (key.revokedAt !== null) return true;
    return !deviceKeyStatePermitsNewOperations(key.status as DeviceKeyLifecycleState);
  }
}
