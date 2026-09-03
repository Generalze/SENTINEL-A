import { Inject, Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import {
  DeviceRegistryKeyRecordSchema,
  deviceKeyStatePermitsNewOperations,
  deviceTrustPermitsPurpose,
  type DeviceCustody,
  type DeviceKeyLifecycleState,
  type DeviceKeyStorage,
  type DeviceRegistryKeyRecord,
  type DeviceRequestPurpose,
  type DeviceRevocationDisposition,
  type DeviceTrust,
} from '@sentinel/contracts';
import type { Principal } from '../../common/security/principal';
import { effectiveDeviceTrust, resolveAttestationStanding } from './attestation.standing';
import { checkDeviceAuthority, projectReadableDeviceSites, readableSiteIds } from './shield.authority';
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
 *
 * C16-07 — `deviceAdmitsNewOperations` OVERCLAIMED, AND IS NOW TWO QUESTIONS
 * ------------------------------------------------------------------------
 * That name read like operational authorisation. The function checked device
 * credential withdrawal and key lifecycle and NOTHING ELSE — so a QUARANTINED,
 * SUSPICIOUS or OFFLINE device with a perfectly healthy key satisfied it. WP-25
 * is about to consume this, and a gateway that gates work on a name it trusts
 * is a gateway that admits a device the registry has already stopped vouching
 * for.
 *
 *   `credentialAdmitsNewOperations`  the CREDENTIAL is intact. Nothing more.
 *   `deviceMayAct(org, device, purpose)`  the credential is intact AND current
 *                                    trust admits this PURPOSE, judged against
 *                                    the frozen `DEVICE_PURPOSE_PERMITTED_TRUST`
 *                                    matrix via `deviceTrustPermitsPurpose`.
 *
 * NEITHER IS COMPLETE AUTHORISATION (§62.1). User authority, site/context
 * authority and policy are SEPARATE, INDEPENDENT facts and this service can
 * answer none of them. A registered device never manufactures user authority,
 * and `deviceMayAct` returning `true` means only that the hardware half of the
 * question is satisfied.
 *
 * C16-06 — A SITE-SCOPED READER IS TOLD ONLY WHAT IT MAY SEE
 * -------------------------------------------------------
 * A read used to succeed if the reader held ONE of a device's sites, and then
 * returned the device's ENTIRE active site list. Holding site A was therefore a
 * way to enumerate every other site a device is deployed at. The standing now
 * carries the PROJECTION `projectReadableDeviceSites` computes: the reader's
 * granted scope intersected with the device's associations, and the full list
 * only for genuine organisation-wide authority.
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
    // C16-06: the projection decides BOTH whether this reader may see the
    // device at all and WHICH of its sites they are told about. `null` is
    // "not visible", and it is reported as the same refusal an invented id
    // gets — a site-scoped reader must not learn that a device exists at a site
    // they do not hold, nor that it is ALSO deployed somewhere they cannot see.
    const visibleSiteIds = projectReadableDeviceSites(principal, ACTION_DEVICE_REGISTRY_READ, input.organisationId, siteIds);
    if (visibleSiteIds === null) return { outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' };

    return { outcome: 'FOUND', standing: await this.buildStanding(device, visibleSiteIds) };
  }

  /** The roster, organisation-scoped and narrowed to the reader's granted sites. */
  async listDevices(principal: Principal, input: { organisationId: string }): Promise<ListDevicesOutcome> {
    if (checkDeviceAuthority(principal, ACTION_DEVICE_REGISTRY_READ, input.organisationId, null) !== null) {
      return { outcome: 'REFUSED', refusal: 'NOT_AUTHORISED' };
    }
    const rows = await this.repository.listDevices(input.organisationId, readableSiteIds(principal, ACTION_DEVICE_REGISTRY_READ));
    const devices: DeviceStanding[] = [];
    for (const row of rows) {
      const siteIds = await this.repository.listDeviceSiteIds(input.organisationId, row.id);
      // C16-06: the SAME projection the single read applies. A roster that
      // narrowed the QUERY but not the ANSWER would leak through the list what
      // the single read no longer leaks directly.
      const visibleSiteIds = projectReadableDeviceSites(principal, ACTION_DEVICE_REGISTRY_READ, input.organisationId, siteIds);
      if (visibleSiteIds === null) continue;
      devices.push(await this.buildStanding(row, visibleSiteIds));
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
   *
   * WP-25/C17-04: `tx` IS NOT OPTIONAL DECORATION. A caller that has taken the
   * device and key row locks and then resolves the key OUTSIDE its transaction
   * is reading a row nothing is holding still — the registry could have rotated
   * or withdrawn it in the gap, and the decision would commit against a fact
   * that was already stale when it was read. Every gateway call site inside a
   * final transaction passes its `tx`; the preflight, which commits nothing,
   * deliberately does not.
   */
  async resolveRegistryKeyRecord(
    organisationId: string,
    keyId: string,
    tx?: Prisma.TransactionClient,
  ): Promise<DeviceRegistryKeyRecord | null> {
    const key = await this.repository.findDeviceKeyByKeyId(organisationId, keyId, tx);
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
   * C16-07: "IS THE CREDENTIAL INTACT?" — and that question ONLY.
   *
   * The D24-09 helper, renamed from `deviceAdmitsNewOperations` because the old
   * name promised something it never delivered. It consults BOTH the device row
   * and the key row, assuming nothing about whether they moved together, and it
   * consults CURRENT TRUST NOT AT ALL. A QUARANTINED device with a healthy key
   * returns `true` here, correctly: its credential IS intact. Whether it may
   * DO anything is a different question, and `deviceMayAct` is where it is
   * asked.
   *
   * Returns `false` for an unknown device, which is the only fail-closed
   * answer: a caller that cannot find a device has not established that it may
   * act, and treating "not found" as anything but a refusal would make the
   * whole registry optional.
   */
  async credentialAdmitsNewOperations(organisationId: string, deviceId: string, tx?: Prisma.TransactionClient): Promise<boolean> {
    const device = await this.repository.findDevice(organisationId, deviceId, tx);
    if (device === null) return false;
    const key = device.currentKeyId === null ? null : await this.repository.findDeviceKeyByKeyId(organisationId, device.currentKeyId, tx);
    return !this.deviceLevelWithdrawn(device) && !this.keyLevelWithdrawn(key);
  }

  /**
   * WP-27/D24-09 — THE TWO WITHDRAWALS, EXPOSED SEPARATELY AND PRINCIPAL-FREE.
   *
   * `credentialAdmitsNewOperations` above returns the AND of the two, which is
   * the right answer for a caller that only needs "may this credential act?".
   * It is the WRONG shape for a caller whose contract asks the two questions
   * INDEPENDENTLY — and `evaluateWhisperDeviceActionV2Admissibility` does, for
   * exactly the reason C15-R4-final gives: the device row and the key row move
   * at different times by different paths, so an evaluator that received one
   * fused boolean could not name which half withdrew the credential, and an
   * operator reading the audit could not either.
   *
   * The two halves are ALREADY computed here, by `deviceLevelWithdrawn` and
   * `keyLevelWithdrawn`, and this method exposes those same helpers rather than
   * letting a caller re-derive them. A second implementation of "is this
   * credential withdrawn?" outside Shield is precisely what D24-09 exists to
   * prevent: the failure mode is not that the copy is wrong on the day it is
   * written, it is that the two drift and only one is the one an auditor reads.
   *
   * `null` for an unknown device — the only fail-closed answer, matching
   * `credentialAdmitsNewOperations` and `effectiveDeviceTrust`.
   */
  async credentialWithdrawal(
    organisationId: string,
    deviceId: string,
    tx?: Prisma.TransactionClient,
  ): Promise<{ deviceLevelWithdrawn: boolean; keyLevelWithdrawn: boolean } | null> {
    const device = await this.repository.findDevice(organisationId, deviceId, tx);
    if (device === null) return null;
    const key = device.currentKeyId === null ? null : await this.repository.findDeviceKeyByKeyId(organisationId, device.currentKeyId, tx);
    return { deviceLevelWithdrawn: this.deviceLevelWithdrawn(device), keyLevelWithdrawn: this.keyLevelWithdrawn(key) };
  }

  /**
   * C16-R5's EFFECTIVE standing, exposed as a VALUE, principal-free.
   *
   * WP-25 needs the trust WORD and not merely a boolean: the frozen
   * `DeviceRegistryFacts.trust` is a `DeviceTrust`, and
   * `evaluateDeviceOperationPrincipals` takes one too. Before this method the
   * only way to obtain it from outside was `readDeviceStanding`, which is a
   * `device.registry.read` PERFORMED BY A PERSON and requires a principal —
   * and D24-02 is explicit that the gateway resolving a registry record to
   * authenticate an incoming device is an internal service call and must not
   * be modelled as one. Minting a synthetic principal to satisfy that guard is
   * exactly what the ruling forbids.
   *
   * It is a one-line delegation to the SAME private resolution `deviceMayAct`
   * and `buildStanding` use, deliberately: C16-R5's whole point is that there
   * is ONE canonical effective-standing resolution, so a second caller gets
   * the same answer rather than a second implementation of it. `null` for an
   * unknown device, which is the only fail-closed answer — a caller that
   * cannot find a device has established nothing about its standing.
   *
   * WP-25/D25-16: `tx` joins the caller's transaction so the D25-04A fence
   * reads this under the same locks it re-reads everything else under.
   */
  async effectiveDeviceTrust(organisationId: string, deviceId: string, tx?: Prisma.TransactionClient): Promise<DeviceTrust | null> {
    const device = await this.repository.findDevice(organisationId, deviceId, tx);
    if (device === null) return null;
    return this.effectiveDeviceStanding(device, tx);
  }

  /**
   * C16-07: "MAY THIS DEVICE ACT FOR THIS PURPOSE?" — credential AND trust.
   *
   * Two independent facts, ANDed, and both are the registry's own:
   *
   *   1. the credential is intact (`credentialAdmitsNewOperations`);
   *   2. CURRENT trust admits this purpose, judged by
   *      `deviceTrustPermitsPurpose` against the frozen
   *      `DEVICE_PURPOSE_PERMITTED_TRUST` matrix. The matrix is the contract's
   *      and is never restated here: WHISPER_DEVICE_ACTION admits TRUSTED
   *      alone (W21-05), RECONNECT_HANDSHAKE is deliberately the widest, and
   *      widening any row is a security-contract change.
   *
   * THIS IS STILL NOT COMPLETE AUTHORISATION (§62.1).
   *
   *     USER AUTHORITY + DEVICE IDENTITY + CURRENT DEVICE TRUST
   *       + SITE/CONTEXT AUTHORITY
   *
   * must remain INDEPENDENT facts. This method answers the middle two and has
   * no way to answer the others: it takes no principal, knows nothing about the
   * site an operation touches, and evaluates no policy. A caller that treats
   * `true` as permission to proceed has collapsed four facts into one, which is
   * precisely the fusion the whole module is shaped to prevent. WP-25's gateway
   * must ask this AND the user-authority question AND the site/context
   * question, separately, and require all of them.
   */
  async deviceMayAct(
    organisationId: string,
    deviceId: string,
    purpose: DeviceRequestPurpose,
    tx?: Prisma.TransactionClient,
  ): Promise<boolean> {
    const device = await this.repository.findDevice(organisationId, deviceId, tx);
    if (device === null) return false;
    const key = device.currentKeyId === null ? null : await this.repository.findDeviceKeyByKeyId(organisationId, device.currentKeyId, tx);
    if (this.deviceLevelWithdrawn(device) || this.keyLevelWithdrawn(key)) return false;
    // C16-R5: the EFFECTIVE trust, not the persisted column. See
    // `effectiveDeviceStanding` — a device whose attestation aged out of the
    // six-hour grace while nothing was observing it still reads TRUSTED in the
    // database, and reading that column here is what let it keep firing Whisper.
    return deviceTrustPermitsPurpose(await this.effectiveDeviceStanding(device, tx), purpose);
  }

  /**
   * C16-R5 — THE ONE CANONICAL EFFECTIVE-DEVICE-STANDING RESOLUTION.
   *
   * Every surface in this service that reports or acts on trust asks THIS, and
   * nothing reads `device.trust` for an authorisation or standing answer any
   * more.
   *
   * WHY IT EXISTS. `device.trust` is a persisted conclusion, and for `TRUSTED`
   * that conclusion rests on attestation evidence with an expiry. C16-05 made
   * the expiry act — but only when an observation ARRIVES. A device that goes
   * dark inside the grace and is never looked at again crosses the six-hour
   * boundary with nothing running: no observation, no job, no write. The row
   * says TRUSTED for ever, and before this method `deviceMayAct` believed it.
   *
   * HOW. The attestation history is resolved through the module's ONE evidence
   * selector (`resolveAttestationStanding`, C16-05) against AUTHORITATIVE SERVER
   * TIME — `clock_timestamp()`, read in the same transaction as the evidence,
   * consistent with every other timing decision in this module — and the
   * standing is reconciled with the persisted trust by `effectiveDeviceTrust`,
   * which calls the contract's `attestationStandingPermitsTrusted` rather than
   * restating any policy.
   *
   * IT FAILS CLOSED IMMEDIATELY AND WRITES NOTHING. The degradation takes effect
   * on the very next question asked. It deliberately does NOT mutate the device
   * row: a read path that writes turns every authorisation check into a writer
   * and would race the observation path that owns the durable
   * `TRUSTED -> DEGRADED` transition and its D24-08 record.
   */
  private async effectiveDeviceStanding(device: DeviceRow, tx?: Prisma.TransactionClient): Promise<DeviceTrust> {
    const persisted = device.trust as DeviceTrust;
    // Only TRUSTED rests on expiring evidence, so only TRUSTED needs the
    // history read. Skipping it elsewhere is not an optimisation dressed as a
    // rule: `effectiveDeviceTrust` returns the persisted value unchanged for
    // every other state, so the read could not change the answer.
    if (persisted !== 'TRUSTED') return persisted;
    const evidence = await this.repository.readAttestationEvidence(device.organisationId, device.id, tx);
    return effectiveDeviceTrust(persisted, resolveAttestationStanding(evidence));
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
      // C16-R5: THE EFFECTIVE TRUST. The registry must never advertise a
      // TRUSTED it would refuse to act on a line later, so the read surface
      // applies exactly the resolution `deviceMayAct` applies. `persistedTrust`
      // beside it is the raw column, for an operator who needs to see that the
      // durable row has not caught up yet.
      trust: await this.effectiveDeviceStanding(device),
      persistedTrust: device.trust as DeviceTrust,
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
      // The AND of the two CREDENTIAL checks, computed here rather than left
      // to each caller for exactly the reason C15-R4-final gives: the caller
      // who forgets one half is the caller who admits a compromised credential.
      // C16-07: it is named `credential...` because it is not, and never was,
      // an answer about whether the device may operate.
      credentialAdmitsNewOperations: !deviceLevelWithdrawn && !keyLevelWithdrawn,
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
