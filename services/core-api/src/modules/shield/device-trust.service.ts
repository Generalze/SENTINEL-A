import { Inject, Injectable } from '@nestjs/common';
import {
  DEVICE_TRUST_RESTORATION_CAPABILITY,
  DEVICE_TRUST_RESTORATION_REQUIRED_FROM,
  canTransitionDeviceKeyLifecycle,
  deviceKeyStatePermitsNewOperations,
  evaluateAttestationStanding,
  evaluateDeviceTrustTransition,
  type DeviceAttestationOutcome,
  type DeviceAttestationStanding,
  type DeviceControlledRestorationDecision,
  type DeviceKeyLifecycleState,
  type DeviceKeyStorage,
  type DeviceRevocationDisposition,
  type DeviceTrust,
} from '@sentinel/contracts';
import type { Principal } from '../../common/security/principal';
import { DEVICE_ATTESTATION_EVALUATOR, type DeviceAttestationEvaluator } from './attestation.evaluator';
import { DeviceSecurityAudit } from './device-security-audit';
import { checkDeviceAuthority } from './shield.authority';
import {
  ACTION_DEVICE_REVOKE,
  ACTION_DEVICE_TRUST_MANAGE,
  ACTION_DEVICE_TRUST_RESTORE,
} from './shield.constants';
import { ShieldRepository, type DeviceKeyRow, type DeviceRow, type Tx } from './shield.repository';
import type { ChangeDeviceTrustOutcome, DeclareDeviceDispositionOutcome, RecordAttestationOutcome } from './shield.types';

/**
 * WP-24/D24-08, D24-09 — SERVER-OWNED TRUST, AND THE THREE DIFFERENT FACTS.
 *
 * NOTHING IN THIS FILE DECIDES WHETHER A TRUST MOVE IS ALLOWED.
 * `evaluateDeviceTrustTransition` decides, every time, without exception, and
 * this service's job is to assemble the SERVER FACTS that evaluator needs and
 * to make the result durable. The distinction matters because D23-05's rules —
 * COMPROMISED is terminal, a device never promotes itself, a restoration needs
 * an explicit capability AND qualifying evidence, a revoked credential climbs
 * nowhere — are precisely the rules that get quietly re-implemented slightly
 * differently in a service and then diverge.
 *
 * EVERY BASIS FIELD IS A SERVER FACT
 * ----------------------------------
 *   controlledRestoration   an explicit human decision, minted here only when
 *                           the PRINCIPAL actually holds `device.trust.restore`
 *                           in the §62 table. A caller cannot supply one.
 *   attestationStanding     computed by `evaluateAttestationStanding` from the
 *                           append-only observation history.
 *   keyStorage              from the registered key row.
 *   credentialContinuity    from the key's lifecycle state.
 *   revoked                 both halves of D24-09's independent check.
 *   previouslyEligible      from the append-only transition history.
 *
 * `deviceReportedHealth` is never passed, because there is no channel in this
 * work package through which a device could report anything. The contract
 * accepts the field and provably ignores it; this service does not even have
 * one to ignore.
 *
 * D24-09'S THREE FACTS ARE THREE DIFFERENT WRITES
 * ----------------------------------------------
 *   LOST             quarantine. The KEY is untouched and a controlled
 *                    restoration path remains, because the hardware may still
 *                    be in honest hands and its credential continuity is intact.
 *   STOLEN           hostile possession assumed. The DEVICE credential is
 *                    revoked and the key is REVOKED; `basis.revoked` then makes
 *                    every upward transition refuse, so no restoration path
 *                    remains and no queued work can later create a new effect.
 *   COMPROMISED_KEY  the key is COMPROMISED and the device identity is
 *                    COMPROMISED. Terminal at BOTH levels. Recovery is a new
 *                    enrolled identity (D23-09), never rehabilitation.
 */
@Injectable()
export class DeviceTrustService {
  constructor(
    @Inject(ShieldRepository) private readonly repository: ShieldRepository,
    @Inject(DeviceSecurityAudit) private readonly audit: DeviceSecurityAudit,
    @Inject(DEVICE_ATTESTATION_EVALUATOR) private readonly attestation: DeviceAttestationEvaluator,
  ) {}

  // -------------------------------------------------------------------------
  // Attestation observations (D24-07)
  // -------------------------------------------------------------------------

  /**
   * Runs the server-owned attestation seam for one device and persists the
   * observation, append-only.
   *
   * The consequence is the CONTRACT's, not this method's. Negative evidence
   * (`NEGATIVE`, `INVALID`, `REVOKED`) acts immediately and quarantines,
   * because a device that failed verification is a device we know something bad
   * about. `UNAVAILABLE` does nothing at all, because a provider outage is not
   * a statement about a device — acting on it would let a third party's
   * downtime quarantine an entire fleet (C14-05).
   *
   * The quarantine still goes through `evaluateDeviceTrustTransition`. A
   * downward move is cheap in that matrix, but it is not free, and routing it
   * through the evaluator is what keeps COMPROMISED terminal even here.
   */
  async recordAttestationObservation(
    input: { organisationId: string; deviceId: string; traceId: string },
  ): Promise<RecordAttestationOutcome> {
    const device = await this.repository.findDevice(input.organisationId, input.deviceId);
    if (device === null) return { outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' };
    const key = await this.currentKey(device);
    if (key === null) return { outcome: 'REFUSED', refusal: 'DEVICE_KEY_NOT_FOUND' };

    const now = await this.repository.now();
    const evidence = await this.attestation.evaluate({
      organisationId: input.organisationId,
      deviceId: device.id,
      enrollmentRequestId: null,
      publicKeyThumbprint: key.publicKeyThumbprint,
      now: now.toISOString(),
    });

    return this.repository.transaction(async (tx) => {
      const observedAt = await this.repository.dbNow(tx);
      const observation = await this.repository.appendAttestationObservation(tx, {
        organisationId: input.organisationId,
        deviceId: device.id,
        enrollmentRequestId: null,
        outcome: evidence.outcome,
        attestationReference: evidence.attestation_reference,
        evaluatedAt: new Date(evidence.evaluated_at),
        observedAt,
        traceId: input.traceId,
      });

      const standing = evaluateAttestationStanding({
        outcome: evidence.outcome,
        lastVerifiedAt: null,
        now: observedAt.toISOString(),
        hasPriorVerified: false,
      });

      // NEGATIVE is the only standing that is device evidence AND actionable
      // without a human. EXPIRED, INELIGIBLE and INCONSISTENT all mean "we
      // cannot vouch", which lowers what the device may DO (through the trust
      // requirements of each operation) without being a statement that
      // something is wrong with it.
      if (standing.standing === 'NEGATIVE' && device.trust !== 'QUARANTINED') {
        const moved = await this.applyTrustTransition(tx, {
          device,
          key,
          to: 'QUARANTINED',
          reason: `ATTESTATION_${evidence.outcome}`,
          evidenceRefs: [`observation:${observation.id}`],
          authorisedByUserId: null,
          restorationDecision: null,
          now: observedAt,
          traceId: input.traceId,
        });
        if (moved.outcome === 'CHANGED') {
          await this.audit.record(
            tx,
            { organisationId: input.organisationId, deviceId: device.id, actorUserId: null, occurredAt: observedAt, traceId: input.traceId },
            { type: 'DEVICE_QUARANTINED', previousTrust: moved.previousTrust, reason: `ATTESTATION_${evidence.outcome}` },
          );
        }
      }

      return { outcome: 'RECORDED', observationId: observation.id, attestationOutcome: evidence.outcome };
    });
  }

  // -------------------------------------------------------------------------
  // Trust transitions (D24-08)
  // -------------------------------------------------------------------------

  /**
   * Moves a device's server-owned trust.
   *
   * TWO AUTHORITIES, NOT ONE (D24-02b). `device.trust.manage` is required for
   * any change. Climbing OUT of `SUSPICIOUS` or `QUARANTINED` additionally
   * requires `device.trust.restore`, and the two are deliberately separate:
   * folding restoration into routine trust administration would mean any
   * future role granted `device.trust.manage` — to flip a stale device to
   * OFFLINE, say — silently inherited the authority to vouch for a quarantined
   * one. That is exactly the inheritance D24-02 exists to prevent.
   *
   * The `DeviceControlledRestorationDecision` is MINTED HERE, from the
   * principal's actual §62 grant, and never accepted from a caller. Its
   * `capability` is the contract's own constant, so
   * `evaluateDeviceTrustTransition` refuses anything else by construction.
   */
  async changeDeviceTrust(
    principal: Principal,
    input: { organisationId: string; deviceId: string; to: DeviceTrust; reason: string; traceId: string },
  ): Promise<ChangeDeviceTrustOutcome> {
    const device = await this.repository.findDevice(input.organisationId, input.deviceId);
    if (device === null) return { outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' };

    const siteIds = await this.repository.listDeviceSiteIds(input.organisationId, device.id);
    const scopeRefusal = this.authoriseAgainstDeviceSites(principal, ACTION_DEVICE_TRUST_MANAGE, input.organisationId, siteIds);
    if (scopeRefusal !== null) return { outcome: 'REFUSED', refusal: scopeRefusal };

    const from = device.trust as DeviceTrust;
    const needsRestoration = DEVICE_TRUST_RESTORATION_REQUIRED_FROM.includes(from);
    if (needsRestoration && !principal.hasAction(ACTION_DEVICE_TRUST_RESTORE)) {
      // Reported as the CONTRACT's own refusal, because that is exactly what
      // the contract would say if it were handed a null decision — and it will
      // be, one line below, for any caller that reaches the evaluator without
      // the capability.
      return { outcome: 'REFUSED', refusal: 'RESTORATION_DECISION_REQUIRED' };
    }

    const key = await this.currentKey(device);

    return this.repository.transaction(async (tx) => {
      const now = await this.repository.dbNow(tx);
      const restorationDecision: DeviceControlledRestorationDecision | null =
        needsRestoration && principal.hasAction(ACTION_DEVICE_TRUST_RESTORE)
          ? {
              decided_by_user_id: principal.user.id,
              // The contract's constant, not a string typed here. A decision
              // carrying any other capability is refused by the evaluator.
              capability: DEVICE_TRUST_RESTORATION_CAPABILITY,
              decided_at: now.toISOString(),
            }
          : null;

      const result = await this.applyTrustTransition(tx, {
        device,
        key,
        to: input.to,
        reason: input.reason,
        evidenceRefs: [],
        authorisedByUserId: principal.user.id,
        restorationDecision,
        now,
        traceId: input.traceId,
      });

      if (result.outcome === 'CHANGED') {
        await this.audit.record(
          tx,
          { organisationId: input.organisationId, deviceId: device.id, actorUserId: principal.user.id, occurredAt: now, traceId: input.traceId },
          { type: 'TRUST_CHANGED', previousTrust: result.previousTrust, newTrust: result.newTrust, reason: input.reason, authorisedByUserId: principal.user.id },
        );
      }
      return result;
    });
  }

  // -------------------------------------------------------------------------
  // Lost, stolen, compromised (D24-09)
  // -------------------------------------------------------------------------

  /**
   * Declares one of the three dispositions, each of which is a DIFFERENT fact
   * with a different consequence at each of the two independent levels.
   *
   * The device-level and key-level writes are separate statements inside one
   * transaction, and that is deliberate rather than incidental: they are two
   * facts, they are asked independently by every reader (D24-09), and writing
   * them as one update would encourage exactly the assumption the directive
   * forbids.
   */
  async declareDisposition(
    principal: Principal,
    input: {
      organisationId: string;
      deviceId: string;
      disposition: DeviceRevocationDisposition;
      reason: string;
      traceId: string;
    },
  ): Promise<DeclareDeviceDispositionOutcome> {
    const device = await this.repository.findDevice(input.organisationId, input.deviceId);
    if (device === null) return { outcome: 'REFUSED', refusal: 'DEVICE_NOT_FOUND' };

    const siteIds = await this.repository.listDeviceSiteIds(input.organisationId, device.id);
    const scopeRefusal = this.authoriseAgainstDeviceSites(principal, ACTION_DEVICE_REVOKE, input.organisationId, siteIds);
    if (scopeRefusal !== null) return { outcome: 'REFUSED', refusal: scopeRefusal };

    const from = device.trust as DeviceTrust;
    // D23-05: a COMPROMISED identity is finished. There is no further
    // disposition to declare about it and no write that would mean anything.
    if (from === 'COMPROMISED') return { outcome: 'REFUSED', refusal: 'SOURCE_STATE_TERMINAL' };

    const key = await this.currentKey(device);
    if (key === null) return { outcome: 'REFUSED', refusal: 'DEVICE_KEY_NOT_FOUND' };

    return this.repository.transaction(async (tx) => {
      const now = await this.repository.dbNow(tx);
      const envelope = {
        organisationId: input.organisationId,
        deviceId: device.id,
        actorUserId: principal.user.id,
        occurredAt: now,
        traceId: input.traceId,
      };

      // The three dispositions differ in exactly three ways: the trust they
      // land on, whether the DEVICE credential is revoked, and what happens to
      // the KEY. Everything else is shared.
      const newTrust: DeviceTrust = input.disposition === 'COMPROMISED_KEY' ? 'COMPROMISED' : 'QUARANTINED';
      const revokesDeviceCredential = input.disposition !== 'LOST';
      const keyTarget: DeviceKeyLifecycleState | null =
        input.disposition === 'LOST' ? null : input.disposition === 'STOLEN' ? 'REVOKED' : 'COMPROMISED';

      // The trust move still goes through the contract. A quarantine is a
      // downward transition and is admitted; the value of routing it here is
      // that the transition RECORD is written by the same path as every other,
      // so no disposition can move trust without an audit trail.
      const moved = await this.applyTrustTransition(tx, {
        device,
        key,
        to: newTrust,
        reason: input.reason,
        evidenceRefs: [`disposition:${input.disposition}`],
        authorisedByUserId: principal.user.id,
        restorationDecision: null,
        now,
        traceId: input.traceId,
      });
      if (moved.outcome === 'REFUSED') return moved;

      // DEVICE level. `revoked_at` is set only where the credential is actually
      // withdrawn: a LOST device is quarantined, not revoked, because D24-09
      // keeps its controlled restoration path open.
      await this.repository.setDeviceRevocation(tx, input.organisationId, device.id, {
        disposition: input.disposition,
        revokedAt: revokesDeviceCredential ? now : null,
        trust: newTrust,
      });

      // KEY level, asked and answered separately.
      let keyStatus: DeviceKeyLifecycleState | null = key.status as DeviceKeyLifecycleState;
      if (keyTarget !== null) {
        const currentStatus = key.status as DeviceKeyLifecycleState;
        // The contract's four-state matrix decides whether the move is legal.
        // It is never collapsed into a boolean here (D24-01).
        if (!canTransitionDeviceKeyLifecycle(currentStatus, keyTarget)) {
          return { outcome: 'REFUSED', refusal: 'DEVICE_CREDENTIAL_WITHDRAWN' };
        }
        await this.repository.withdrawDeviceKey(tx, input.organisationId, key.keyId, {
          from: currentStatus,
          to: keyTarget,
          revokedAt: now,
          disposition: input.disposition,
        });
        keyStatus = keyTarget;
      }

      if (input.disposition === 'LOST') {
        await this.audit.record(tx, envelope, {
          type: 'DEVICE_LOST',
          previousTrust: moved.previousTrust,
          newTrust,
          disposition: input.disposition,
        });
        await this.audit.record(tx, envelope, { type: 'DEVICE_QUARANTINED', previousTrust: moved.previousTrust, reason: input.reason });
      } else if (input.disposition === 'STOLEN') {
        await this.audit.record(tx, envelope, {
          type: 'DEVICE_STOLEN',
          previousTrust: moved.previousTrust,
          newTrust,
          disposition: input.disposition,
          keyId: key.keyId,
          keyVersion: key.keyVersion,
        });
        await this.audit.record(tx, envelope, { type: 'KEY_REVOKED', keyId: key.keyId, keyVersion: key.keyVersion, disposition: input.disposition });
      } else {
        await this.audit.record(tx, envelope, {
          type: 'KEY_COMPROMISED',
          keyId: key.keyId,
          keyVersion: key.keyVersion,
          disposition: input.disposition,
        });
      }

      if (revokesDeviceCredential) {
        await this.audit.record(tx, envelope, {
          type: 'DEVICE_REVOKED',
          disposition: input.disposition,
          previousTrust: moved.previousTrust,
          newTrust,
          revokedAt: now.toISOString(),
        });
      }

      return {
        outcome: 'DECLARED',
        disposition: input.disposition,
        previousTrust: moved.previousTrust,
        newTrust,
        keyStatus,
        // D24-09: a LOST device may come back. A stolen or compromised
        // credential may not — `basis.revoked` makes every upward transition
        // refuse with CREDENTIAL_REVOKED, and COMPROMISED is terminal on top
        // of that.
        restorationPathRemains: input.disposition === 'LOST',
      };
    });
  }

  // -------------------------------------------------------------------------
  // Internals
  // -------------------------------------------------------------------------

  /**
   * The ONE place a trust value changes, and the one place a transition record
   * is written. Both happen or neither does.
   *
   * The basis is assembled from server facts and handed to the contract; the
   * contract's verdict is returned verbatim, so a refusal a caller sees is the
   * refusal the frozen evaluator actually produced.
   */
  private async applyTrustTransition(
    tx: Tx,
    input: {
      device: DeviceRow;
      key: DeviceKeyRow | null;
      to: DeviceTrust;
      reason: string;
      evidenceRefs: string[];
      authorisedByUserId: string | null;
      restorationDecision: DeviceControlledRestorationDecision | null;
      now: Date;
      traceId: string;
    },
  ): Promise<ChangeDeviceTrustOutcome> {
    const from = input.device.trust as DeviceTrust;
    const standing = await this.attestationStanding(input.device.organisationId, input.device.id, input.now);

    const decision = evaluateDeviceTrustTransition(from, input.to, {
      controlledRestoration: input.restorationDecision,
      attestationStanding: standing,
      // A device with no current key row cannot be TRUSTED: SOFTWARE is the
      // fail-closed stand-in, and `deviceKeyStoragePermitsTrusted` refuses it.
      keyStorage: (input.key?.keyStorage ?? 'SOFTWARE') as DeviceKeyStorage,
      credentialContinuityIntact: this.credentialContinuityIntact(input.key),
      // D24-09: BOTH levels, asked independently and ORed. Either one saying
      // the credential is gone is sufficient on its own — the device's own
      // `revoked_at`, and the key's lifecycle state and its own revocation
      // instant, which `credentialContinuityIntact` reads separately.
      revoked: input.device.revokedAt !== null || !this.credentialContinuityIntact(input.key),
      previouslyEligible: await this.repository.hasHeldTrusted(input.device.organisationId, input.device.id),
    });

    if (!decision.allowed) return { outcome: 'REFUSED', refusal: decision.refusal };

    const moved = await this.repository.setDeviceTrust(tx, input.device.organisationId, input.device.id, from, input.to);
    // Lost to a concurrent transition. The device is no longer in the state
    // this decision was taken against, so applying it would overwrite someone
    // else's conclusion with one judged against a world that has moved.
    if (moved !== 1) return { outcome: 'REFUSED', refusal: 'DEVICE_CREDENTIAL_WITHDRAWN' };

    // D24-08: EVERY trust change writes an append-only transition record.
    await this.repository.appendTrustTransition(tx, {
      organisationId: input.device.organisationId,
      deviceId: input.device.id,
      previousTrust: from,
      newTrust: input.to,
      reason: input.reason,
      evidenceRefs: [...input.evidenceRefs, `attestation:${standing}`],
      authorisedByUserId: input.authorisedByUserId,
      occurredAt: input.now,
      traceId: input.traceId,
    });

    return { outcome: 'CHANGED', previousTrust: from, newTrust: input.to };
  }

  /**
   * The device's attestation standing right now, from the append-only history.
   *
   * A device with NO observation at all is treated as `UNAVAILABLE` rather than
   * as anything negative: C14-05's asymmetry is that an absence of evidence is
   * not evidence, and the standing evaluator then maps it to `INELIGIBLE` when
   * there is no prior verified result to ride on.
   */
  private async attestationStanding(organisationId: string, deviceId: string, now: Date): Promise<DeviceAttestationStanding> {
    const latest = await this.repository.latestAttestationObservation(organisationId, deviceId);
    const lastVerified = await this.repository.latestVerifiedAttestation(organisationId, deviceId);
    return evaluateAttestationStanding({
      outcome: (latest?.outcome ?? 'UNAVAILABLE') as DeviceAttestationOutcome,
      lastVerifiedAt: lastVerified === null ? null : lastVerified.evaluatedAt.toISOString(),
      now: now.toISOString(),
      hasPriorVerified: lastVerified !== null,
    }).standing;
  }

  /**
   * "The device can still prove possession of its current registered key."
   *
   * Which, at the registry level, is the question of whether that key may still
   * authorise new work — the CONTRACT's `deviceKeyStatePermitsNewOperations`,
   * plus the independent key-level revocation instant. A missing key row is a
   * lost credential, not an unknown one.
   */
  private credentialContinuityIntact(key: DeviceKeyRow | null): boolean {
    if (key === null) return false;
    if (key.revokedAt !== null) return false;
    return deviceKeyStatePermitsNewOperations(key.status as DeviceKeyLifecycleState);
  }

  private async currentKey(device: DeviceRow): Promise<DeviceKeyRow | null> {
    if (device.currentKeyId === null) return null;
    return this.repository.findDeviceKeyByKeyId(device.organisationId, device.currentKeyId);
  }

  /**
   * Site scope for an operation on an existing device.
   *
   * The device's OWN sites are the subject, so an org-wide grant passes and a
   * site-scoped grant must intersect at least one of them. A caller with the
   * action at no relevant site gets `DEVICE_NOT_FOUND` — the same answer as a
   * device that does not exist, because "you may not touch that device" and
   * "there is no such device" must be indistinguishable from outside.
   */
  private authoriseAgainstDeviceSites(
    principal: Principal,
    action: string,
    organisationId: string,
    siteIds: string[],
  ): 'DEVICE_NOT_FOUND' | null {
    if (checkDeviceAuthority(principal, action, organisationId, null) !== null) return 'DEVICE_NOT_FOUND';
    if (siteIds.length === 0) return null;
    const allowed = siteIds.some((siteId) => checkDeviceAuthority(principal, action, organisationId, siteId) === null);
    return allowed ? null : 'DEVICE_NOT_FOUND';
  }
}
