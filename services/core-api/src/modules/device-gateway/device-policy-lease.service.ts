import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import {
  DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS,
  DEVICE_OFFLINE_STALE_TOLERANT_OPERATION_KINDS,
  DevicePolicyLeaseSchema,
  FieldOfflineOperationKindSchema,
  classifyDevicePolicyLease,
  type AuthenticatedDeviceContext,
  type DevicePolicyLease,
  type FieldOfflineOperationKind,
} from '@sentinel/contracts';
import { REQUIRED_ACTION_FOR_KIND } from '../field-offline/field-offline.constants';
import { ShieldRepository } from '../shield/shield.repository';
import { DeviceGatewayRepository, type GatewayTx } from './device-gateway.repository';
import { resolveActorAuthority } from './device-gateway.principals';

/**
 * WP-29A / D29A-26 — ISSUING AND RESOLVING THE CACHED OFFLINE AUTHORITY.
 *
 * A device that is about to lose connectivity needs to know what it may still
 * do, and central needs to be able to judge — later, after the fact — whether
 * what it did was permitted. Both halves are this record. The device caches a
 * copy so it can decide locally what to queue; the SERVER's copy is the only
 * one that decides anything, and it is re-resolved on every reconnect.
 *
 * WHAT THIS SERVICE DELIBERATELY DOES NOT DO
 * ------------------------------------------
 * It does not authenticate. Issuance is reachable only from a route that has
 * already passed the WP-25 device boundary (D29A-26 §13), so the device
 * identity, the human session and the fresh possession proof are established
 * facts by the time `issue` is called — never things it goes and looks up.
 * There is no second device-authentication mechanism here, and adding one
 * would be the exact defect C17-01 corrected.
 *
 * It also mints nothing on request. A lease is the INTERSECTION of what the
 * client asked for with what the device and the actor may currently do; a
 * client that names a wider scope receives a narrower lease or none at all
 * (§6/§11/§12). The scope is never simply believed.
 */
@Injectable()
export class DevicePolicyLeaseService {
  constructor(
    @Inject(DeviceGatewayRepository) private readonly repository: DeviceGatewayRepository,
    @Inject(ShieldRepository) private readonly shield: ShieldRepository,
  ) {}

  /**
   * Issues a bounded lease, or refuses.
   *
   * `null` is the ONLY refusal answer, for every reason, exactly as D25-13
   * requires of the rest of this module: a caller learns that no lease was
   * issued and nothing about which of the device, the site, the actor or the
   * scope was the problem. The precise reason belongs in the internal audit,
   * where an operator can read it and an attacker cannot.
   */
  async issue(input: {
    /**
     * THE SERVER-ESTABLISHED CONTEXT, not loose identifiers.
     *
     * C17-02's tripwire is what forced this signature, and it was right to.
     * The first version took `organisationId`, `deviceId` and `actorUserId` as
     * plain strings, which made the caller responsible for having resolved them
     * — and a security record whose tenant is whatever the caller passed is one
     * refactor away from being anchored on a tenant somebody claimed. Taking
     * the context makes that unrepresentable: the organisation, the device and
     * the actor all come from the row WP-25 committed, and there is no
     * parameter through which a different one could be supplied.
     */
    context: AuthenticatedDeviceContext;
    /** The site being leased for. The caller has already bound it to the context. */
    siteId: string;
    /** What the client asked for. Narrowed below; never granted as given. */
    requestedScope: readonly string[];
    /** The `user_roles` row whose capability justified this issuance. */
    authorityBasisId: string;
    /** Server-chosen lifetime. Clamped to the frozen ceiling regardless. */
    requestedLifetimeMs: number;
  }): Promise<DevicePolicyLease | null> {
    const organisationId = input.context.organisation_id;
    const deviceId = input.context.device_id;
    const actorUserId = input.context.actor_user_id;

    // The site must be one the context actually established. Belt and braces
    // with the caller's own binding: a lease for a site outside the context
    // would be authority the ceremony never granted.
    if (!input.context.authorised_site_ids.includes(input.siteId)) return null;

    const requested = this.parseScope(input.requestedScope);
    if (requested.length === 0) return null;

    // -----------------------------------------------------------------------
    // §11 — THE DEVICE HALF. The lease may never out-scope the device.
    // -----------------------------------------------------------------------
    const device = await this.shield.findDevice(organisationId, deviceId);
    if (device === null) return null;
    // A device that may not act now may not be handed authority to act later.
    // Asking this at issuance is not a substitute for asking it again at
    // reconnect — central re-reads current trust when the queue arrives — it is
    // the first of the two, and skipping it would mint authority for a device
    // we already distrust.
    if (!(await this.shield.hasActiveDeviceSiteScope(organisationId, deviceId, input.siteId))) {
      return null;
    }

    // -----------------------------------------------------------------------
    // §12 — THE ACTOR HALF, asked SEPARATELY and per operation kind.
    // -----------------------------------------------------------------------
    // §62.1 independence: the device being entitled to the site says nothing
    // about whether this human may perform these operations there, and the
    // reverse is equally true. Each kind carries its own required action, so a
    // lease that admits two kinds must clear two capability checks — an actor
    // who may acknowledge messages but not act on assignments receives a lease
    // for the first alone rather than for both.
    const admitted: FieldOfflineOperationKind[] = [];
    for (const kind of requested) {
      const authority = await resolveActorAuthority(this.repository, {
        organisationId,
        actorUserId,
        requiredAction: REQUIRED_ACTION_FOR_KIND[kind],
      });
      if (authority === null) return null;
      if (!authority.facts.holds_required_capability) continue;
      if (!authority.facts.authorised_site_ids.includes(input.siteId)) continue;
      admitted.push(kind);
    }
    // Every requested kind was refused. Issuing an empty lease would be
    // issuing a permit that admits nothing while looking like authority.
    if (admitted.length === 0) return null;

    // -----------------------------------------------------------------------
    // §7 — THE CEILING, from the frozen constant.
    // -----------------------------------------------------------------------
    // `DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS` is imported and clamped against,
    // never copied into a local number. D25-12's rule about not acquiring a
    // second freshness opinion applies here word for word: a duplicated
    // duration is a duration that will eventually be edited on its own.
    const lifetimeMs = Math.min(Math.max(input.requestedLifetimeMs, 0), DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS);
    if (lifetimeMs === 0) return null;

    // §8 — SERVER TIME. The device's clock is not consulted, and there is no
    // parameter through which it could be.
    const issuedAt = await this.repository.now();
    const expiresAt = new Date(issuedAt.getTime() + lifetimeMs);

    const lease: DevicePolicyLease = {
      schema_version: 1,
      lease_id: randomUUID(),
      organisation_id: organisationId,
      site_id: input.siteId,
      device_id: deviceId,
      actor_user_id: actorUserId,
      authority_basis_id: input.authorityBasisId,
      scope: admitted,
      issued_at: issuedAt.toISOString(),
      expires_at: expiresAt.toISOString(),
    };

    // The contract re-refines what this service just built — the window bound
    // and the scope-uniqueness rule — so a future edit here that widens either
    // fails at the contract rather than reaching the database.
    const parsed = DevicePolicyLeaseSchema.safeParse(lease);
    if (!parsed.success) return null;

    await this.repository.createPolicyLease({
      id: lease.lease_id,
      organisationId: lease.organisation_id,
      deviceId: lease.device_id,
      siteId: lease.site_id,
      actorUserId: lease.actor_user_id,
      authorityBasisId: lease.authority_basis_id,
      scope: [...lease.scope],
      issuedAt,
      expiresAt,
    });

    return parsed.data;
  }

  /**
   * THE RESOLUTION `evaluateOfflineOperationAdmissibility` DEPENDS ON.
   *
   * Resolved by `(lease_id, organisation_id)` TOGETHER. A lease belonging to
   * another tenant and a lease that never existed produce the same answer from
   * the same query, so this path cannot be used to discover that some id is a
   * real lease somewhere else in the estate (D25-13).
   *
   * A REVOKED LEASE RESOLVES TO `null`, and that is a deliberate choice rather
   * than an omission. The frozen evaluator has no revocation input: it judges
   * identity, scope and the window through `classifyDevicePolicyLease`, which
   * knows only about instants. Returning a revoked lease would therefore have
   * it judged as though it were live, and the operation would be ADMITTED.
   * Withholding it produces `LEASE_MISSING`, which is the correct fail-closed
   * answer, and the row itself is untouched so the provenance survives (§9).
   */
  async resolve(organisationId: string, leaseId: string, tx?: GatewayTx): Promise<DevicePolicyLease | null> {
    const row = await this.repository.findPolicyLease(organisationId, leaseId, tx);
    if (row === null) return null;
    if (row.revokedAt !== null) return null;

    // Re-parsed rather than cast. A row written before a contract change, or
    // by hand, must fail closed here instead of flowing into the evaluator as
    // a shape it was never checked against.
    const parsed = DevicePolicyLeaseSchema.safeParse({
      schema_version: 1,
      lease_id: row.id,
      organisation_id: row.organisationId,
      site_id: row.siteId,
      device_id: row.deviceId,
      actor_user_id: row.actorUserId,
      authority_basis_id: row.authorityBasisId,
      scope: row.scope,
      issued_at: row.issuedAt.toISOString(),
      expires_at: row.expiresAt.toISOString(),
    });
    return parsed.success ? parsed.data : null;
  }

  /**
   * §9 — revocation is a STATE, never a deletion.
   *
   * Deleting the row would take every receipt that cites it with it, or be
   * refused by the receipt's `Restrict` relation. Both are worse than the
   * truth, which is that the lease existed, authorised what it authorised, and
   * was withdrawn at a named instant.
   *
   * Idempotent: revoking an already-revoked lease keeps the FIRST instant. A
   * second call must not move the moment authority was withdrawn.
   */
  async revoke(organisationId: string, leaseId: string): Promise<boolean> {
    return this.repository.revokePolicyLease(organisationId, leaseId, await this.repository.now());
  }

  /**
   * Whether a lease is currently in force, by the contract's own classifier.
   *
   * Exposed for issuance-time decisions only — "does this device already hold
   * a live lease?". Admissibility does NOT call this: it runs the frozen
   * evaluator, which classifies the lease itself against the authoritative
   * receipt clock. Two places asking the same question two ways is how they
   * come to disagree.
   */
  isInForce(lease: DevicePolicyLease, at: Date): boolean {
    return classifyDevicePolicyLease(lease, at.toISOString()) === 'VALID';
  }

  /**
   * The client's requested scope, narrowed to kinds this contract admits.
   *
   * An unknown kind is DROPPED rather than refused outright, and the caller
   * then refuses an empty result. The alternative — throwing — would let a
   * client probe which strings the server recognises by watching which ones
   * produce a different answer.
   */
  private parseScope(requested: readonly string[]): FieldOfflineOperationKind[] {
    const seen = new Set<FieldOfflineOperationKind>();
    for (const candidate of requested) {
      const parsed = FieldOfflineOperationKindSchema.safeParse(candidate);
      if (parsed.success) seen.add(parsed.data);
    }
    return [...seen];
  }
}

/**
 * WP-29A's admitted scope, and the reason it is one kind long.
 *
 * `INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE` is the ONLY kind WP-23 lists as
 * stale-tolerant, which is precisely what lets it run without an Edge: every
 * other kind requires a trustworthy time witness placing it inside the lease
 * window, and the only thing that can produce one is an Edge — which WP-29A
 * does not have and WP-29B will build.
 *
 * So this is not a cautious subset that could be widened when convenient. Any
 * other kind would reach `NO_TRUSTWORTHY_TIME_WITNESS` and refuse, and making
 * it not refuse would mean widening
 * `DEVICE_OFFLINE_STALE_TOLERANT_OPERATION_KINDS` — which the contract states
 * in terms is a security-contract change, not a convenience.
 */
export const WP29A_ADMITTED_OFFLINE_OPERATION_KINDS: readonly FieldOfflineOperationKind[] = [
  ...DEVICE_OFFLINE_STALE_TOLERANT_OPERATION_KINDS,
];
