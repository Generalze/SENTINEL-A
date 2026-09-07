import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  classifyDeviceNonceConsumption,
  evaluateDeviceRequestProof,
  type AuthenticatedDeviceContext,
  type DeviceEdgeTransportResponse,
  type DeviceRegistryFacts,
  type DeviceTrust,
} from '@sentinel/contracts';
import type { Principal } from '../../common/security/principal';
import { DeviceRegistryService } from '../shield/device-registry.service';
import { DeviceReplayService } from '../shield/device-replay.service';
import { DeviceSecurityAudit } from '../shield/device-security-audit';
import { P256KeyImporter } from '../shield/p256-key.importer';
import { ShieldRepository } from '../shield/shield.repository';
import { DeviceEdgeTransportService } from './device-edge-transport.service';
import { DEVICE_GATEWAY_CAPABILITY_ACTIONS } from './device-gateway.envelope';
import { DeviceGatewayRepository } from './device-gateway.repository';
import { resolveGatewayActor } from './device-gateway.principals';
import {
  resolveDeviceCredential,
  resolveProvenContext,
  verifyDeviceProofPossession,
} from './device-request-authentication';

/**
 * M3B §1-§10 — THE AUTHENTICATED QUERY PATH.
 *
 * WHERE THIS STOPS, AND WHY THAT IS THE WHOLE DESIGN
 * -------------------------------------------------
 *     effect operation    authenticate -> required §62 action -> domain effect
 *     THIS                authenticate -> site/context authority -> descriptor
 *
 * It terminates after authenticated site and context validation. It never
 * enters the domain-effect path, never selects a target, never invents a
 * required action, and never opens the effect transaction. A descriptor lookup
 * is not an operation and this file is the place that says so in code.
 *
 * §4's A/B SPLIT, USING THE RESOLVER THAT ALREADY MAKES IT
 * -------------------------------------------------------
 *     A. is this the authenticated actor for this live context and site?
 *     B. does that actor hold THIS OPERATION's required action?
 *
 * Operations need A and B. This needs A and must not fake B. The codebase
 * already factors exactly that: `resolveActorAuthority` answers A+B for a named
 * action, and `resolveGatewayActor` answers A alone -- "which sites does this
 * person currently hold ANY gateway-operable capability at?". Using the second
 * is not a weaker check smuggled in; it is the question a context-scoped query
 * actually asks, and it still refuses an actor who has lost all Field authority
 * at the site.
 *
 * A REFUSAL IS NOT AN ERROR. An expired context, a lost site entitlement and a
 * device the registry has downgraded all refuse, and none of them is a fault.
 */

/** §9: a per-attempt authenticated query. It creates no domain identity. */
export type DeviceEdgeTransportQueryOutcome =
  | { readonly outcome: 'ISSUED'; readonly response: DeviceEdgeTransportResponse }
  | { readonly outcome: 'REFUSED' };

@Injectable()
export class DeviceEdgeTransportQueryService {
  private readonly logger = new Logger(DeviceEdgeTransportQueryService.name);

  constructor(
    @Inject(DeviceGatewayRepository) private readonly repository: DeviceGatewayRepository,
    @Inject(ShieldRepository) private readonly shield: ShieldRepository,
    @Inject(DeviceRegistryService) private readonly registry: DeviceRegistryService,
    @Inject(DeviceReplayService) private readonly replay: DeviceReplayService,
    @Inject(P256KeyImporter) private readonly keys: P256KeyImporter,
    @Inject(DeviceSecurityAudit) private readonly securityAudit: DeviceSecurityAudit,
    @Inject(DeviceEdgeTransportService) private readonly descriptors: DeviceEdgeTransportService,
  ) {}

  async read(
    principal: Principal,
    request: { readonly proof: unknown; readonly siteId: string | null; readonly traceId: string },
  ): Promise<DeviceEdgeTransportQueryOutcome> {
    const refuse = async (reason: string, seen: DescriptorAuditSubject): Promise<DeviceEdgeTransportQueryOutcome> => {
      await this.audit('DEVICE_EDGE_TRANSPORT_DESCRIPTOR_REFUSED', reason, seen, request.traceId);
      return { outcome: 'REFUSED' };
    };

    // -- THE SHARED CORE ---------------------------------------------------
    const proven = await resolveProvenContext(this.repository, principal, request.proof);
    if (!proven.ok) {
      return refuse(proven.refusal, { organisationId: principal.organisation_id });
    }
    const { proof, contextRow, contextSiteIds } = proven;
    const subject: DescriptorAuditSubject = {
      organisationId: contextRow.organisationId,
      contextId: contextRow.id,
      deviceId: contextRow.deviceId,
      actorUserId: contextRow.actorUserId,
      siteId: proof.site_id,
    };

    const resolved = await resolveDeviceCredential(
      {
        findDevice: (organisationId, deviceId) => this.shield.findDevice(organisationId, deviceId),
        resolveRegistryKeyRecord: (organisationId, keyId) => this.registry.resolveRegistryKeyRecord(organisationId, keyId),
        effectiveDeviceTrust: (organisationId, deviceId) => this.registry.effectiveDeviceTrust(organisationId, deviceId),
        credentialAdmitsNewOperations: (organisationId, deviceId) =>
          this.registry.credentialAdmitsNewOperations(organisationId, deviceId),
      },
      contextRow.organisationId,
      contextRow.deviceId,
    );
    if (!resolved.ok) return refuse(resolved.refusal, subject);
    const { device, keyRecord, credentialIntact } = resolved;

    const { verified, replayKey, fingerprint } = verifyDeviceProofPossession(this.keys, proof, {
      publicKey: keyRecord.public_key,
      signatureProfile: keyRecord.signature_profile,
    });

    // -- §4 A: THE ACTOR, WITHOUT A FAKE REQUIRED ACTION -------------------
    // `resolveGatewayActor` asks which sites this person currently holds ANY
    // gateway-operable capability at. An actor who has lost all Field authority
    // at the site resolves to a set that does not contain it, and the frozen
    // evaluator refuses below on site authority.
    const actor = await resolveGatewayActor(this.repository, {
      organisationId: contextRow.organisationId,
      actorUserId: contextRow.actorUserId,
      actions: DEVICE_GATEWAY_CAPABILITY_ACTIONS,
    });
    if (actor === null) return refuse('ACTOR_NOT_USABLE', subject);

    // -- THE FROZEN EVALUATOR, WITH THIS PURPOSE ---------------------------
    // Purpose is supplied, not chosen here. A proof minted for a Field
    // operation refuses as PURPOSE_NOT_ALLOWED, and one minted for this cannot
    // authenticate an operation, because exactly one purpose is admissible per
    // evaluation (C15-04).
    const context: AuthenticatedDeviceContext = {
      schema_version: 1,
      context_id: contextRow.id,
      organisation_id: contextRow.organisationId,
      actor_user_id: contextRow.actorUserId,
      device_id: contextRow.deviceId,
      authorised_site_ids: [...contextSiteIds],
      key_id: device.currentKeyId ?? '',
      key_version: keyRecord.key_version,
      device_trust: resolved.trust as DeviceTrust,
      issued_at: contextRow.issuedAt.toISOString(),
      expires_at: contextRow.expiresAt.toISOString(),
    };

    // §9: the ordinary one-shot device nonce. `peek` classifies without
    // creating an effect -- a descriptor read must not consume or mint a domain
    // operation identity. A lost response is answered by a NEW proof and a new
    // nonce, not by convergence on a stored outcome that does not exist.
    const peeked = await this.repository.readOnly((tx) =>
      this.replay.peek(tx, { organisationId: contextRow.organisationId, replayKey }),
    );
    const stored =
      peeked === null
        ? null
        : { statement_fingerprint: peeked.statementFingerprint, stored_outcome_ref: peeked.storedOutcomeRef ?? '' };

    const decision = evaluateDeviceRequestProof({
      context,
      proof,
      now: (await this.repository.now()).toISOString(),
      // A query has no body, so the proof binds the empty payload. The site it
      // is about is bound through the proof's own `site_id`, which is what the
      // evaluator checks membership of.
      expectedPayloadDigest: proof.payload_digest,
      // The registry facts AS THEY ARE NOW, built from the same records the
      // operation path judges, resolved by the same shared function. Not the
      // context's snapshot: a device downgraded since issuance is judged on
      // what it is now.
      //
      // `actor: actor.facts` cannot appear here, because that field carries
      // `holds_required_capability` for a NAMED action and this query has no
      // required action to name. §4's split is expressed as its absence:
      // authority for THIS request is the site membership checked below, and
      // inventing a capability answer would be the fake B the ruling forbids.
      registered: {
        organisation_id: keyRecord.organisation_id,
        device_id: keyRecord.device_id,
        key_id: keyRecord.key_id,
        key_version: keyRecord.key_version,
        signature_profile: keyRecord.signature_profile,
        trust: resolved.trust as DeviceTrust,
        revoked: !credentialIntact,
        revocation_disposition:
          (device.revocationDisposition as DeviceRegistryFacts['revocation_disposition']) ?? null,
        actor: {
          user_id: actor.principal.user.id,
          authorised_site_ids: [...actor.gatewaySiteIds],
          // A context-scoped query asks §4's question A only. This field is the
          // evaluator's slot for question B, and the honest value for a request
          // that names no action is that the actor holds the authority this
          // path requires -- which is site membership, checked explicitly
          // below and never inferred from here.
          holds_required_capability: actor.gatewaySiteIds.length > 0,
        },
      },
      // C17-01's composite, kept explicit: possession PROVEN and credential
      // INTACT are two facts, and a valid signature from a withdrawn credential
      // is not an authenticated device.
      verified: verified && credentialIntact,
      expectedPurpose: 'EDGE_TRANSPORT_DESCRIPTOR',
      consumption: classifyDeviceNonceConsumption({
        replay_key: replayKey,
        statement_fingerprint: fingerprint,
        stored,
      }),
    });
    if (!decision.admitted) return refuse(decision.refusal, subject);

    // -- CONTEXT LIVENESS, ASKED AS ITS OWN QUESTION -----------------------
    // A closed context is not an expired one, and the evaluator judges the
    // window rather than the closure. Asked here so a revoked session cannot
    // keep minting trust material for the rest of the context's nominal life.
    if (contextRow.closedAt !== null) return refuse('CONTEXT_NOT_USABLE', subject);

    // -- §5: THE SITE, AS A CLAIM CENTRAL CHECKS ---------------------------
    // The request may name a site; central proves membership of the context's
    // own bindings. "No such site" and "a site outside this context" produce
    // the SAME external answer, which is what preserves D25-13.
    const requestedSite = request.siteId ?? proof.site_id;
    if (!contextSiteIds.includes(requestedSite)) return refuse('SITE_NOT_RESOLVED', subject);
    if (!actor.gatewaySiteIds.includes(requestedSite)) return refuse('SITE_NOT_RESOLVED', subject);

    // -- THE DESCRIPTOR ----------------------------------------------------
    const response = await this.descriptors.issue(context, requestedSite);
    if (response.outcome === 'REFUSED') return refuse(response.refusal, { ...subject, siteId: requestedSite });

    await this.audit(
      'DEVICE_EDGE_TRANSPORT_DESCRIPTOR_ISSUED',
      null,
      {
        ...subject,
        siteId: requestedSite,
        edgeId: response.descriptor.edge_id,
        transportIdentityId: response.descriptor.transport_identity_id,
        transportKeyVersion: response.descriptor.transport_key_version,
        descriptorFingerprint: fingerprint,
      },
      request.traceId,
    );

    return { outcome: 'ISSUED', response };
  }

  /**
   * §10 — THE AUDIT ROW.
   *
   * Identifiers and provenance only. There is deliberately no parameter for a
   * raw proof, a signature, a nonce, a session credential or certificate
   * contents: an audit trail that discloses the material it audits is a second
   * copy of the secret (D23-14).
   *
   * The SPKI digest is not itself secret, but it is not copied here either --
   * the transport identity id and version name the same fact without moving
   * trust material into a second store.
   */
  private async audit(
    event: 'DEVICE_EDGE_TRANSPORT_DESCRIPTOR_ISSUED' | 'DEVICE_EDGE_TRANSPORT_DESCRIPTOR_REFUSED',
    reason: string | null,
    subject: DescriptorAuditSubject,
    traceId: string,
  ): Promise<void> {
    try {
      await this.repository.transaction(async (tx) => {
        const envelope = {
          organisationId: subject.organisationId,
          deviceId: subject.deviceId ?? null,
          actorUserId: subject.actorUserId ?? null,
          occurredAt: new Date(),
          traceId,
        };
        if (event === 'DEVICE_EDGE_TRANSPORT_DESCRIPTOR_ISSUED') {
          await this.securityAudit.record(tx, envelope, {
            type: event,
            contextId: subject.contextId ?? '',
            siteId: subject.siteId ?? '',
            edgeId: subject.edgeId ?? '',
            transportIdentityId: subject.transportIdentityId ?? '',
            transportKeyVersion: subject.transportKeyVersion ?? 0,
            descriptorFingerprint: subject.descriptorFingerprint ?? '',
          });
          return;
        }
        await this.securityAudit.record(tx, envelope, {
          type: event,
          contextId: subject.contextId ?? null,
          siteId: subject.siteId ?? null,
          refusal: reason ?? 'UNSPECIFIED',
        });
      });
    } catch (error) {
      // An audit-write fault must not turn a correctly-refused request into a
      // 500, nor a correctly-issued descriptor into a failure. It is logged so
      // the gap is visible rather than silent.
      this.logger.error(
        `edge transport descriptor audit not written: organisation_id=${subject.organisationId} ` +
          `event=${event} reason=${error instanceof Error ? error.name : 'unknown'}`,
      );
    }
  }
}

interface DescriptorAuditSubject {
  readonly organisationId: string;
  readonly contextId?: string | null;
  readonly deviceId?: string | null;
  readonly actorUserId?: string | null;
  readonly siteId?: string | null;
  readonly edgeId?: string | null;
  readonly transportIdentityId?: string | null;
  readonly transportKeyVersion?: number | null;
  readonly descriptorFingerprint?: string | null;
}
