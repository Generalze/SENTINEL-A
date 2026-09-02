import { randomBytes, randomUUID } from 'node:crypto';
import { Inject, Injectable } from '@nestjs/common';
import {
  AuthenticatedDeviceContextSchema,
  DEVICE_CONTEXT_MAX_LIFETIME_MS,
  DEVICE_PURPOSE_PERMITTED_TRUST,
  DeviceRequestProofSchema,
  canonicalDeviceRequestProofStatement,
  classifyDeviceNonceConsumption,
  deviceRequestProofFingerprint,
  deviceRequestProofReplayKey,
  deviceRequestProofStatementInput,
  evaluateDeviceOperationPrincipals,
  evaluateDeviceReconnectAuthentication,
  type AuthenticatedDeviceContext,
  type DeviceRegistryFacts,
  type DeviceRequestProof,
  type DeviceTrust,
} from '@sentinel/contracts';
import type { Principal } from '../../common/security/principal';
import { DeviceRegistryService } from '../shield/device-registry.service';
import { DeviceReplayService } from '../shield/device-replay.service';
import { P256KeyImporter } from '../shield/p256-key.importer';
import { ShieldRepository } from '../shield/shield.repository';
import {
  deviceContextEstablishmentChallengeDigest,
  type DeviceContextEstablishmentChallengeView,
} from './device-context.challenge';
import {
  DEVICE_CONTEXT_ESTABLISHMENT_MAX_AGE_MS,
  DEVICE_GATEWAY_ESTABLISHMENT_CEREMONY,
  DEVICE_GATEWAY_ESTABLISHMENT_NONCE_BYTES,
} from './device-gateway.constants';
import { DEVICE_GATEWAY_CAPABILITY_ACTIONS } from './device-gateway.envelope';
import { resolveGatewayActor } from './device-gateway.principals';
import { DeviceGatewayRepository, type EstablishmentChallengeRow, type GatewayTx } from './device-gateway.repository';
import { DeviceGatewayTransactionRollback, isDeviceGatewayTransactionRollback } from './device-gateway.rollback';
import type { DeviceContextEstablishmentResult, DeviceGatewayRefusal } from './device-gateway.types';

/**
 * WP-25/D25-03A — THE PRE-CONTEXT ESTABLISHMENT CEREMONY.
 *
 * THE PROBLEM, STATED HONESTLY
 * ----------------------------
 * The first draft of D25-03 was circular and the directive says so: "the device
 * signs a context request, the server verifies, the server mints a context" —
 * but the frozen `DeviceRequestProof` is itself bound to a `context_id` and its
 * evaluator takes an `AuthenticatedDeviceContext`. Requiring an issued context
 * in order to obtain the FIRST context cannot work.
 *
 * It is NOT solved with a bearer bootstrap token and NOT by inventing another
 * cryptographic domain. It is solved by having the SERVER propose the context
 * id, and by assembling an IN-MEMORY CANDIDATE context from SERVER FACTS purely
 * so the frozen evaluator has something to judge.
 *
 *     CURRENT HUMAN SESSION requests establishment for a registered device+site
 *        -> SERVER resolves org, actor, device, current key id+version,
 *           current registry standing, current actor/site intersection
 *        -> SERVER creates a short-lived ONE-SHOT challenge
 *        -> NO CONTEXT HAS BEEN ISSUED. NO DEVICE AUTHORITY EXISTS.
 *        -> DEVICE signs a frozen DeviceRequestProof:
 *             context_id     = the PROPOSED context id
 *             purpose        = RECONNECT_HANDSHAKE
 *             payload_digest = digest of the EXACT challenge
 *        -> SERVER builds the IN-MEMORY CANDIDATE
 *        -> P-256 verify against the CURRENT Shield registry key
 *        -> evaluateDeviceReconnectAuthentication (authentication-only)
 *           + evaluateDeviceOperationPrincipals
 *        -> FINAL TRANSACTION: re-read, consume the challenge, consume the
 *           replay identity, persist the context and its site rows, append audit
 *
 * THE CANDIDATE IS NOT AN ISSUED CONTEXT, AND IT NEVER LEAVES THIS PROCESS.
 *
 * It is built for the evaluator and discarded. It is never returned to the
 * client, never persisted, and accepted nowhere else — the context this method
 * hands back is assembled from the COMMITTED ROW, after the transaction wrote
 * it. That distinction is the entire reason this is not a bearer bootstrap: a
 * candidate that could be returned would be a credential minted before the
 * checks that justify it.
 *
 * WHY `evaluateDeviceReconnectAuthentication` AND NOT `evaluateDeviceRequestProof`
 * ------------------------------------------------------------------------------
 * C15-R2 split reconnect into two decisions and D25-05 requires WP-25 to keep
 * them apart. Authentication answers "is the registered hardware on the other
 * end of this connection?" from possession alone, under AUTHENTICATION_ONLY,
 * and its success arm carries the literal `queue_examination_permitted: false`.
 * The human authority question is NOT skipped here — it is asked separately, by
 * `evaluateDeviceOperationPrincipals` below, exactly as D25-03A specifies, so a
 * strong device proof can never paper over an absent or withdrawn session.
 *
 * `evaluateDeviceOfflineQueueAdmission` IS DELIBERATELY NOT CALLED ANYWHERE IN
 * THIS MODULE. WP-25 ships no offline queue; authentication never unlocks one,
 * and the moment one exists it gets its own decision at the fixed purpose
 * OFFLINE_SYNC rather than inheriting this one.
 *
 * THE SERVER OWNS EVERY FIELD OF THE MINTED CONTEXT. Nothing in the issued row
 * was proposed by the device, and there is no parameter through which it could
 * be — not the context id, not the nonce, not the key, not the site, not the
 * lifetime.
 */
@Injectable()
export class DeviceContextService {
  constructor(
    @Inject(DeviceGatewayRepository) private readonly repository: DeviceGatewayRepository,
    @Inject(ShieldRepository) private readonly shield: ShieldRepository,
    @Inject(DeviceRegistryService) private readonly registry: DeviceRegistryService,
    @Inject(DeviceReplayService) private readonly replay: DeviceReplayService,
    @Inject(P256KeyImporter) private readonly keys: P256KeyImporter,
  ) {}

  /**
   * STEP ONE — the human session asks for a challenge.
   *
   * The caller here is a PERSON, authenticated by the ordinary session guard.
   * That is the independent second factor D25-03A rests on: the challenge is
   * not a secret, so the only thing that makes stealing it useless is that
   * issuance ALSO required a live human session and the hardware key.
   *
   * Every refusal below returns the same outcome and appends the precise reason
   * to the internal audit (D25-13). A device that belongs to another tenant,
   * one that never existed, one at a site this person cannot work, and one the
   * registry has stopped vouching for are externally indistinguishable.
   */
  async requestEstablishment(
    principal: Principal,
    input: { organisationId: string; deviceId: string; siteId: string; traceId: string },
  ): Promise<{ outcome: 'ISSUED'; challenge: DeviceContextEstablishmentChallengeView } | { outcome: 'REFUSED' }> {
    const refuse = async (refusal: DeviceGatewayRefusal): Promise<{ outcome: 'REFUSED' }> => {
      await this.repository.appendOperationEventOutsideTransaction(
        {
          organisationId: input.organisationId,
          contextId: null,
          deviceId: null,
          actorUserId: principal.user.id,
          operationKind: null,
          occurredAt: new Date(),
          traceId: input.traceId,
        },
        {
          type: 'ESTABLISHMENT_REFUSED',
          establishmentId: null,
          proposedContextId: null,
          siteId: input.siteId,
          refusal,
          contractRefusal: null,
        },
      );
      return { outcome: 'REFUSED' };
    };

    // The session's own tenant is the only tenant it may ask about. A principal
    // naming another organisation is not an error to be reported, it is a probe.
    if (principal.organisation_id !== input.organisationId) return refuse('ESTABLISHMENT_NOT_PERMITTED');

    const actor = await resolveGatewayActor(
      this.repository,
      { organisationId: input.organisationId, actorUserId: principal.user.id, actions: DEVICE_GATEWAY_CAPABILITY_ACTIONS },
      undefined,
    );
    if (actor === null) return refuse('ACTOR_NOT_USABLE');
    if (!actor.gatewaySiteIds.includes(input.siteId)) return refuse('SITE_NOT_USABLE');

    const device = await this.shield.findDevice(input.organisationId, input.deviceId);
    if (device === null) return refuse('DEVICE_NOT_USABLE');
    if (device.currentKeyId === null || device.currentKeyVersion === null) return refuse('REGISTRY_KEY_UNRESOLVABLE');

    // The device must be deployed at the site the context is being issued for.
    // This is the DEVICE half of site authority and it is asked separately from
    // the actor half above — neither may stand in for the other.
    const deviceSiteIds = await this.shield.listDeviceSiteIds(input.organisationId, device.id);
    if (!deviceSiteIds.includes(input.siteId)) return refuse('SITE_NOT_USABLE');

    // CURRENT registry standing, through Shield's ONE canonical effective
    // resolution (C16-R5) at the frozen RECONNECT_HANDSHAKE purpose. A
    // QUARANTINED or COMPROMISED device gets no challenge at all: those are
    // decisions, not ignorance, and the purpose table says so.
    if (!(await this.registry.deviceMayAct(input.organisationId, device.id, 'RECONNECT_HANDSHAKE'))) {
      return refuse('DEVICE_NOT_USABLE');
    }
    const effectiveTrust = await this.registry.effectiveDeviceTrust(input.organisationId, device.id);
    if (effectiveTrust === null) return refuse('DEVICE_NOT_USABLE');

    // The key is RESOLVED FROM THE REGISTRY. There is no parameter through
    // which a caller could supply one, here or anywhere else in this module.
    const keyRecord = await this.registry.resolveRegistryKeyRecord(input.organisationId, device.currentKeyId);
    if (keyRecord === null) return refuse('REGISTRY_KEY_UNRESOLVABLE');

    const issuedAt = await this.repository.now();
    const expiresAt = new Date(issuedAt.getTime() + DEVICE_CONTEXT_ESTABLISHMENT_MAX_AGE_MS);
    const row = await this.repository.createEstablishmentChallenge({
      organisationId: input.organisationId,
      proposedContextId: randomUUID(),
      actorUserId: principal.user.id,
      deviceId: device.id,
      siteId: input.siteId,
      keyId: keyRecord.key_id,
      keyVersion: keyRecord.key_version,
      // SERVER-generated. The device never chooses what it is asked to sign.
      nonce: randomBytes(DEVICE_GATEWAY_ESTABLISHMENT_NONCE_BYTES).toString('base64url'),
      issuedAt,
      expiresAt,
    });

    const challenge = challengeViewOf(row);
    await this.repository.appendOperationEventOutsideTransaction(
      {
        organisationId: input.organisationId,
        contextId: null,
        deviceId: device.id,
        actorUserId: principal.user.id,
        operationKind: null,
        occurredAt: issuedAt,
        traceId: input.traceId,
      },
      {
        type: 'ESTABLISHMENT_CHALLENGE_ISSUED',
        establishmentId: row.id,
        proposedContextId: row.proposedContextId,
        siteId: row.siteId,
        keyId: row.keyId,
        keyVersion: row.keyVersion,
        expiresAt: expiresAt.toISOString(),
        effectiveTrust,
      },
    );
    // The NONCE is in the response, because the device must sign it. It is NOT
    // in the audit payload, because an audit stream is read by more people, for
    // longer, than a two-minute ceremony is (D25-13).
    return { outcome: 'ISSUED', challenge };
  }

  /**
   * STEP TWO — the device answers, and a context is issued or nothing is.
   *
   * There is no human session on this call, deliberately: the caller is the
   * DEVICE. The human half was established when the challenge was issued and
   * is RE-ESTABLISHED here from current server state — the actor must still
   * exist and must still hold a gateway-operable capability at the site — so a
   * session that was live at step one and withdrawn before step two refuses.
   */
  async completeEstablishment(input: {
    establishmentId: string;
    proof: unknown;
    traceId: string;
  }): Promise<DeviceContextEstablishmentResult> {
    const parsedProof = DeviceRequestProofSchema.safeParse(input.proof);
    if (!parsedProof.success) {
      // Nothing has been resolved, so there is no tenant to file the event
      // under and no device to name. A malformed proof is a shape complaint.
      return { outcome: 'REFUSED' };
    }
    const proof = parsedProof.data;

    const refuse = async (
      refusal: DeviceGatewayRefusal,
      contractRefusal: string | null,
      context: { deviceId: string | null; actorUserId: string | null; establishmentId: string | null; proposedContextId: string | null; siteId: string | null },
    ): Promise<DeviceContextEstablishmentResult> => {
      await this.repository.appendOperationEventOutsideTransaction(
        {
          organisationId: proof.organisation_id,
          contextId: null,
          deviceId: context.deviceId,
          actorUserId: context.actorUserId,
          operationKind: null,
          occurredAt: new Date(),
          traceId: input.traceId,
        },
        {
          type: 'ESTABLISHMENT_REFUSED',
          establishmentId: context.establishmentId,
          proposedContextId: context.proposedContextId,
          siteId: context.siteId,
          refusal,
          contractRefusal,
        },
      );
      return { outcome: 'REFUSED' };
    };

    // ---------------------------------------------------------------------
    // PREFLIGHT — establishes nothing, commits nothing
    // ---------------------------------------------------------------------
    const challengeRow = await this.repository.findEstablishmentChallenge(proof.organisation_id, input.establishmentId);
    if (challengeRow === null) {
      return refuse('ESTABLISHMENT_NOT_USABLE', null, {
        deviceId: null,
        actorUserId: null,
        establishmentId: input.establishmentId,
        proposedContextId: null,
        siteId: null,
      });
    }
    const trace = {
      deviceId: challengeRow.deviceId,
      actorUserId: challengeRow.actorUserId,
      establishmentId: challengeRow.id,
      proposedContextId: challengeRow.proposedContextId,
      siteId: challengeRow.siteId,
    };

    const preflightNow = await this.repository.now();
    // Expiry is evaluated AT REQUEST TIME, exclusively (`now >= expires_at`),
    // and there is no scheduler anywhere. One-shot is decided here for the
    // cheap case and AGAIN under lock in the transaction, which is the one that
    // counts.
    if (challengeRow.consumedAt !== null) return refuse('ESTABLISHMENT_NOT_USABLE', null, trace);
    if (preflightNow.getTime() >= challengeRow.expiresAt.getTime()) return refuse('ESTABLISHMENT_NOT_USABLE', null, trace);

    const preflight = await this.resolveFacts(challengeRow, undefined);
    if (preflight.kind === 'REFUSED') return refuse(preflight.refusal, null, trace);

    const statement = canonicalDeviceRequestProofStatement(
      deviceRequestProofStatementInput(proof, preflight.registered.signature_profile),
    );
    const verified = this.keys.verifySignature({
      registeredPublicKey: preflight.publicKey,
      message: statement,
      signature: proof.signature,
      // C15-01: the SERVER resolved the profile; the proof merely claimed one.
      // The importer binds them before it touches any crypto, so no client can
      // steer the verifier.
      serverResolvedProfile: preflight.registered.signature_profile,
      claimedProfile: proof.claimed_signature_profile,
    });

    const replayKey = deviceRequestProofReplayKey(proof);
    const peeked = await this.repository.readOnly((tx) => this.replay.peek(tx, { organisationId: proof.organisation_id, replayKey }));

    const preflightDecision = this.judge({
      challenge: challengeRow,
      proof,
      now: preflightNow,
      registered: preflight.registered,
      trust: preflight.trust,
      verified,
      credentialIntact: preflight.credentialIntact,
      actorResolved: preflight.actorResolved,
      siteAuthorityGranted: preflight.siteAuthorityGranted,
      consumptionStored:
        peeked === null ? null : { statement_fingerprint: peeked.statementFingerprint, stored_outcome_ref: peeked.storedOutcomeRef ?? '' },
      replayKey,
    });
    if (preflightDecision.kind === 'REFUSED') {
      return refuse(preflightDecision.refusal, preflightDecision.contractRefusal, trace);
    }

    // ---------------------------------------------------------------------
    // FINAL TRANSACTION — one transaction, or nothing
    // ---------------------------------------------------------------------
    try {
      const issued = await this.repository.transaction(async (tx) => {
        const locked = await this.repository.lockEstablishmentChallenge(tx, proof.organisation_id, input.establishmentId);
        if (locked === null) throw new DeviceGatewayTransactionRollback('ESTABLISHMENT_NOT_USABLE');
        const now = await this.repository.dbNow(tx);
        if (locked.consumedAt !== null) throw new DeviceGatewayTransactionRollback('ESTABLISHMENT_NOT_USABLE');
        if (now.getTime() >= locked.expiresAt.getTime()) throw new DeviceGatewayTransactionRollback('ESTABLISHMENT_NOT_USABLE');

        // Every fact re-read, under the device and key row locks, INSIDE the
        // transaction that is about to mint the context.
        await this.shield.lockDevice(tx, locked.organisationId, locked.deviceId);
        await this.shield.lockDeviceKeyByKeyId(tx, locked.organisationId, locked.keyId);
        const facts = await this.resolveFacts(locked, tx);
        if (facts.kind === 'REFUSED') throw new DeviceGatewayTransactionRollback(facts.refusal);

        const finalPeek = await this.replay.peek(tx, { organisationId: proof.organisation_id, replayKey });
        const decision = this.judge({
          challenge: locked,
          proof,
          now,
          registered: facts.registered,
          trust: facts.trust,
          verified,
          credentialIntact: facts.credentialIntact,
          actorResolved: facts.actorResolved,
          siteAuthorityGranted: facts.siteAuthorityGranted,
          consumptionStored:
            finalPeek === null
              ? null
              : { statement_fingerprint: finalPeek.statementFingerprint, stored_outcome_ref: finalPeek.storedOutcomeRef ?? '' },
          replayKey,
        });
        if (decision.kind === 'REFUSED') {
          throw new DeviceGatewayTransactionRollback(decision.refusal, decision.contractRefusal);
        }

        // Spend the ceremony. Fenced on `consumed_at IS NULL`, so a second use
        // updates zero rows and the whole transaction rolls back — "one-shot"
        // is a compare-and-set, not an intention.
        const consumed = await this.repository.consumeEstablishmentChallenge(tx, locked.organisationId, locked.id, now);
        if (consumed !== 1) throw new DeviceGatewayTransactionRollback('ESTABLISHMENT_NOT_USABLE');

        // Spend the one-shot replay identity in Shield's ONE store, under this
        // module's own ceremony label. The outcome reference is the context id
        // that is about to exist, so a later exact retry converges on THIS
        // ceremony rather than minting a second context.
        const claimed = await this.replay.consume(tx, {
          organisationId: locked.organisationId,
          ceremony: DEVICE_GATEWAY_ESTABLISHMENT_CEREMONY,
          replayKey,
          statementFingerprint: decision.fingerprint,
          candidateOutcomeRef: locked.proposedContextId,
          traceId: input.traceId,
        });
        if (claimed.consumption.outcome !== 'FIRST_SEEN') {
          // The challenge CAS above already refuses an honest retry, so an
          // identity that is already spent here means this nonce was burned by
          // some other ceremony. There is nothing to converge on.
          throw new DeviceGatewayTransactionRollback('ESTABLISHMENT_NOT_USABLE');
        }

        const expiresAt = new Date(now.getTime() + DEVICE_CONTEXT_MAX_LIFETIME_MS);
        const record = await this.repository.createIssuedContext(tx, {
          id: locked.proposedContextId,
          organisationId: locked.organisationId,
          actorUserId: locked.actorUserId,
          deviceId: locked.deviceId,
          keyId: locked.keyId,
          keyVersion: locked.keyVersion,
          issuedAt: now,
          expiresAt,
          establishmentId: locked.id,
          issuanceTraceId: input.traceId,
        });
        await this.repository.createContextSite(tx, {
          contextId: record.id,
          organisationId: record.organisationId,
          siteId: locked.siteId,
        });

        await this.repository.appendOperationEvent(
          tx,
          {
            organisationId: record.organisationId,
            contextId: record.id,
            deviceId: record.deviceId,
            actorUserId: record.actorUserId,
            operationKind: null,
            occurredAt: now,
            traceId: input.traceId,
          },
          {
            type: 'CONTEXT_ISSUED',
            establishmentId: locked.id,
            siteId: locked.siteId,
            keyId: record.keyId,
            keyVersion: record.keyVersion,
            issuedAt: record.issuedAt.toISOString(),
            expiresAt: record.expiresAt.toISOString(),
            effectiveTrust: facts.trust,
            statementFingerprint: decision.fingerprint,
          },
        );

        // ASSEMBLED FROM THE COMMITTED ROW, not from the candidate. The
        // candidate `judge` built above is discarded here and has never left
        // this process.
        return AuthenticatedDeviceContextSchema.parse({
          schema_version: 1,
          context_id: record.id,
          organisation_id: record.organisationId,
          actor_user_id: record.actorUserId,
          device_id: record.deviceId,
          authorised_site_ids: [locked.siteId],
          // HISTORICAL ISSUANCE STATE. The frozen contract requires the field;
          // no column stores it, and every operation reads CURRENT standing.
          device_trust: facts.trust,
          key_id: record.keyId,
          key_version: record.keyVersion,
          issued_at: record.issuedAt.toISOString(),
          expires_at: record.expiresAt.toISOString(),
        });
      });
      return { outcome: 'ISSUED', context: issued };
    } catch (error) {
      if (isDeviceGatewayTransactionRollback(error)) {
        // The transaction is already rolled back. The audit event is written
        // afterwards, in its OWN transaction, so the trail of the refusal
        // survives while the security state does not.
        return refuse(error.refusal, error.contractRefusal, trace);
      }
      throw error;
    }
  }

  // -------------------------------------------------------------------------
  // The facts, resolved identically in preflight and under lock
  // -------------------------------------------------------------------------

  /**
   * ONE resolution, called TWICE — once in preflight and once inside the final
   * transaction with `tx` supplied.
   *
   * Two copies of this would be two opinions about what the current facts are,
   * and the fence in the transaction would then be checking something subtly
   * different from what the preflight approved.
   */
  private async resolveFacts(
    challenge: EstablishmentChallengeRow,
    tx: GatewayTx | undefined,
  ): Promise<
    | {
        kind: 'RESOLVED';
        registered: DeviceRegistryFacts;
        publicKey: string;
        trust: DeviceTrust;
        credentialIntact: boolean;
        /** The actor row was RESOLVED from live tables. Never a default. */
        actorResolved: boolean;
        siteAuthorityGranted: boolean;
      }
    | { kind: 'REFUSED'; refusal: DeviceGatewayRefusal }
  > {
    const device = await this.shield.findDevice(challenge.organisationId, challenge.deviceId, tx);
    if (device === null) return { kind: 'REFUSED', refusal: 'DEVICE_NOT_USABLE' };
    if (device.currentKeyId === null) return { kind: 'REFUSED', refusal: 'REGISTRY_KEY_UNRESOLVABLE' };

    // The key is resolved from the REGISTRY by the DEVICE's current pointer,
    // never by anything the proof claims. The proof's own `key_id` and
    // `key_version` are then bound against these by the frozen evaluator, so a
    // disagreement is a refusal rather than a lookup somebody could skip.
    const keyRecord = await this.registry.resolveRegistryKeyRecord(challenge.organisationId, device.currentKeyId);
    if (keyRecord === null) return { kind: 'REFUSED', refusal: 'REGISTRY_KEY_UNRESOLVABLE' };

    const trust = await this.registry.effectiveDeviceTrust(challenge.organisationId, device.id, tx);
    if (trust === null) return { kind: 'REFUSED', refusal: 'DEVICE_NOT_USABLE' };
    const credentialIntact = await this.registry.credentialAdmitsNewOperations(challenge.organisationId, device.id, tx);

    const actor = await resolveGatewayActor(
      this.repository,
      { organisationId: challenge.organisationId, actorUserId: challenge.actorUserId, actions: DEVICE_GATEWAY_CAPABILITY_ACTIONS },
      tx,
    );
    if (actor === null) return { kind: 'REFUSED', refusal: 'ACTOR_NOT_USABLE' };

    const deviceSiteIds = await this.shield.listDeviceSiteIds(challenge.organisationId, device.id);
    // Both halves of site authority, asked independently: the HUMAN must
    // currently work this site and the DEVICE must currently be deployed at it.
    const siteAuthorityGranted = actor.gatewaySiteIds.includes(challenge.siteId) && deviceSiteIds.includes(challenge.siteId);

    return {
      kind: 'RESOLVED',
      publicKey: keyRecord.public_key,
      trust,
      credentialIntact,
      actorResolved: true,
      siteAuthorityGranted,
      registered: {
        organisation_id: keyRecord.organisation_id,
        device_id: keyRecord.device_id,
        key_id: keyRecord.key_id,
        key_version: keyRecord.key_version,
        signature_profile: keyRecord.signature_profile,
        trust,
        revoked: !credentialIntact,
        revocation_disposition: (device.revocationDisposition as DeviceRegistryFacts['revocation_disposition']) ?? null,
        actor: {
          user_id: actor.principal.user.id,
          authorised_site_ids: actor.gatewaySiteIds,
          // AUTHENTICATION_ONLY skips the actor block, so this value does not
          // steer the reconnect verdict. It is set honestly all the same, and
          // the authority question that DOES bind is asked immediately below by
          // `evaluateDeviceOperationPrincipals`.
          holds_required_capability: actor.gatewaySiteIds.includes(challenge.siteId),
        },
      },
    };
  }

  /**
   * The two frozen evaluators, in the D25-03A order, over the in-memory
   * candidate. This function is where the candidate exists, and it does not
   * escape it.
   */
  private judge(input: {
    /** Set ONLY where the actor row was read back from live tables. Never defaulted. */
    actorResolved: boolean;
    challenge: EstablishmentChallengeRow;
    proof: DeviceRequestProof;
    now: Date;
    registered: DeviceRegistryFacts;
    trust: DeviceTrust;
    verified: boolean;
    credentialIntact: boolean;
    siteAuthorityGranted: boolean;
    consumptionStored: { statement_fingerprint: string; stored_outcome_ref: string } | null;
    replayKey: string;
  }):
    | { kind: 'AUTHENTICATED'; fingerprint: string }
    | { kind: 'REFUSED'; refusal: DeviceGatewayRefusal; contractRefusal: string | null } {
    const nowIso = input.now.toISOString();

    // THE IN-MEMORY CANDIDATE. Assembled from SERVER facts only: the proposed
    // id the server minted, the tenant, actor, device, site, key and key
    // version the server resolved, and a window the server chose. It is never
    // returned, never persisted, and accepted nowhere else.
    const candidate: AuthenticatedDeviceContext = {
      schema_version: 1,
      context_id: input.challenge.proposedContextId,
      organisation_id: input.challenge.organisationId,
      actor_user_id: input.challenge.actorUserId,
      device_id: input.challenge.deviceId,
      authorised_site_ids: [input.challenge.siteId],
      device_trust: input.trust,
      key_id: input.challenge.keyId,
      key_version: input.challenge.keyVersion,
      issued_at: nowIso,
      expires_at: new Date(input.now.getTime() + DEVICE_CONTEXT_MAX_LIFETIME_MS).toISOString(),
    };

    // The device signs the digest of the EXACT challenge, and the server
    // recomputes it from the row rather than trusting a value in the request.
    const expectedPayloadDigest = deviceContextEstablishmentChallengeDigest(challengeViewOf(input.challenge));

    const statementInput = deviceRequestProofStatementInput(input.proof, input.registered.signature_profile);
    const fingerprint = deviceRequestProofFingerprint(statementInput);
    const consumption = classifyDeviceNonceConsumption({
      replay_key: input.replayKey,
      statement_fingerprint: fingerprint,
      stored: input.consumptionStored,
    });

    const authentication = evaluateDeviceReconnectAuthentication({
      context: candidate,
      proof: input.proof,
      now: nowIso,
      expectedPayloadDigest,
      registered: input.registered,
      verified: input.verified,
      consumption,
    });
    if (!authentication.authenticated) {
      return { kind: 'REFUSED', refusal: 'PROOF_REFUSED', contractRefusal: authentication.refusal };
    }

    // BOTH PRINCIPALS, INDEPENDENTLY. A perfectly TRUSTED device with no
    // current human authority is refused here, and an authenticated human with
    // no hardware possession was already refused above. That symmetry is the
    // whole ruling.
    const admission = evaluateDeviceOperationPrincipals({
      userAuthenticated: input.actorResolved,
      deviceAuthenticated: input.verified && input.credentialIntact,
      deviceTrust: input.trust,
      requiredTrust: DEVICE_PURPOSE_PERMITTED_TRUST.RECONNECT_HANDSHAKE,
      siteAuthorityGranted: input.siteAuthorityGranted,
      // WP-25 adds no Constitution policy to these three surfaces. When one is
      // introduced it is evaluated HERE, as its own independent fact, and never
      // inferred from the device or the session.
      policySatisfied: true,
    });
    if (!admission.admitted) {
      return { kind: 'REFUSED', refusal: 'PRINCIPALS_REFUSED', contractRefusal: admission.refusal };
    }

    return { kind: 'AUTHENTICATED', fingerprint: authentication.fingerprint };
  }
}

function challengeViewOf(row: EstablishmentChallengeRow): DeviceContextEstablishmentChallengeView {
  return {
    schema_version: 1,
    establishment_id: row.id,
    proposed_context_id: row.proposedContextId,
    organisation_id: row.organisationId,
    actor_user_id: row.actorUserId,
    device_id: row.deviceId,
    site_id: row.siteId,
    key_id: row.keyId,
    key_version: row.keyVersion,
    nonce: row.nonce,
    issued_at: row.issuedAt.toISOString(),
    expires_at: row.expiresAt.toISOString(),
  };
}
