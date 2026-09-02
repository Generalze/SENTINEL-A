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
import { composeDeviceGatewayPrincipalFacts, resolveGatewayActor, sessionAuthenticatedBy } from './device-gateway.principals';
import {
  DeviceGatewayRepository,
  type EstablishmentChallengeRow,
  type GatewayTx,
  type IssuedContextRow,
} from './device-gateway.repository';
import { DeviceGatewayTransactionRollback, isDeviceGatewayTransactionRollback } from './device-gateway.rollback';
import type { DeviceContextEstablishmentResult, DeviceGatewayPrincipalFacts, DeviceGatewayRefusal } from './device-gateway.types';

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
 *        -> THE SAME HUMAN, STILL AUTHENTICATED, submits the device's answer:
 *           a frozen DeviceRequestProof signed by the registered key —
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
 * C17-01 — BOTH STEPS REQUIRE THE AUTHENTICATED HUMAN, AND THAT IS NOT A
 * BEARER SHORTCUT
 * -----------------------------------------------------------------------
 * The previous revision of this file made step two `@Public()` and then
 * re-derived the "human half" from a live user/role lookup keyed on the
 * challenge's own `actor_user_id`. That is an AUTHORISATION lookup wearing an
 * AUTHENTICATION label: it proves a person with that id exists and still holds
 * a capability, and says nothing whatsoever about who sent the request. Anyone
 * holding the challenge and the device key satisfied it.
 *
 * D25-01 forbids a DEVICE BEARER CREDENTIAL. It does not forbid — it REQUIRES —
 * the independent human session, and collapsing the two is exactly what the
 * two-principal split exists to prevent. So:
 *
 *     THE SESSION proves WHO is calling.
 *     THE POSSESSION PROOF proves WHICH HARDWARE is answering.
 *     THE LIVE RE-READ proves THEY ARE STILL AUTHORISED NOW.
 *
 * and none of the three substitutes for another. The session is checked against
 * the challenge's own tenant and actor before anything else happens, so a valid
 * proof presented by a DIFFERENT authenticated human refuses.
 *
 * C17-02 — THE SESSION'S TENANT IS THE INITIAL TRUST ANCHOR
 * --------------------------------------------------------
 * Nothing here looks a challenge up by `proof.organisation_id`, and no audit
 * row is ever filed under a tenant the request merely NAMED. The challenge is
 * resolved under `principal.organisation_id`; the proof's claim is then
 * EQUALITY-BOUND against the persisted row and a mismatch is a refusal. Once
 * the row resolves, its own persisted organisation is authoritative. The
 * gateway audit deliberately carries no lifecycle foreign key, which makes
 * write-time provenance the only provenance there is.
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
    // C17-02: THE AUDIT TENANT IS THE SESSION'S, NEVER THE REQUEST'S. Filing a
    // refusal under `input.organisationId` would let any authenticated caller
    // append an append-only event to any tenant it could name.
    const auditOrganisationId = principal.organisation_id;
    const refuse = async (refusal: DeviceGatewayRefusal): Promise<{ outcome: 'REFUSED' }> => {
      await this.repository.appendOperationEventOutsideTransaction(
        {
          organisationId: auditOrganisationId,
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
          // The site is only a site id: it names nothing outside this tenant and
          // is a scalar the operator needs. The TENANT above is the field that
          // decides ownership, and it is the session's.
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
    const organisationId = principal.organisation_id;

    const actor = await resolveGatewayActor(
      this.repository,
      { organisationId, actorUserId: principal.user.id, actions: DEVICE_GATEWAY_CAPABILITY_ACTIONS },
      undefined,
    );
    if (actor === null) return refuse('ACTOR_NOT_USABLE');
    if (!actor.gatewaySiteIds.includes(input.siteId)) return refuse('SITE_NOT_USABLE');

    const device = await this.shield.findDevice(organisationId, input.deviceId);
    if (device === null) return refuse('DEVICE_NOT_USABLE');
    if (device.currentKeyId === null || device.currentKeyVersion === null) return refuse('REGISTRY_KEY_UNRESOLVABLE');

    // The device must be deployed at the site the context is being issued for.
    // This is the DEVICE half of site authority and it is asked separately from
    // the actor half above — neither may stand in for the other.
    if (!(await this.shield.hasActiveDeviceSiteScope(organisationId, device.id, input.siteId))) {
      return refuse('SITE_NOT_USABLE');
    }

    // CURRENT registry standing, through Shield's ONE canonical effective
    // resolution (C16-R5) at the frozen RECONNECT_HANDSHAKE purpose. A
    // QUARANTINED or COMPROMISED device gets no challenge at all: those are
    // decisions, not ignorance, and the purpose table says so.
    if (!(await this.registry.deviceMayAct(organisationId, device.id, 'RECONNECT_HANDSHAKE'))) {
      return refuse('DEVICE_NOT_USABLE');
    }
    const effectiveTrust = await this.registry.effectiveDeviceTrust(organisationId, device.id);
    if (effectiveTrust === null) return refuse('DEVICE_NOT_USABLE');

    // The key is RESOLVED FROM THE REGISTRY. There is no parameter through
    // which a caller could supply one, here or anywhere else in this module.
    const keyRecord = await this.registry.resolveRegistryKeyRecord(organisationId, device.currentKeyId);
    if (keyRecord === null) return refuse('REGISTRY_KEY_UNRESOLVABLE');

    const issuedAt = await this.repository.now();
    const expiresAt = new Date(issuedAt.getTime() + DEVICE_CONTEXT_ESTABLISHMENT_MAX_AGE_MS);
    const row = await this.repository.createEstablishmentChallenge({
      organisationId,
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
        organisationId: row.organisationId,
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
   * STEP TWO — the device answers, and a context is issued, converged on, or
   * nothing happens.
   *
   * C17-01: THE SAME AUTHENTICATED HUMAN AS STEP ONE. The session is not a
   * formality bolted onto a device call — it is the second principal, and the
   * three checks it feeds are asked before any server state is touched:
   *
   *     the request carries an authenticated principal at all;
   *     that principal's tenant owns the persisted challenge;
   *     that principal IS the actor the challenge is bound to.
   *
   * The human half is ALSO re-established from current server state (the actor
   * must still exist and must still hold a gateway-operable capability at the
   * site), because "authenticated a moment ago" and "authorised now" are two
   * facts and this ceremony needs both.
   */
  async completeEstablishment(
    principal: Principal,
    input: { establishmentId: string; proof: unknown; traceId: string },
  ): Promise<DeviceContextEstablishmentResult> {
    /**
     * C17-01 — THE SESSION FACT, ESTABLISHED ONCE, AT THE TOP.
     *
     * `principal` is a REQUIRED parameter of this method, and the controller
     * obtains it with `requirePrincipal`, which throws when the global guard
     * chain attached none. There is therefore no path on which this value is
     * defaulted, inferred, or derived from anything the caller sent — which is
     * precisely what was wrong with the boolean it replaces.
     */
    // C17-01: the TYPE is the proof, not this line. `principal` is a required,
    // non-nullable parameter supplied by `requirePrincipal` behind the global
    // session guard, so a caller cannot reach here without one — and
    // `sessionAuthenticatedBy` will not produce `true` from anything else.
    // The previous revision derived this half from "a matching user row was
    // found", which is authorisation, not authentication.
    const sessionAuthenticated = sessionAuthenticatedBy(principal);

    // C17-02: the initial tenant anchor, before ANY server row has resolved. It
    // is replaced, below, by the persisted challenge's own organisation the
    // moment one is found — and never by anything the request claimed.
    let auditOrganisationId = principal.organisation_id;

    const refuse = async (
      refusal: DeviceGatewayRefusal,
      contractRefusal: string | null,
      context: {
        deviceId: string | null;
        actorUserId: string | null;
        establishmentId: string | null;
        proposedContextId: string | null;
        siteId: string | null;
      },
    ): Promise<DeviceContextEstablishmentResult> => {
      await this.repository.appendOperationEventOutsideTransaction(
        {
          organisationId: auditOrganisationId,
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

    const parsedProof = DeviceRequestProofSchema.safeParse(input.proof);
    if (!parsedProof.success) {
      // A malformed proof is a shape complaint about the caller's own bytes.
      // The event is still filed, and it is filed under the SESSION's tenant,
      // which is a fact the server established rather than one it was told.
      return refuse('PROOF_MALFORMED', null, {
        deviceId: null,
        actorUserId: principal.user.id,
        establishmentId: input.establishmentId,
        proposedContextId: null,
        siteId: null,
      });
    }
    const proof = parsedProof.data;

    // ---------------------------------------------------------------------
    // PREFLIGHT — establishes nothing, commits nothing
    // ---------------------------------------------------------------------

    // C17-02: LOOKED UP BY THE SESSION'S TENANT. Never by `proof.organisation_id`.
    const challengeRow = await this.repository.findEstablishmentChallenge(principal.organisation_id, input.establishmentId);
    if (challengeRow === null) {
      return refuse('ESTABLISHMENT_NOT_USABLE', null, {
        deviceId: null,
        actorUserId: principal.user.id,
        establishmentId: input.establishmentId,
        proposedContextId: null,
        siteId: null,
      });
    }
    // The persisted row's organisation is authoritative from here on. It equals
    // the session's, because that is what selected it; assigning it anyway is
    // the statement that the ROW owns the tenant, not the lookup.
    auditOrganisationId = challengeRow.organisationId;
    const trace = {
      deviceId: challengeRow.deviceId,
      actorUserId: challengeRow.actorUserId,
      establishmentId: challengeRow.id,
      proposedContextId: challengeRow.proposedContextId,
      siteId: challengeRow.siteId,
    };

    // C17-02: the proof's CLAIMED tenant, equality-bound against the persisted
    // one. A claim may name a tenant in an internal reason; it may never select
    // which tenant owns an audit row.
    if (proof.organisation_id !== challengeRow.organisationId) {
      return refuse('PROOF_ORGANISATION_MISMATCH', null, trace);
    }
    // C17-01: a valid proof carried by a DIFFERENT authenticated human refuses.
    // Possession and identity are two facts; holding the key does not make the
    // caller the person the ceremony was opened for.
    if (principal.user.id !== challengeRow.actorUserId) {
      return refuse('SESSION_ACTOR_MISMATCH', null, trace);
    }

    const preflightNow = await this.repository.now();
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
    const peeked = await this.repository.readOnly((tx) =>
      this.replay.peek(tx, { organisationId: challengeRow.organisationId, replayKey }),
    );

    const preflightDecision = this.judge({
      challenge: challengeRow,
      proof,
      now: preflightNow,
      registered: preflight.registered,
      verified,
      principals: preflight.principals(verified, sessionAuthenticated),
      consumptionStored:
        peeked === null ? null : { statement_fingerprint: peeked.statementFingerprint, stored_outcome_ref: peeked.storedOutcomeRef ?? '' },
      replayKey,
    });
    if (preflightDecision.kind === 'REFUSED') {
      return refuse(preflightDecision.refusal, preflightDecision.contractRefusal, trace);
    }

    // C17-03: the ONE-SHOT GATES ARE ASKED OF AN ISSUANCE, NOT OF A RETRY.
    //
    // The old ordering rejected any challenge with `consumed_at IS NOT NULL`
    // before the classifier ever ran, which meant the lost-response retry — the
    // byte-identical signed request whose first response never arrived — was
    // told `ESTABLISHMENT_NOT_USABLE` about a ceremony that had SUCCEEDED. That
    // is Sentinel lying to an honest client about its own state.
    //
    // So the gates below apply to the arm that would MINT something. An exact
    // retry mints nothing: it is answered from the row that already exists.
    if (preflightDecision.effect === 'PROCEED') {
      if (challengeRow.consumedAt !== null) return refuse('ESTABLISHMENT_NOT_USABLE', null, trace);
      // Expiry is evaluated AT REQUEST TIME, exclusively (`now >= expires_at`),
      // and there is no scheduler anywhere. One-shot is decided here for the
      // cheap case and AGAIN under lock in the transaction, which is the one
      // that counts.
      if (preflightNow.getTime() >= challengeRow.expiresAt.getTime()) return refuse('ESTABLISHMENT_NOT_USABLE', null, trace);
    }

    // ---------------------------------------------------------------------
    // FINAL TRANSACTION — one transaction, or nothing
    // ---------------------------------------------------------------------
    try {
      return await this.repository.transaction(async (tx) => {
        const locked = await this.repository.lockEstablishmentChallenge(tx, challengeRow.organisationId, input.establishmentId);
        if (locked === null) throw new DeviceGatewayTransactionRollback('ESTABLISHMENT_NOT_USABLE');
        const now = await this.repository.dbNow(tx);

        // Every fact re-read, under the device and key row locks, INSIDE the
        // transaction that is about to mint the context.
        await this.shield.lockDevice(tx, locked.organisationId, locked.deviceId);
        await this.shield.lockDeviceKeyByKeyId(tx, locked.organisationId, locked.keyId);
        const facts = await this.resolveFacts(locked, tx);
        if (facts.kind === 'REFUSED') throw new DeviceGatewayTransactionRollback(facts.refusal);

        const finalPeek = await this.replay.peek(tx, { organisationId: locked.organisationId, replayKey });
        const decision = this.judge({
          challenge: locked,
          proof,
          now,
          registered: facts.registered,
          verified,
          principals: facts.principals(verified, sessionAuthenticated),
          consumptionStored:
            finalPeek === null
              ? null
              : { statement_fingerprint: finalPeek.statementFingerprint, stored_outcome_ref: finalPeek.storedOutcomeRef ?? '' },
          replayKey,
        });
        if (decision.kind === 'REFUSED') {
          throw new DeviceGatewayTransactionRollback(decision.refusal, decision.contractRefusal);
        }

        if (decision.effect === 'CONVERGE') {
          return this.converge(tx, {
            locked,
            storedOutcomeRef: decision.storedOutcomeRef,
            fingerprint: decision.fingerprint,
            traceId: input.traceId,
            trust: facts.trust,
          });
        }

        // A FIRST issuance. Both one-shot gates again, now under the row lock,
        // which is the check that actually decides.
        if (locked.consumedAt !== null) throw new DeviceGatewayTransactionRollback('ESTABLISHMENT_NOT_USABLE');
        if (now.getTime() >= locked.expiresAt.getTime()) throw new DeviceGatewayTransactionRollback('ESTABLISHMENT_NOT_USABLE');

        // Spend the ceremony. Fenced on `consumed_at IS NULL`, so a second use
        // updates zero rows and the whole transaction rolls back — "one-shot"
        // is a compare-and-set, not an intention.
        const consumed = await this.repository.consumeEstablishmentChallenge(tx, locked.organisationId, locked.id, now);
        if (consumed !== 1) throw new DeviceGatewayTransactionRollback('ESTABLISHMENT_NOT_USABLE');

        // Spend the one-shot replay identity in Shield's ONE store, under this
        // module's own ceremony label. The outcome reference is the context id
        // that is about to exist, which is exactly what makes the C17-03
        // convergence above a REAL comparison rather than a tautology: the
        // retry derives nothing — it reads this stored value and resolves it
        // against the committed row.
        const claimed = await this.replay.consume(tx, {
          organisationId: locked.organisationId,
          ceremony: DEVICE_GATEWAY_ESTABLISHMENT_CEREMONY,
          replayKey,
          statementFingerprint: decision.fingerprint,
          candidateOutcomeRef: locked.proposedContextId,
          traceId: input.traceId,
        });
        if (claimed.consumption.outcome === 'REUSED_WITH_CHANGED_SEMANTICS') {
          throw new DeviceGatewayTransactionRollback('REPLAY_CONFLICT', 'NONCE_REUSED_WITH_CHANGED_SEMANTICS');
        }
        if (claimed.consumption.outcome === 'EXACT_DUPLICATE') {
          // A concurrent identical request committed between the peek and this
          // insert. It is the same convergence, decided against the store's
          // authoritative answer rather than against the peek's.
          return this.converge(tx, {
            locked,
            storedOutcomeRef: claimed.consumption.stored_outcome_ref,
            fingerprint: decision.fingerprint,
            traceId: input.traceId,
            trust: facts.trust,
          });
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
        return { outcome: 'ISSUED' as const, context: contextViewOf(record, [locked.siteId], facts.trust) };
      });
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

  /**
   * C17-03 — THE CONVERGENCE ARM: THE LOST RESPONSE, ANSWERED HONESTLY.
   *
   * EVERY ONE of the following must agree before a retry is answered with a
   * context, and any disagreement FAILS CLOSED rather than degrading into a
   * second issuance:
   *
   *   * the same ESTABLISHMENT — the locked challenge row this retry named;
   *   * the same REPLAY IDENTITY — the store already holds it;
   *   * the same STATEMENT FINGERPRINT — the frozen classifier said
   *     EXACT_DUPLICATE, so the signed bytes are the same bytes;
   *   * the same PROPOSED CONTEXT — the stored outcome reference IS this
   *     challenge's `proposed_context_id`, not merely something that parses;
   *   * an AUTHORITATIVE PERSISTED CONTEXT — read back, under lock, in this
   *     transaction, still open;
   *   * the EXACT binding — organisation, actor, device, site, key id and key
   *     version, each equality-bound against the challenge.
   *
   * WHAT IT RETURNS IS THE ROW, NOT A RECONSTRUCTION. The same `context_id`,
   * the same `issued_at`, the same `expires_at`. A retry that extended the
   * window would be minting authority out of a network failure, which is the
   * mirror image of the bug this fixes.
   *
   * AND IT GRANTS NOTHING NEW. The session checks in `completeEstablishment`
   * ran before this point and apply to the retry exactly as they applied to the
   * first attempt: an exact retry presented by a different authenticated human,
   * or with no session at all, never reaches here.
   */
  private async converge(
    tx: GatewayTx,
    input: {
      locked: EstablishmentChallengeRow;
      storedOutcomeRef: string;
      fingerprint: string;
      traceId: string;
      trust: DeviceTrust;
    },
  ): Promise<DeviceContextEstablishmentResult> {
    const { locked } = input;
    // The stored reference must be THIS ceremony's proposed context id. A
    // reference that resolves to anything else is a stored outcome this
    // ceremony cannot claim.
    if (input.storedOutcomeRef !== locked.proposedContextId) {
      throw new DeviceGatewayTransactionRollback('DUPLICATE_UNRESOLVABLE');
    }
    const record = await this.repository.lockContext(tx, locked.organisationId, locked.proposedContextId);
    if (record === null) throw new DeviceGatewayTransactionRollback('DUPLICATE_UNRESOLVABLE');
    if (record.closedAt !== null) throw new DeviceGatewayTransactionRollback('DUPLICATE_UNRESOLVABLE');
    if (
      record.establishmentId !== locked.id ||
      record.organisationId !== locked.organisationId ||
      record.actorUserId !== locked.actorUserId ||
      record.deviceId !== locked.deviceId ||
      record.keyId !== locked.keyId ||
      record.keyVersion !== locked.keyVersion
    ) {
      throw new DeviceGatewayTransactionRollback('DUPLICATE_UNRESOLVABLE');
    }
    const siteIds = await this.repository.listContextSiteIds(tx, record.organisationId, record.id);
    if (siteIds.length !== 1 || siteIds[0] !== locked.siteId) {
      throw new DeviceGatewayTransactionRollback('DUPLICATE_UNRESOLVABLE');
    }

    await this.repository.appendOperationEvent(
      tx,
      {
        organisationId: record.organisationId,
        contextId: record.id,
        deviceId: record.deviceId,
        actorUserId: record.actorUserId,
        operationKind: null,
        occurredAt: new Date(),
        traceId: input.traceId,
      },
      {
        type: 'CONTEXT_CONVERGED',
        establishmentId: locked.id,
        siteId: locked.siteId,
        keyId: record.keyId,
        keyVersion: record.keyVersion,
        issuedAt: record.issuedAt.toISOString(),
        expiresAt: record.expiresAt.toISOString(),
        statementFingerprint: input.fingerprint,
        storedOutcomeRef: input.storedOutcomeRef,
      },
    );

    return { outcome: 'CONVERGED', context: contextViewOf(record, siteIds, input.trust) };
  }

  // -------------------------------------------------------------------------
  // The facts, resolved identically in preflight and under lock
  // -------------------------------------------------------------------------

  /**
   * ONE resolution, called TWICE — once in preflight and once inside the final
   * transaction with `tx` supplied.
   *
   * C17-04: WHEN `tx` IS SUPPLIED, EVERY READ BELOW JOINS IT. The previous
   * revision claimed that in a comment while resolving the registry key record
   * and the device's site deployment on the base client — outside the
   * transaction holding the device and key locks. Both are authority-bearing,
   * and a read taken outside the transaction that commits on it is a read of a
   * world that may already have moved. The site deployment is not merely joined
   * to the transaction now: the EXACT `(organisation, device, site)` scope row
   * is LOCKED, so a concurrent release blocks rather than slipping between the
   * decision and the commit.
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
        /**
         * The five facts of C17-01, composed from what THIS resolution
         * established plus the two the caller owns: whether the signature
         * verified, and whether THIS REQUEST carried an authenticated session.
         */
        principals: (possessionVerified: boolean, sessionAuthenticated: boolean) => DeviceGatewayPrincipalFacts;
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
    const keyRecord = await this.registry.resolveRegistryKeyRecord(challenge.organisationId, device.currentKeyId, tx);
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

    // Both halves of site authority, asked independently: the HUMAN must
    // currently work this site and the DEVICE must currently be deployed at it.
    const humanSiteAuthorityGranted = actor.gatewaySiteIds.includes(challenge.siteId);
    const deviceSiteAuthorityGranted =
      tx === undefined
        ? await this.shield.hasActiveDeviceSiteScope(challenge.organisationId, device.id, challenge.siteId)
        : await this.shield.lockActiveDeviceSiteScope(tx, challenge.organisationId, device.id, challenge.siteId);

    return {
      kind: 'RESOLVED',
      publicKey: keyRecord.public_key,
      trust,
      principals: (possessionVerified, sessionAuthenticated) =>
        composeDeviceGatewayPrincipalFacts({
          sessionAuthenticated,
          // The establishment ceremony is not pinned to one §62 action (see
          // `resolveGatewayActor`): what it requires is that the person still
          // holds SOME gateway-operable capability SOMEWHERE, and the site
          // question is asked separately below.
          actorCurrentlyAuthorised: actor.gatewaySiteIds.length > 0,
          possessionVerified,
          credentialIntact,
          deviceCurrentlyTrusted: trust,
          humanSiteAuthorityGranted,
          deviceSiteAuthorityGranted,
        }),
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
          holds_required_capability: humanSiteAuthorityGranted,
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
    challenge: EstablishmentChallengeRow;
    proof: DeviceRequestProof;
    now: Date;
    registered: DeviceRegistryFacts;
    verified: boolean;
    /** C17-01: five named facts, never one boolean standing in for two. */
    principals: DeviceGatewayPrincipalFacts;
    consumptionStored: { statement_fingerprint: string; stored_outcome_ref: string } | null;
    replayKey: string;
  }):
    | { kind: 'AUTHENTICATED'; effect: 'PROCEED'; fingerprint: string }
    | { kind: 'AUTHENTICATED'; effect: 'CONVERGE'; fingerprint: string; storedOutcomeRef: string }
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
      device_trust: input.principals.deviceCurrentlyTrusted,
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
      // C17-03: the SAME one-shot identity carrying DIFFERENT signed semantics
      // is not a retry to converge, it is a conflict, and it stays one whether
      // or not the establishment has been spent.
      const conflict = authentication.refusal === 'NONCE_REUSED_WITH_CHANGED_SEMANTICS';
      return {
        kind: 'REFUSED',
        refusal: conflict ? 'REPLAY_CONFLICT' : 'PROOF_REFUSED',
        contractRefusal: authentication.refusal,
      };
    }

    // C17-01: AUTHORISATION NOW, asked as its own question. `AUTHENTICATION_ONLY`
    // deliberately skips the frozen evaluator's actor block, so this is the only
    // place the establishment ceremony asks it, and it is asked of a fact the
    // live user/role re-read established — never of the session, and never of
    // the device.
    if (!input.principals.actorCurrentlyAuthorised) {
      return { kind: 'REFUSED', refusal: 'ACTOR_NOT_USABLE', contractRefusal: null };
    }

    // BOTH PRINCIPALS, INDEPENDENTLY. A perfectly TRUSTED device with no
    // current human SESSION is refused here, and an authenticated human with no
    // hardware possession was already refused above. That symmetry is the whole
    // ruling.
    const admission = evaluateDeviceOperationPrincipals({
      // C17-01: THE SESSION, AND ONLY THE SESSION. This used to be fed from
      // "the actor row resolved", which answers a different question entirely
      // and answered it `true` for a caller with no session at all.
      userAuthenticated: input.principals.sessionAuthenticated,
      deviceAuthenticated: input.principals.deviceAuthenticated,
      deviceTrust: input.principals.deviceCurrentlyTrusted,
      requiredTrust: DEVICE_PURPOSE_PERMITTED_TRUST.RECONNECT_HANDSHAKE,
      siteAuthorityGranted: input.principals.siteAuthorityGranted,
      // WP-25 adds no Constitution policy to these three surfaces. When one is
      // introduced it is evaluated HERE, as its own independent fact, and never
      // inferred from the device or the session.
      policySatisfied: true,
    });
    if (!admission.admitted) {
      return { kind: 'REFUSED', refusal: 'PRINCIPALS_REFUSED', contractRefusal: admission.refusal };
    }

    if (authentication.effect === 'CONVERGE_ON_STORED_OUTCOME') {
      return { kind: 'AUTHENTICATED', effect: 'CONVERGE', fingerprint: authentication.fingerprint, storedOutcomeRef: authentication.stored_outcome_ref };
    }
    return { kind: 'AUTHENTICATED', effect: 'PROCEED', fingerprint: authentication.fingerprint };
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

/**
 * The context handed back, ASSEMBLED FROM THE COMMITTED ROW.
 *
 * One function for both the issuance and the convergence arm, deliberately: two
 * would be two opinions about what an issued context looks like, and the whole
 * point of C17-03 is that a retry sees exactly what the first attempt produced.
 */
function contextViewOf(record: IssuedContextRow, siteIds: string[], trust: DeviceTrust): AuthenticatedDeviceContext {
  return AuthenticatedDeviceContextSchema.parse({
    schema_version: 1,
    context_id: record.id,
    organisation_id: record.organisationId,
    actor_user_id: record.actorUserId,
    device_id: record.deviceId,
    authorised_site_ids: siteIds,
    // HISTORICAL ISSUANCE STATE. The frozen contract requires the field; no
    // column stores it, and every operation reads CURRENT standing.
    device_trust: trust,
    key_id: record.keyId,
    key_version: record.keyVersion,
    issued_at: record.issuedAt.toISOString(),
    expires_at: record.expiresAt.toISOString(),
  });
}
