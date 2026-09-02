import { HttpException, Inject, Injectable } from '@nestjs/common';
import {
  DEVICE_PURPOSE_PERMITTED_TRUST,
  DeviceRequestProofSchema,
  canonicalDeviceRequestProofStatement,
  classifyDeviceNonceConsumption,
  deviceRequestProofFingerprint,
  deviceRequestProofReplayKey,
  deviceRequestProofStatementInput,
  evaluateDeviceOperationPrincipals,
  evaluateDeviceRequestProof,
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
import { DeviceGatewayDomainAdapters, type DeviceGatewayDomainCall } from './device-gateway.adapters';
import { DEVICE_GATEWAY_OPERATION_CEREMONY } from './device-gateway.constants';
import {
  DEVICE_GATEWAY_REQUIRED_ACTION,
  DEVICE_GATEWAY_TARGET_TYPE_FOR_KIND,
  parseOperationEnvelope,
  type DeviceGatewayOperationEnvelope,
  type DeviceGatewayOperationKind,
} from './device-gateway.envelope';
import { deviceGatewayDomainIdempotencyKey } from './device-gateway.idempotency';
import { composeDeviceGatewayPrincipalFacts, resolveActorAuthority, sessionAuthenticatedBy, type ResolvedActorAuthority } from './device-gateway.principals';
import { DeviceGatewayRepository, type GatewayTx, type IssuedContextRow } from './device-gateway.repository';
import { DeviceGatewayTransactionRollback, isDeviceGatewayTransactionRollback } from './device-gateway.rollback';
import type { DeviceGatewayOperationResult, DeviceGatewayPrincipalFacts, DeviceGatewayRefusal } from './device-gateway.types';

/**
 * WP-25/D25-02 — THE INGRESS PIPELINE: PREFLIGHT, THEN ONE EFFECT TRANSACTION.
 *
 * ```text
 * PREFLIGHT — establishes nothing, commits nothing
 * ────────────────────────────────────────────────
 * parse the typed operation envelope     gateway-owned, canonical (D25-11)
 * resolve the persisted context          server state, never a credential
 * resolve the current registry key       by the DEVICE's current pointer, in-org
 * bind the server profile                bindClaimedSignatureProfile
 * import the key                         WP-24's P-256 importer, OpenSSL
 * verify the signature                   over the canonical statement
 * build current registry + actor facts   DeviceRegistryFacts, read now
 * classify existing replay state         WITHOUT creating an effect
 * evaluateDeviceRequestProof             the frozen evaluator, unmodified
 * evaluateDeviceOperationPrincipals      both principals, independently
 *
 * FINAL EFFECT TRANSACTION — one transaction, or nothing
 * ──────────────────────────────────────────────────────
 * re-read AND LOCK:  persisted context (open, unexpired)
 *                    current device, current key, key version
 *                    revocation state, effective trust
 *                    current actor authority, current site authority
 *                    the domain target itself
 * then atomically:   claim the replay identity
 *                    execute the domain effect
 *                    record the authoritative outcome reference
 *                    append the gateway security audit
 * COMMIT TOGETHER
 * ```
 *
 * THE GOVERNING INVARIANT
 * -----------------------
 *     NO FIRST_SEEN DEVICE REPLAY CONSUMPTION MAY SURVIVE
 *     WITHOUT ITS CORRESPONDING DOMAIN EFFECT.
 *
 * This is why consumption and the domain effect are ONE transaction. The first
 * draft of D25-02 ended "consume the replay identity, then execute", which is
 * precisely the failure class WP-24 spent two correction batches eliminating:
 * if consumption commits and the effect then fails, Sentinel remembers an
 * operation that never happened, and the honest retry converges on nothing.
 *
 * C17-01 - THE HUMAN PRINCIPAL IS THE REQUEST'S SESSION, NOT A LOOKUP
 * ------------------------------------------------------------------
 * These routes are NOT `@Public()`. Every operation carries the ordinary
 * authenticated human principal, exactly as every other authenticated route in
 * this codebase does, and that principal is bound to the persisted context
 * before anything else happens:
 *
 *     principal.organisation_id === context.organisation_id
 *     principal.user.id         === context.actor_user_id
 *
 * A valid proof presented by a DIFFERENT authenticated human refuses, and a
 * valid proof presented with NO session never reaches this service at all. The
 * previous revision derived the human half from "a matching user row exists and
 * their roles resolve" - which proves CURRENT AUTHORISATION and proves nothing
 * about who sent the request, so a stolen context plus a device key was a
 * complete authority. Requiring the session is not a bearer shortcut: D25-01
 * forbids a DEVICE bearer credential, and the independent human session is the
 * second principal the whole invariant is built on.
 *
 * C17-02 - THE TENANT ANCHOR IS THE SESSION'S, NEVER THE PROOF'S
 * -------------------------------------------------------------
 * The context is resolved under `principal.organisation_id`; the proof's
 * claimed organisation is then EQUALITY-BOUND against the persisted row.
 * Nothing here files an audit event under a tenant the request merely named -
 * the gateway audit has no lifecycle foreign key by design, so write-time
 * provenance is the only provenance it has.
 *
 * WHY STEPS 9 AND 10 OF THE PREFLIGHT STAY SEPARATE
 * -------------------------------------------------
 * One asks *is this proof good for this context?* The other asks *are both
 * principals present and sufficient?* Collapsing them would let a strong device
 * proof paper over a missing session — which is the one thing §62.1 exists to
 * prevent.
 *
 * THE KEY IS NEVER TAKEN FROM THE REQUEST. It is resolved from the registry, by
 * the DEVICE ROW's current key pointer, and there is no parameter anywhere in
 * this module through which a caller could supply one. The proof's own `key_id`
 * and `key_version` are equality-bound against the registry's by the frozen
 * evaluator, so a disagreement is a refusal rather than a lookup somebody could
 * skip.
 *
 * POSSESSION IS PROVEN BEFORE ANY DOMAIN EFFECT, never alongside it.
 *
 * THE D25-04A FENCE
 * -----------------
 * Everything the preflight approved is RE-READ UNDER LOCK and RE-JUDGED by the
 * same two frozen evaluators inside the final transaction. A device revoked, a
 * key rotated, a context closed, an actor's capability withdrawn or a site
 * entitlement lost BETWEEN preflight and commit therefore refuses with zero
 * effect and zero consumption — an open connection is not a grant, and neither
 * is a preflight that passed a moment ago.
 */
@Injectable()
export class DeviceGatewayService {
  constructor(
    @Inject(DeviceGatewayRepository) private readonly repository: DeviceGatewayRepository,
    @Inject(ShieldRepository) private readonly shield: ShieldRepository,
    @Inject(DeviceRegistryService) private readonly registry: DeviceRegistryService,
    @Inject(DeviceReplayService) private readonly replay: DeviceReplayService,
    @Inject(P256KeyImporter) private readonly keys: P256KeyImporter,
    @Inject(DeviceGatewayDomainAdapters) private readonly adapters: DeviceGatewayDomainAdapters,
  ) {}

  /**
   * ONE entry point for all three operations.
   *
   * `kind` is supplied by the ROUTE and is not caller-controlled security input
   * (D25-11). `targetId` is `null` for the field-state update, whose target is
   * the operative themselves and is therefore resolved from the persisted
   * context rather than from the request.
   */
  async execute(
    principal: Principal,
    kind: DeviceGatewayOperationKind,
    request: { proof: unknown; body: unknown; targetId: string | null; traceId: string },
  ): Promise<DeviceGatewayOperationResult> {
    /**
     * C17-01 - THE SESSION FACT, ESTABLISHED ONCE, AT THE TOP.
     *
     * `principal` is a REQUIRED parameter and the controller obtains it with
     * `requirePrincipal`, which throws when the global guard chain attached
     * none. There is no path on which this is defaulted or inferred - which is
     * exactly what was wrong with the boolean it replaces.
     */
    // C17-01: the TYPE is the proof, not this line. `principal` is a required,
    // non-nullable parameter supplied by `requirePrincipal` behind the global
    // session guard, so a caller cannot reach here without one — and
    // `sessionAuthenticatedBy` will not produce `true` from anything else.
    // The previous revision derived this half from "a matching user row was
    // found", which is authorisation, not authentication.
    const sessionAuthenticated = sessionAuthenticatedBy(principal);

    // C17-02: the initial tenant anchor, before ANY server row has resolved.
    // Replaced below by the persisted context's own organisation, and never by
    // anything the request claimed.
    let auditOrganisationId = principal.organisation_id;

    const audit = (
      refusal: DeviceGatewayRefusal,
      contractRefusal: string | null,
      seen: {
        contextId: string | null;
        deviceId: string | null;
        actorUserId: string | null;
        siteId: string | null;
        targetId: string | null;
        payloadDigest: string | null;
        effectiveTrust: string | null;
      },
    ): Promise<void> =>
      this.repository.appendOperationEventOutsideTransaction(
        {
          organisationId: auditOrganisationId,
          contextId: seen.contextId,
          deviceId: seen.deviceId,
          actorUserId: seen.actorUserId,
          operationKind: kind,
          occurredAt: new Date(),
          traceId: request.traceId,
        },
        {
          type: 'OPERATION_REFUSED',
          siteId: seen.siteId,
          targetType: DEVICE_GATEWAY_TARGET_TYPE_FOR_KIND[kind],
          targetId: seen.targetId,
          payloadDigest: seen.payloadDigest,
          refusal,
          contractRefusal,
          effectiveTrust: seen.effectiveTrust,
        },
      );

    // -----------------------------------------------------------------------
    // PREFLIGHT
    // -----------------------------------------------------------------------

    const parsedProof = DeviceRequestProofSchema.safeParse(request.proof);
    if (!parsedProof.success) {
      // A malformed proof is a shape complaint about the caller's own bytes.
      // The event is still filed, and it is filed under the SESSION's tenant -
      // a fact the server established rather than one it was told.
      await audit('PROOF_MALFORMED', null, blank({ targetId: request.targetId }));
      return { outcome: 'REFUSED' };
    }
    const proof = parsedProof.data;

    // C17-02: RESOLVED BY THE SESSION'S TENANT, never by `proof.organisation_id`.
    // The context is resolved by (id, organisation) TOGETHER, so a foreign
    // context and a context that never existed produce one answer, from one
    // query, and there is no branch in which they could diverge (D25-13).
    const contextRow = await this.repository.findContext(principal.organisation_id, proof.context_id);
    if (contextRow === null) {
      await audit('CONTEXT_NOT_USABLE', null, blank({ targetId: request.targetId }));
      return { outcome: 'REFUSED' };
    }
    // The persisted row's organisation is authoritative from here on.
    auditOrganisationId = contextRow.organisationId;
    const contextSiteIds = await this.repository.listContextSiteIdsUnlocked(contextRow.organisationId, contextRow.id);
    const seen = {
      contextId: contextRow.id,
      deviceId: contextRow.deviceId,
      actorUserId: contextRow.actorUserId,
      siteId: proof.site_id,
      targetId: request.targetId ?? contextRow.actorUserId,
      payloadDigest: null as string | null,
      effectiveTrust: null as string | null,
    };

    // C17-02: the proof's CLAIMED tenant, equality-bound against the persisted
    // context's. A claim may appear in an internal reason; it may never select
    // which tenant owns an audit row.
    if (proof.organisation_id !== contextRow.organisationId) {
      await audit('PROOF_ORGANISATION_MISMATCH', null, seen);
      return { outcome: 'REFUSED' };
    }
    // C17-01: a valid proof carried by a DIFFERENT authenticated human refuses.
    // Possession and identity are two facts, and holding the hardware does not
    // make the caller the operative the context is bound to.
    if (principal.user.id !== contextRow.actorUserId) {
      await audit('SESSION_ACTOR_MISMATCH', null, seen);
      return { outcome: 'REFUSED' };
    }

    const targetId = request.targetId ?? contextRow.actorUserId;
    const envelopeParse = parseOperationEnvelope(
      kind,
      {
        // Every identity field is SERVER-RESOLVED — from the persisted context
        // and from the signed proof's site — and none is read from the body.
        organisationId: contextRow.organisationId,
        siteId: proof.site_id,
        actorUserId: contextRow.actorUserId,
        deviceId: contextRow.deviceId,
        targetId,
      },
      request.body,
    );
    if (!envelopeParse.ok) {
      await audit(envelopeParse.refusal, null, seen);
      return { outcome: 'REFUSED' };
    }
    seen.payloadDigest = envelopeParse.digest;

    const requiredAction = DEVICE_GATEWAY_REQUIRED_ACTION[kind];
    const preflight = await this.resolveFacts(contextRow, contextSiteIds, proof, requiredAction, undefined);
    if (preflight.kind === 'REFUSED') {
      await audit(preflight.refusal, null, seen);
      return { outcome: 'REFUSED' };
    }
    seen.effectiveTrust = preflight.trust;

    const statement = canonicalDeviceRequestProofStatement(
      deviceRequestProofStatementInput(proof, preflight.registered.signature_profile),
    );
    const verified = this.keys.verifySignature({
      registeredPublicKey: preflight.publicKey,
      message: statement,
      signature: proof.signature,
      serverResolvedProfile: preflight.registered.signature_profile,
      claimedProfile: proof.claimed_signature_profile,
    });

    const replayKey = deviceRequestProofReplayKey(proof);
    const fingerprint = deviceRequestProofFingerprint(
      deviceRequestProofStatementInput(proof, preflight.registered.signature_profile),
    );
    // CLASSIFY WITHOUT CREATING AN EFFECT. `peek` reads what the store already
    // holds for this identity and takes no decision; `consume` — the call that
    // BURNS the identity — happens only inside the final transaction.
    const peeked = await this.repository.readOnly((tx) =>
      this.replay.peek(tx, { organisationId: contextRow.organisationId, replayKey }),
    );

    const preflightJudgement = this.judge({
      context: preflight.context,
      proof,
      now: await this.repository.now(),
      expectedPayloadDigest: envelopeParse.digest,
      registered: preflight.registered,
      verified,
      principals: preflight.principals(verified, sessionAuthenticated),
      replayKey,
      fingerprint,
      stored: peeked === null ? null : { statement_fingerprint: peeked.statementFingerprint, stored_outcome_ref: peeked.storedOutcomeRef ?? '' },
    });
    if (preflightJudgement.kind === 'REFUSED') {
      await audit(preflightJudgement.refusal, preflightJudgement.contractRefusal, seen);
      return preflightJudgement.refusal === 'REPLAY_CONFLICT' ? { outcome: 'CONFLICT' } : { outcome: 'REFUSED' };
    }

    // -----------------------------------------------------------------------
    // FINAL EFFECT TRANSACTION — one, or nothing
    // -----------------------------------------------------------------------
    try {
      return await this.repository.transaction(async (tx) => {
        const lockedContext = await this.repository.lockContext(tx, contextRow.organisationId, contextRow.id);
        if (lockedContext === null) throw new DeviceGatewayTransactionRollback('CONTEXT_NOT_USABLE');
        // D25-04A: server-side invalidation lands on `closed_at`, and this is
        // where a close that happened AFTER the preflight is seen.
        if (lockedContext.closedAt !== null) throw new DeviceGatewayTransactionRollback('CONTEXT_NOT_USABLE');
        const lockedSiteIds = await this.repository.listContextSiteIds(tx, lockedContext.organisationId, lockedContext.id);
        // C17-04: the context's EXACT site binding for the site being acted at,
        // LOCKED, rather than inferred from a list nothing is holding still. The
        // list above is what the frozen evaluator judges; this is the one row the
        // decision actually rests on, and it is held for the commit.
        if (!(await this.repository.lockContextSiteBinding(tx, lockedContext.organisationId, lockedContext.id, proof.site_id))) {
          throw new DeviceGatewayTransactionRollback('SITE_NOT_USABLE');
        }

        // The device and key rows — the two rows that can WITHDRAW a credential
        // — are held still for the duration of the decision they feed.
        await this.shield.lockDevice(tx, lockedContext.organisationId, lockedContext.deviceId);
        await this.shield.lockDeviceKeyByKeyId(tx, lockedContext.organisationId, lockedContext.keyId);

        const facts = await this.resolveFacts(lockedContext, lockedSiteIds, proof, requiredAction, tx);
        if (facts.kind === 'REFUSED') throw new DeviceGatewayTransactionRollback(facts.refusal);

        const finalPeek = await this.replay.peek(tx, { organisationId: lockedContext.organisationId, replayKey });
        const judgement = this.judge({
          context: facts.context,
          proof,
          now: await this.repository.dbNow(tx),
          expectedPayloadDigest: envelopeParse.digest,
          registered: facts.registered,
          verified,
          principals: facts.principals(verified, sessionAuthenticated),
          replayKey,
          fingerprint,
          stored:
            finalPeek === null
              ? null
              : { statement_fingerprint: finalPeek.statementFingerprint, stored_outcome_ref: finalPeek.storedOutcomeRef ?? '' },
        });
        if (judgement.kind === 'REFUSED') {
          throw new DeviceGatewayTransactionRollback(judgement.refusal, judgement.contractRefusal);
        }

        // D25-16B: the downstream identity, derived HERE, from facts of the
        // signed request. The device has no parameter with which to choose it.
        const domainIdempotencyKey = deviceGatewayDomainIdempotencyKey({
          organisationId: lockedContext.organisationId,
          contextId: lockedContext.id,
          actorUserId: lockedContext.actorUserId,
          deviceId: lockedContext.deviceId,
          keyId: facts.registered.key_id,
          keyVersion: facts.registered.key_version,
          operationKind: kind,
          targetType: envelopeParse.envelope.target_type,
          targetId: envelopeParse.envelope.target_id,
          deviceNonce: proof.nonce,
          payloadDigest: envelopeParse.digest,
        });

        const call: DeviceGatewayDomainCall = {
          kind,
          principal: facts.actor.principal,
          siteScope: facts.actor.siteScope,
          siteId: proof.site_id,
          deviceId: lockedContext.deviceId,
          targetId: envelopeParse.envelope.target_id,
          semanticPayload: envelopeParse.envelope.semantic_payload,
          domainIdempotencyKey,
          traceId: request.traceId,
        };

        const auditEnvelope = {
          organisationId: lockedContext.organisationId,
          contextId: lockedContext.id,
          deviceId: lockedContext.deviceId,
          actorUserId: lockedContext.actorUserId,
          operationKind: kind,
          occurredAt: new Date(),
          traceId: request.traceId,
        };

        if (judgement.effect === 'CONVERGE') {
          return this.converge(tx, {
            call,
            envelope: envelopeParse.envelope,
            digest: envelopeParse.digest,
            fingerprint,
            storedOutcomeRef: judgement.storedOutcomeRef,
            domainIdempotencyKey,
            auditEnvelope,
            contextId: lockedContext.id,
          });
        }

        // FIRST_SEEN. Claim the identity — uncommitted — and then cause the
        // effect, so the two land together or not at all.
        const claimed = await this.replay.consume(tx, {
          organisationId: lockedContext.organisationId,
          ceremony: DEVICE_GATEWAY_OPERATION_CEREMONY,
          replayKey,
          statementFingerprint: fingerprint,
          // The reference a later exact retry converges ON. It is the SERVER's
          // domain idempotency key, which is deterministic for this exact
          // signed operation — so the retry derives the same value and the
          // convergence check is a real comparison rather than a tautology.
          candidateOutcomeRef: domainIdempotencyKey,
          traceId: request.traceId,
        });
        if (claimed.consumption.outcome === 'REUSED_WITH_CHANGED_SEMANTICS') {
          throw new DeviceGatewayTransactionRollback('REPLAY_CONFLICT', 'NONCE_REUSED_WITH_CHANGED_SEMANTICS');
        }
        if (claimed.consumption.outcome === 'EXACT_DUPLICATE') {
          // A concurrent identical request won the race and committed between
          // the peek and this insert. It is the same convergence, decided
          // against the store's authoritative answer rather than the peek's.
          return this.converge(tx, {
            call,
            envelope: envelopeParse.envelope,
            digest: envelopeParse.digest,
            fingerprint,
            storedOutcomeRef: claimed.consumption.stored_outcome_ref,
            domainIdempotencyKey,
            auditEnvelope,
            contextId: lockedContext.id,
          });
        }

        const applied = await this.applyDomainEffect(tx, call);
        // The gateway attests to what the DOMAIN actually did, never to the
        // fact that a call returned. An unverifiable result rolls everything
        // back rather than recording an outcome nobody can prove.
        if (!applied.authoritative) throw new DeviceGatewayTransactionRollback('DOMAIN_EFFECT_NOT_AUTHORITATIVE');

        await this.repository.appendOperationEvent(tx, auditEnvelope, {
          type: 'OPERATION_COMMITTED',
          siteId: proof.site_id,
          targetType: envelopeParse.envelope.target_type,
          targetId: envelopeParse.envelope.target_id,
          keyId: facts.registered.key_id,
          keyVersion: facts.registered.key_version,
          payloadDigest: envelopeParse.digest,
          statementFingerprint: fingerprint,
          domainIdempotencyKey,
          effectiveTrust: facts.trust,
        });

        return {
          outcome: 'COMMITTED' as const,
          operationKind: kind,
          targetType: envelopeParse.envelope.target_type,
          targetId: envelopeParse.envelope.target_id,
          contextId: lockedContext.id,
          view: applied.view,
        };
      });
    } catch (error) {
      if (isDeviceGatewayTransactionRollback(error)) {
        // Postgres has already rolled the whole transaction back. The audit
        // event is written AFTERWARDS, in its own transaction, so the trail of
        // the refusal survives while the security state does not.
        await audit(error.refusal, error.contractRefusal, seen);
        return error.refusal === 'REPLAY_CONFLICT' ? { outcome: 'CONFLICT' } : { outcome: 'REFUSED' };
      }
      throw error;
    }
  }

  /**
   * The convergence arm: same identity, same fingerprint, a committed outcome
   * that RESOLVES. No second effect.
   *
   * BOTH halves are checked. The stored reference must be the one this exact
   * signed operation derives, AND the DOMAIN must confirm that identity
   * committed. A reference that cannot be proved against the actual
   * authoritative domain row FAILS CLOSED — convergence is never manufactured
   * out of the request that asked for it.
   */
  private async converge(
    tx: GatewayTx,
    input: {
      call: DeviceGatewayDomainCall;
      envelope: DeviceGatewayOperationEnvelope;
      digest: string;
      fingerprint: string;
      storedOutcomeRef: string;
      domainIdempotencyKey: string;
      auditEnvelope: Parameters<DeviceGatewayRepository['appendOperationEvent']>[1];
      contextId: string;
    },
  ): Promise<DeviceGatewayOperationResult> {
    if (input.storedOutcomeRef !== input.domainIdempotencyKey) {
      throw new DeviceGatewayTransactionRollback('DUPLICATE_UNRESOLVABLE');
    }
    if (!(await this.adapters.resolveCommitted(input.call))) {
      throw new DeviceGatewayTransactionRollback('DUPLICATE_UNRESOLVABLE');
    }
    const view = await this.adapters.readCommittedView(input.call);
    await this.repository.appendOperationEvent(tx, input.auditEnvelope, {
      type: 'OPERATION_CONVERGED',
      siteId: input.envelope.site_id,
      targetType: input.envelope.target_type,
      targetId: input.envelope.target_id,
      payloadDigest: input.digest,
      statementFingerprint: input.fingerprint,
      storedOutcomeRef: input.storedOutcomeRef,
    });
    return {
      outcome: 'CONVERGED',
      operationKind: input.call.kind,
      targetType: input.envelope.target_type,
      targetId: input.envelope.target_id,
      contextId: input.contextId,
      view,
    };
  }

  /**
   * Calls the domain service, and turns ITS refusal into a rollback.
   *
   * A domain service that refuses does so by throwing its own HTTP exception —
   * a 404 for an assignment that is not this operative's, a 409 for a delivery
   * row that is not DELIVERED. Letting that escape would return normally from
   * the callback's perspective in some future refactor, and a normal return
   * from a Prisma interactive transaction COMMITS. It is converted to the
   * sentinel here so the replay claim taken a moment ago cannot outlive the
   * effect it was claimed for.
   *
   * Anything that is NOT a domain refusal — an infrastructure fault, a driver
   * error, an injected failure — is rethrown untouched. It still aborts the
   * transaction, and dressing it up as a refusal would hide a real fault behind
   * a security verdict.
   */
  private async applyDomainEffect(
    tx: GatewayTx,
    call: DeviceGatewayDomainCall,
  ): Promise<{ view: unknown; authoritative: boolean }> {
    try {
      return await this.adapters.apply(tx, call);
    } catch (error) {
      if (error instanceof HttpException) throw new DeviceGatewayTransactionRollback('DOMAIN_EFFECT_REFUSED');
      throw error;
    }
  }

  // -------------------------------------------------------------------------
  // The facts, resolved identically in preflight and under lock
  // -------------------------------------------------------------------------

  /**
   * ONE resolution, called TWICE — once in preflight and once inside the final
   * transaction with `tx` supplied, where every read joins the transaction that
   * holds the locks.
   *
   * Two copies would be two opinions about what the current facts are, and the
   * D25-04A fence would then be checking something subtly different from what
   * the preflight approved.
   */
  private async resolveFacts(
    contextRow: IssuedContextRow,
    contextSiteIds: string[],
    proof: DeviceRequestProof,
    requiredAction: string,
    tx: GatewayTx | undefined,
  ): Promise<
    | {
        kind: 'RESOLVED';
        context: AuthenticatedDeviceContext;
        registered: DeviceRegistryFacts;
        publicKey: string;
        trust: DeviceTrust;
        /**
         * C17-01: the five named facts, composed from what THIS resolution
         * established plus the two the caller owns - whether the signature
         * verified, and whether THIS REQUEST carried an authenticated session.
         */
        principals: (possessionVerified: boolean, sessionAuthenticated: boolean) => DeviceGatewayPrincipalFacts;
        actor: ResolvedActorAuthority;
      }
    | { kind: 'REFUSED'; refusal: DeviceGatewayRefusal }
  > {
    const device = await this.shield.findDevice(contextRow.organisationId, contextRow.deviceId, tx);
    if (device === null) return { kind: 'REFUSED', refusal: 'DEVICE_NOT_USABLE' };
    if (device.currentKeyId === null) return { kind: 'REFUSED', refusal: 'REGISTRY_KEY_UNRESOLVABLE' };

    // C17-04: `tx` is threaded. Resolving the registry key on the base client
    // while the transaction holds the device and key row locks would be reading
    // a row nothing is holding still, in the transaction that commits on it.
    const keyRecord = await this.registry.resolveRegistryKeyRecord(contextRow.organisationId, device.currentKeyId, tx);
    if (keyRecord === null) return { kind: 'REFUSED', refusal: 'REGISTRY_KEY_UNRESOLVABLE' };

    const trust = await this.registry.effectiveDeviceTrust(contextRow.organisationId, device.id, tx);
    if (trust === null) return { kind: 'REFUSED', refusal: 'DEVICE_NOT_USABLE' };
    const credentialIntact = await this.registry.credentialAdmitsNewOperations(contextRow.organisationId, device.id, tx);

    const actor = await resolveActorAuthority(
      this.repository,
      { organisationId: contextRow.organisationId, actorUserId: contextRow.actorUserId, requiredAction },
      tx,
    );
    if (actor === null) return { kind: 'REFUSED', refusal: 'ACTOR_NOT_USABLE' };

    // C17-04: the DEVICE half of site authority. Inside the final transaction
    // this LOCKS the exact active (organisation, device, site) scope row, so a
    // concurrent release blocks until this decision commits or rolls back rather
    // than slipping between the two. Outside it, in the preflight that commits
    // nothing, it is the same question asked without a lock.
    const deviceSiteAuthorityGranted =
      tx === undefined
        ? await this.shield.hasActiveDeviceSiteScope(contextRow.organisationId, device.id, proof.site_id)
        : await this.shield.lockActiveDeviceSiteScope(tx, contextRow.organisationId, device.id, proof.site_id);

    if (contextSiteIds.length === 0) return { kind: 'REFUSED', refusal: 'CONTEXT_NOT_USABLE' };

    return {
      kind: 'RESOLVED',
      publicKey: keyRecord.public_key,
      trust,
      actor,
      principals: (possessionVerified, sessionAuthenticated) =>
        composeDeviceGatewayPrincipalFacts({
          sessionAuthenticated,
          // AUTHORISATION NOW, from the live user and role tables, for the
          // action THIS operation requires. It is a different question from
          // "who is calling?", and it is asked separately for that reason.
          actorCurrentlyAuthorised: actor.facts.holds_required_capability,
          possessionVerified,
          credentialIntact,
          deviceCurrentlyTrusted: trust,
          // BOTH halves of site authority, asked independently. The HUMAN must
          // currently work the site and the DEVICE must currently be deployed at
          // it; neither says anything about the other, and a registered device
          // acting at a site it was never associated with is exactly the fusion
          // 62.1 forbids.
          humanSiteAuthorityGranted: actor.facts.authorised_site_ids.includes(proof.site_id),
          deviceSiteAuthorityGranted,
        }),
      context: {
        schema_version: 1,
        context_id: contextRow.id,
        organisation_id: contextRow.organisationId,
        actor_user_id: contextRow.actorUserId,
        device_id: contextRow.deviceId,
        authorised_site_ids: contextSiteIds,
        // The frozen schema requires the field and no evaluator reads it. There
        // is deliberately no column for it (see `device-gateway.prisma`): the
        // CURRENT effective standing is filled in here so that no stale
        // authority-shaped value exists anywhere for somebody to mistake for
        // the answer.
        device_trust: trust,
        key_id: contextRow.keyId,
        key_version: contextRow.keyVersion,
        issued_at: contextRow.issuedAt.toISOString(),
        expires_at: contextRow.expiresAt.toISOString(),
      },
      registered: {
        organisation_id: keyRecord.organisation_id,
        device_id: keyRecord.device_id,
        // The CURRENT registry key and version, so a rotation refuses as
        // KEY_VERSION_ROTATED rather than as a signature that happens to fail.
        key_id: keyRecord.key_id,
        key_version: keyRecord.key_version,
        signature_profile: keyRecord.signature_profile,
        trust,
        revoked: !credentialIntact,
        revocation_disposition: (device.revocationDisposition as DeviceRegistryFacts['revocation_disposition']) ?? null,
        actor: actor.facts,
      },
    };
  }

  /**
   * The two frozen evaluators, in the D25-02 order, judging the same inputs in
   * preflight and again under lock.
   */
  private judge(input: {
    /** C17-01: five named facts, never one boolean standing in for two. */
    principals: DeviceGatewayPrincipalFacts;
    context: AuthenticatedDeviceContext;
    proof: DeviceRequestProof;
    now: Date;
    expectedPayloadDigest: string;
    registered: DeviceRegistryFacts;
    verified: boolean;
    replayKey: string;
    fingerprint: string;
    stored: { statement_fingerprint: string; stored_outcome_ref: string } | null;
  }):
    | { kind: 'ADMITTED'; effect: 'PROCEED' }
    | { kind: 'ADMITTED'; effect: 'CONVERGE'; storedOutcomeRef: string }
    | { kind: 'REFUSED'; refusal: DeviceGatewayRefusal; contractRefusal: string | null } {
    const consumption = classifyDeviceNonceConsumption({
      replay_key: input.replayKey,
      statement_fingerprint: input.fingerprint,
      stored: input.stored,
    });

    const decision = evaluateDeviceRequestProof({
      context: input.context,
      proof: input.proof,
      now: input.now.toISOString(),
      expectedPayloadDigest: input.expectedPayloadDigest,
      registered: input.registered,
      verified: input.verified,
      // D25-10: all three operations map to the frozen FIELD_OPERATION. No new
      // `DeviceRequestPurpose` value is added merely because there are three
      // route types; their semantic distinction lives in the payload digest,
      // which is what makes a proof for one of them unusable for another.
      expectedPurpose: 'FIELD_OPERATION',
      consumption,
    });
    if (!decision.admitted) {
      const conflict = decision.refusal === 'NONCE_REUSED_WITH_CHANGED_SEMANTICS';
      return { kind: 'REFUSED', refusal: conflict ? 'REPLAY_CONFLICT' : 'PROOF_REFUSED', contractRefusal: decision.refusal };
    }

    // C17-01: AUTHORISATION NOW, as its own question. The frozen evaluator above
    // also asks it, through `registered.actor`; asking it here as well is not
    // duplication but separation - it is the one fact `actorCurrentlyAuthorised`
    // names, and it is judged from the live re-read rather than from the session.
    if (!input.principals.actorCurrentlyAuthorised) {
      return { kind: 'REFUSED', refusal: 'ACTOR_NOT_USABLE', contractRefusal: null };
    }

    const admission = evaluateDeviceOperationPrincipals({
      // C17-01: THE SESSION, AND ONLY THE SESSION. This used to be fed from "the
      // actor row resolved", which answers a different question entirely and
      // answered it `true` for a caller with no session at all. A stolen context
      // plus a device key was therefore a complete authority; it no longer is,
      // because nothing in this module can produce this value except the
      // authenticated principal on the request.
      userAuthenticated: input.principals.sessionAuthenticated,
      // The hardware half: possession proven AND the credential intact. Neither
      // alone is sufficient and neither manufactures the other.
      deviceAuthenticated: input.principals.deviceAuthenticated,
      deviceTrust: input.principals.deviceCurrentlyTrusted,
      requiredTrust: DEVICE_PURPOSE_PERMITTED_TRUST.FIELD_OPERATION,
      // BOTH halves - the human works this site AND the device is deployed at it.
      siteAuthorityGranted: input.principals.siteAuthorityGranted,
      policySatisfied: true,
    });
    if (!admission.admitted) {
      return { kind: 'REFUSED', refusal: 'PRINCIPALS_REFUSED', contractRefusal: admission.refusal };
    }

    if (decision.effect === 'CONVERGE_ON_STORED_OUTCOME') {
      return { kind: 'ADMITTED', effect: 'CONVERGE', storedOutcomeRef: decision.stored_outcome_ref };
    }
    return { kind: 'ADMITTED', effect: 'PROCEED' };
  }
}

/** The audit shape for a refusal taken before anything was resolved. */
function blank(input: { targetId: string | null }): {
  contextId: string | null;
  deviceId: string | null;
  actorUserId: string | null;
  siteId: string | null;
  targetId: string | null;
  payloadDigest: string | null;
  effectiveTrust: string | null;
} {
  return {
    contextId: null,
    deviceId: null,
    actorUserId: null,
    siteId: null,
    targetId: input.targetId,
    payloadDigest: null,
    effectiveTrust: null,
  };
}
