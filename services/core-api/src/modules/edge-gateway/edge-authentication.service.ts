import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  EdgeRequestProofSchema,
  canonicalEdgeRequestStatement,
  checkCanonicalEdgeRequestRoute,
  classifyEdgeRequestTrustedTimeClaim,
  deviceKeyStatePermitsNewOperations,
  edgeRequestBodyDigest,
  edgeRequestFingerprint,
  edgeRequestReplayKey,
  edgeRequestStatementInput,
  isConsistentDeviceNonceConsumption,
  DEVICE_TIME_NOT_AUTHORITATIVE,
  type DeviceSignatureProfile,
  type EdgeRequestMethod,
  type EdgeRequestProof,
  type EdgeRequestPurpose,
  type EdgeTrustedTimeClaimStanding,
} from '@sentinel/contracts';
import { DeviceReplayService } from '../shield/device-replay.service';
import { P256KeyImporter } from '../shield/p256-key.importer';
import {
  EDGE_STATE_ACTIVE,
  EDGE_TRUST_TRUSTED,
} from '../edge-registry/edge-registry.constants';
import { EdgeRegistryRepository } from '../edge-registry/edge-registry.repository';
import { EdgeRegistryService } from '../edge-registry/edge-registry.service';
import { CEREMONY_EDGE_REQUEST, type EdgeAuthenticationRefusal } from './edge-gateway.constants';

/**
 * ============================================================================
 * WP-29B EDGE-B — THE EDGE→CENTRAL AUTHENTICATION BOUNDARY.
 *
 * ```text
 * parse the proof, strictly            the frozen contract, nothing lenient
 * bind method + route to THIS request  a proof for one route is not a proof for another
 * resolve the registry key             by registry_key_id, tenant NOT supplied
 * derive organisation + site FROM IT   the tenant is an output, never an input
 * bind the claimed Edge identity       proof.edge_id must be the key's own Edge
 * assemble the frozen registry record  parsed, or treated as absent
 * enforce the single-site invariant    exactly one site, and it is the Edge's
 * judge key lifecycle, trust, state    three separate questions, asked separately
 * reconstruct the canonical statement  with the SERVER's profile
 * digest the REAL request bytes        and compare to what was signed
 * verify the signature                 WP-24's importer, the only recipe
 * judge the trusted-time claim         classified, never converted into a time
 * spend the one-shot request identity  Sentinel's ONE replay store, new label
 * mint AuthenticatedEdgeContext        and nothing else in the estate can
 * ```
 *
 * THE GOVERNING INVARIANT
 * -----------------------
 *     AN `AuthenticatedEdgeContext` EXISTS ONLY WHERE THIS SEQUENCE COMPLETED,
 *     AND EVERY FIELD IN IT IS SERVER STATE.
 *
 * `edgeId`, `organisationId`, `siteId`, `registryKeyId` and `signatureProfile`
 * are read from the registry row this resolver found. NOTHING in the request
 * contributes a value to the context — the proof's `edge_id` and
 * `registry_key_id` are equality-bound against the row and then discarded, and
 * `EdgeRequestProofSchema` has no tenant or site field for a future edit to
 * reach for. That is C17-02's rule ("the tenant is anchored on server state,
 * never on a claim") in the one setting where it is hardest to hold: there is
 * no session to anchor on, so the anchor has to come out of the credential's
 * own registry record.
 *
 * WHY THE KEY IS RESOLVED WITHOUT A TENANT
 * ----------------------------------------
 * The device gateway resolves its context under `principal.organisation_id`,
 * which is a fact the session guard established. An Edge has no session and no
 * human. If this resolver accepted an organisation alongside the proof, that
 * organisation would SELECT the row the whole decision is then taken against —
 * so a caller holding any valid Edge key could aim the lookup at another
 * tenant's namespace and probe it. `findRegistryKeyByKeyIdAcrossTenants` asks
 * for the key alone, requires exactly one answer, and hands back the tenant.
 *
 * NO CONTROLLER, DELIBERATELY — the round-3 argument, unchanged.
 * `EdgeRegistryModule` publishes no HTTP surface because an unauthenticated
 * route that accepted an Edge's key would be the trust-on-first-use door the
 * ceremony exists to close. This module publishes none either, for the adjacent
 * reason: the route belongs to whoever wires Edge transport, and a route
 * published before its handler enforces the two-layer rule below would be a
 * surface on which a verified receipt could be mistaken for an authenticated
 * caller. The seam is an exported service, and the integration suite drives it.
 *
 * WHAT THIS SERVICE NEVER DOES
 * ----------------------------
 * It never authorises anything. Authentication answers "which Edge is on the
 * line, right now, holding its registered key?" and stops. Whether that Edge
 * may do the thing it is asking for is a separate question with a separate
 * answer, and an `AuthenticatedEdgeContext` is not a permit.
 *
 * It never derives a time from the Edge. `classifyEdgeRequestTrustedTimeClaim`
 * returns a STANDING and there is no path from it to an instant central acts
 * on — see `edge-trusted-time.ts` for why that inversion is the one thing this
 * work package cannot tolerate.
 *
 * It never re-uses the Edge signing key for transport. This key verifies
 * statements; TLS identity is a different credential with a different lifetime
 * and a different compromise story, and nothing here reads or emits one.
 * ============================================================================
 */

/**
 * THE BRAND, AND WHY IT IS A MODULE-PRIVATE SYMBOL.
 *
 * `AuthenticatedEdgeContext` must be UNFORGEABLE — not "by convention", but in
 * the type system, because the two-layer rule below is only as strong as the
 * impossibility of manufacturing one of these beside it. A plain interface of
 * five strings is structurally satisfied by any object literal with the right
 * field names, so `{ edgeId, organisationId, siteId, registryKeyId,
 * signatureProfile }` written anywhere in the service would BE an authenticated
 * context as far as TypeScript is concerned.
 *
 * This symbol is `const`, so its type is `unique symbol`; it is used as a
 * computed key on the interface; and it is NOT exported. A module that cannot
 * NAME the key cannot write an object that has it, so `AuthenticatedEdgeContext`
 * can be passed, stored and read everywhere, and CONSTRUCTED only in this file.
 * The one `as` cast that mints it is `mintAuthenticatedEdgeContext` below,
 * which is itself not exported.
 *
 * It is a real runtime symbol rather than a `declare`d phantom, so the guard
 * beneath it can also answer the question at runtime — a caller that reaches
 * this boundary through `unknown` (a queue payload, a deserialised job) gets
 * the same answer the compiler would have given.
 */
const AUTHENTICATED_EDGE_CONTEXT_BRAND: unique symbol = Symbol('sentinel.edge.authenticated-context.v1');

/**
 * WHAT CENTRAL KNOWS ABOUT THE EDGE ON THE OTHER END OF THIS REQUEST.
 *
 * Every field is SERVER-OWNED. `siteId` is the single site the Edge row is
 * deployed at, not a list and not a claim; there is no `authorisedSiteIds`
 * here because a single-site Edge is a locked invariant and a plural field is
 * how a locked invariant quietly stops being one.
 *
 * `trustedTime` is a STANDING, not a time. It is on the context so that a
 * caller which needs live trusted time asks for it explicitly and gets an
 * honest `NONE`/`STALE` when there is none, instead of a nullable instant it
 * would eventually forget to null-check.
 */
export interface AuthenticatedEdgeContext {
  readonly [AUTHENTICATED_EDGE_CONTEXT_BRAND]: true;
  readonly edgeId: string;
  readonly organisationId: string;
  readonly siteId: string;
  readonly registryKeyId: string;
  readonly signatureProfile: DeviceSignatureProfile;
  /** The purpose the Edge SIGNED for. Allowlisted at the parse boundary. */
  readonly purpose: EdgeRequestPurpose;
  /** The verb and path this context was established for, as signed and as served. */
  readonly method: EdgeRequestMethod;
  readonly route: string;
  /** Classified, never converted. `NONE` and `STALE` both mean "central has no trusted time here". */
  readonly trustedTime: EdgeTrustedTimeClaimStanding;
  /** The canonical statement digest, for the audit row that must not carry the statement. */
  readonly statementFingerprint: string;
}

/**
 * The ONLY constructor. Not exported, and unreachable from any other module
 * because the brand key cannot be named outside this file.
 */
function mintAuthenticatedEdgeContext(fields: Omit<AuthenticatedEdgeContext, typeof AUTHENTICATED_EDGE_CONTEXT_BRAND>): AuthenticatedEdgeContext {
  return { [AUTHENTICATED_EDGE_CONTEXT_BRAND]: true, ...fields };
}

/**
 * The runtime half of the brand, for a boundary that receives `unknown`.
 *
 * It checks the symbol, not the shape. A hand-built object with all seven
 * fields is refused, which is the whole point: the question is never "does this
 * look authenticated?" but "did `EdgeAuthenticationService` produce it?".
 */
export function isAuthenticatedEdgeContext(value: unknown): value is AuthenticatedEdgeContext {
  return typeof value === 'object' && value !== null && (value as Record<symbol, unknown>)[AUTHENTICATED_EDGE_CONTEXT_BRAND] === true;
}

/**
 * What the transport hands in.
 *
 * `body` is BYTES, and the type says so. A parsed object here would mean the
 * server digests its own parser's output rather than what arrived, and a
 * parser that drops a duplicate key or reorders anything makes the digest agree
 * with a body the Edge never sent.
 */
export interface EdgeRequestAuthenticationInput {
  readonly proof: unknown;
  /** The verb actually being served. Compared to the signed one, never taken from it. */
  readonly method: string;
  /** The path actually being served, with no query string. Compared, never taken. */
  readonly route: string;
  /** The exact request bytes. Empty for a bodyless request. */
  readonly body: Uint8Array | string;
  readonly traceId: string;
}

/**
 * ONE EXTERNAL ANSWER FOR EVERY REFUSAL (D25-13).
 *
 * There is deliberately no `refusal` field on the refused arm and no optional
 * `reason`. A shape that COULD carry the precise reason outward is a shape
 * somebody eventually logs at a transport boundary; the reason travels to the
 * internal audit and to this module's tests through
 * `EdgeAuthenticationOutcome`, which never leaves the service layer.
 */
export type EdgeRequestAuthentication =
  | { readonly outcome: 'AUTHENTICATED'; readonly context: AuthenticatedEdgeContext }
  | { readonly outcome: 'REFUSED' };

/**
 * The INTERNAL result, reason included. Exported for the audit and for the
 * tests that must prove which rule fired; a transport must call `authenticate`
 * and never this.
 */
export type EdgeAuthenticationOutcome =
  | { readonly outcome: 'AUTHENTICATED'; readonly context: AuthenticatedEdgeContext }
  | {
      readonly outcome: 'REFUSED';
      readonly refusal: EdgeAuthenticationRefusal;
      /** Present only once the registry established one. Never taken from the request. */
      readonly organisationId: string | null;
      readonly edgeId: string | null;
    };

@Injectable()
export class EdgeAuthenticationService {
  private readonly logger = new Logger(EdgeAuthenticationService.name);

  constructor(
    @Inject(EdgeRegistryRepository) private readonly repository: EdgeRegistryRepository,
    @Inject(EdgeRegistryService) private readonly registry: EdgeRegistryService,
    @Inject(DeviceReplayService) private readonly replay: DeviceReplayService,
    @Inject(P256KeyImporter) private readonly keys: P256KeyImporter,
  ) {}

  /**
   * THE TRANSPORT'S ENTRY POINT. One answer, whatever went wrong.
   *
   * A foreign-tenant Edge, an Edge that never existed, a revoked Edge and a
   * forged signature are indistinguishable from here — same shape, same
   * absence of detail, and the internal reason is filed where only an operator
   * can read it.
   */
  async authenticate(input: EdgeRequestAuthenticationInput): Promise<EdgeRequestAuthentication> {
    const judged = await this.judge(input);
    await this.record(judged, input);
    return judged.outcome === 'AUTHENTICATED' ? { outcome: 'AUTHENTICATED', context: judged.context } : { outcome: 'REFUSED' };
  }

  /**
   * The sequence itself. Returns the PRECISE reason, and every early return is
   * a refusal that has established nothing and committed nothing.
   */
  private async judge(input: EdgeRequestAuthenticationInput): Promise<EdgeAuthenticationOutcome> {
    const refused = (refusal: EdgeAuthenticationRefusal, organisationId: string | null = null, edgeId: string | null = null): EdgeAuthenticationOutcome => ({
      outcome: 'REFUSED',
      refusal,
      organisationId,
      edgeId,
    });

    // -- 1. THE PARSE IS THE BOUNDARY -------------------------------------
    // A malformed proof never reaches a lookup, so a caller cannot use the
    // shape of a failure to learn anything about the registry.
    const parsedProof = EdgeRequestProofSchema.safeParse(input.proof);
    if (!parsedProof.success) return refused('PROOF_MALFORMED');
    const proof: EdgeRequestProof = parsedProof.data;

    // -- 2. BIND THE PROOF TO THIS REQUEST --------------------------------
    // The route the router is serving must be the route the Edge signed, in
    // the ONE canonical spelling, compared as bytes. Without this the proof
    // binds a string nobody checks, and a proof minted for a heartbeat is a
    // proof for a key rotation.
    if (!checkCanonicalEdgeRequestRoute(input.route).ok) return refused('ROUTE_NOT_CANONICAL');
    if (input.method !== proof.method || input.route !== (proof.route as string)) return refused('REQUEST_BINDING_MISMATCH');

    // -- 3. RESOLVE THE KEY, WITHOUT BEING TOLD A TENANT ------------------
    // ONE query, ONE code for every way it can fail. See the header.
    const keyRow = await this.repository.findRegistryKeyByKeyIdAcrossTenants(proof.registry_key_id);
    if (keyRow === null) return refused('EDGE_KEY_NOT_RESOLVED');

    // -- 4. THE TENANT AND THE SITE ARE OUTPUTS OF THAT LOOKUP ------------
    const organisationId = keyRow.organisationId;
    const edgeRow = await this.repository.findEdge(organisationId, keyRow.edgeId);
    // An orphaned key is reported as an unresolved key, not as a different
    // failure: telling them apart would say "that key exists but its Edge is
    // gone", which is a fact about the estate.
    if (edgeRow === null) return refused('EDGE_KEY_NOT_RESOLVED');

    // -- 5. THE CLAIMED EDGE MUST BE THIS KEY'S EDGE ----------------------
    // The proof binds `edge_id` so that a mismatch is a cryptographic
    // contradiction rather than a lookup somebody could skip; this is where the
    // contradiction is turned into a refusal.
    if (proof.edge_id !== keyRow.edgeId) return refused('EDGE_IDENTITY_MISMATCH', organisationId, keyRow.edgeId);

    // -- 6. THE FROZEN RECORD, PARSED --------------------------------------
    // A record the contract would refuse is not weak evidence, it is no
    // evidence. This is also where the thumbprint is re-derived from the key
    // and a REVOKED row without a withdrawal instant is refused, by the
    // contract, not by this service.
    const record = await this.registry.resolveEdgeRegistryKeyRecord(organisationId, proof.registry_key_id);
    if (record === null) return refused('EDGE_RECORD_NOT_REPRESENTABLE', organisationId, keyRow.edgeId);

    // -- 7. SINGLE-SITE IS A LOCKED INVARIANT ------------------------------
    // Asked against the Edge ROW as well as the record, because the two are
    // assembled by different code and the invariant is only worth anything if
    // it survives them disagreeing. A multi-site Edge is refused here rather
    // than quietly witnessing for a site it has never seen.
    if (record.authorised_site_ids.length !== 1 || record.authorised_site_ids[0] !== edgeRow.siteId) {
      return refused('EDGE_SITE_BINDING_INVALID', organisationId, keyRow.edgeId);
    }

    // -- 8. THREE SEPARATE QUESTIONS, ASKED SEPARATELY ---------------------
    // C15-02's split, and C15-R4-final's: the KEY's lifecycle, the PRINCIPAL's
    // trust and the ENROLMENT state do not move atomically and do not mean the
    // same thing. A rotated key on a trusted Edge, a valid key on a suspended
    // Edge and a live credential on a withdrawn Edge are three different
    // incidents, and collapsing them would make two of them invisible.
    if (!deviceKeyStatePermitsNewOperations(record.status) || record.revoked_at !== null) {
      return refused('EDGE_KEY_NOT_USABLE', organisationId, keyRow.edgeId);
    }
    if (record.edge_trust !== EDGE_TRUST_TRUSTED) return refused('EDGE_NOT_TRUSTED', organisationId, keyRow.edgeId);
    if (edgeRow.enrolmentState !== EDGE_STATE_ACTIVE) return refused('EDGE_NOT_ACTIVE', organisationId, keyRow.edgeId);

    // -- 9. THE BODY DIGEST, OVER THE REAL BYTES ---------------------------
    // Checked BEFORE the signature so a mismatched body cannot be distinguished
    // from a bad signature by timing at the crypto call, and so a request whose
    // body was swapped in transit dies without touching a key.
    if (edgeRequestBodyDigest(input.body) !== proof.body_digest) {
      return refused('BODY_DIGEST_MISMATCH', organisationId, keyRow.edgeId);
    }

    // -- 10. RECONSTRUCT, THEN VERIFY --------------------------------------
    // The statement is built from the SERVER's resolved profile; the type
    // forbids passing the proof's claim. `verifySignature` binds the claim to
    // the resolved profile before it will touch a key, decodes the signature
    // canonically (high-S dies here), and imports the point through OpenSSL.
    // There is no second verification recipe in this codebase.
    const statement = canonicalEdgeRequestStatement(edgeRequestStatementInput(proof, record.signature_profile));
    if (proof.claimed_signature_profile !== record.signature_profile) {
      return refused('SIGNATURE_PROFILE_CLAIM_MISMATCH', organisationId, keyRow.edgeId);
    }
    const verified = this.keys.verifySignature({
      registeredPublicKey: record.public_key,
      message: statement,
      signature: proof.signature,
      serverResolvedProfile: record.signature_profile,
      claimedProfile: proof.claimed_signature_profile,
    });
    if (!verified) return refused('POSSESSION_NOT_PROVEN', organisationId, keyRow.edgeId);

    // -- 11. THE TRUSTED-TIME CLAIM ----------------------------------------
    // Judged against the DATABASE's clock, which is the same clock the whole
    // Edge ceremony uses; nothing here reads the process wall clock.
    //
    // NONE and STALE are ADMISSIBLE. An Edge that has not anchored since boot,
    // or whose anchor has aged out, can still authenticate — it simply holds no
    // trusted time, and the standing on the context says so honestly rather
    // than a nullable instant a caller would forget to check.
    //
    // FUTURE_SKEWED IS NOT. An Edge that cannot make an honest claim may make
    // NO claim; it may not make a false one. A signed assertion about a fact
    // central can independently check, which central can see is wrong, is
    // evidence of a broken or hostile box and is refused rather than filed.
    const serverNow = await this.repository.dbNow();
    const trustedTime = classifyEdgeRequestTrustedTimeClaim(proof, serverNow.toISOString());
    if (trustedTime === DEVICE_TIME_NOT_AUTHORITATIVE) return refused('TIME_NOT_AUTHORITATIVE', organisationId, keyRow.edgeId);
    if (trustedTime === 'FUTURE_SKEWED') return refused('TRUSTED_TIME_CLAIM_NOT_PLAUSIBLE', organisationId, keyRow.edgeId);

    // -- 12. SPEND THE ONE-SHOT IDENTITY -----------------------------------
    //
    // WHY THIS BURNS RATHER THAN PEEKS, AND WHY THAT IS NOT THE WP-25 DEFECT.
    //
    // The device gateway PEEKS in preflight and consumes inside the one effect
    // transaction, because there a FIRST_SEEN consumption that outlived its
    // domain effect would remember an operation that never happened. There is
    // no domain effect here. The effect of this sequence IS the admission, and
    // the admission has no convergent outcome to hand back on a second
    // presentation — so an identity already spent is a REPLAY, full stop, and
    // EXACT_DUPLICATE is refused exactly as REUSED_WITH_CHANGED_SEMANTICS is.
    //
    // The cost is deliberate and documented on `request_id` in the contract:
    // it is per-ATTEMPT, not per-intent. A transport retry mints a new id, and
    // the idempotency of whatever the request goes on to do is carried by the
    // signed payload's own identifiers. Conflating the two would let a captured
    // frame re-enter a decision that had already been taken.
    //
    // It happens LAST, so an unverifiable request can never burn an identity —
    // an attacker without the key cannot spend slots.
    const replayKey = edgeRequestReplayKey({
      // SERVER-ESTABLISHED, and it could not have come from the proof: the
      // contract has no tenant field, and this function's type will not accept
      // a proof in its place.
      organisation_id: organisationId,
      edge_id: keyRow.edgeId,
      registry_key_id: proof.registry_key_id,
      request_id: proof.request_id,
    });
    const statementFingerprint = edgeRequestFingerprint(edgeRequestStatementInput(proof, record.signature_profile));
    const consumption = await this.repository.transaction((tx) =>
      this.replay.consume(tx, {
        organisationId,
        ceremony: CEREMONY_EDGE_REQUEST,
        replayKey,
        statementFingerprint,
        // The reference a later presentation would converge on IS this
        // statement. There is no other authoritative outcome to name, and a
        // row that named no outcome would be the C15-R1 shape the contract's
        // own consistency check refuses.
        candidateOutcomeRef: statementFingerprint,
        traceId: input.traceId,
      }),
    );
    // C15-R1: a fact this module cannot act on fails CLOSED rather than being
    // interpreted charitably.
    if (!isConsistentDeviceNonceConsumption(consumption.consumption)) {
      return refused('REPLAY_FACT_INCONSISTENT', organisationId, keyRow.edgeId);
    }
    if (consumption.consumption.outcome !== 'FIRST_SEEN') return refused('REQUEST_REPLAYED', organisationId, keyRow.edgeId);

    // -- 13. ONLY NOW ------------------------------------------------------
    return {
      outcome: 'AUTHENTICATED',
      context: mintAuthenticatedEdgeContext({
        edgeId: keyRow.edgeId,
        organisationId,
        // THE SITE COMES FROM THE EDGE ROW. The proof has no site field and the
        // record's list has already been proved to be exactly this one value.
        siteId: edgeRow.siteId,
        registryKeyId: record.edge_key_id,
        signatureProfile: record.signature_profile,
        purpose: proof.purpose,
        method: proof.method,
        route: proof.route as string,
        trustedTime,
        statementFingerprint,
      }),
    };
  }

  /**
   * The internal audit row, and the one case where there deliberately is none.
   *
   * A refusal taken BEFORE any registry row resolved — a malformed proof, an
   * unresolvable key, a non-canonical route — has no tenant. The device gateway
   * can anchor such an event on the session's organisation because a session
   * guard established one; there is no equivalent fact here, and filing under
   * an invented tenant would corrupt every tenant-scoped audit query in the
   * estate (C17-02's rule, from the other direction). Those refusals are
   * LOGGED, with the reason and the trace, and no row is written. That is the
   * honest answer, and it is stated here so nobody later "fixes" it by
   * inventing a placeholder organisation.
   */
  private async record(judged: EdgeAuthenticationOutcome, input: EdgeRequestAuthenticationInput): Promise<void> {
    const common = { siteId: null as string | null, actorUserId: null, edgeKeyVersion: null, occurredAt: new Date(), traceId: input.traceId };
    if (judged.outcome === 'REFUSED') {
      const organisationId = judged.organisationId;
      if (organisationId === null) {
        this.logger.warn({ msg: 'edge request refused before a tenant was established', refusal: judged.refusal, traceId: input.traceId });
        return;
      }
      await this.repository.appendSecurityEventOutsideTransaction({
        ...common,
        organisationId,
        edgeId: judged.edgeId,
        eventType: 'EDGE_REQUEST_REFUSED',
        edgeKeyId: null,
        outcome: 'REFUSED',
        // The PRECISE reason, on the inside only. The external answer carried
        // none of this (D25-13).
        refusalCode: judged.refusal,
        // An allowlist of non-secret facts. No proof, no statement, no
        // signature, no nonce, no key material (D23-14's rule for audit rows).
        payload: { method: input.method, route: input.route },
      });
      return;
    }
    await this.repository.appendSecurityEventOutsideTransaction({
      ...common,
      organisationId: judged.context.organisationId,
      edgeId: judged.context.edgeId,
      siteId: judged.context.siteId,
      eventType: 'EDGE_REQUEST_AUTHENTICATED',
      edgeKeyId: judged.context.registryKeyId,
      outcome: 'AUTHENTICATED',
      refusalCode: null,
      payload: {
        purpose: judged.context.purpose,
        method: judged.context.method,
        route: judged.context.route,
        trusted_time: judged.context.trustedTime,
        // The statement's DIGEST, never the statement.
        statement_fingerprint: judged.context.statementFingerprint,
      },
    });
  }

  /**
   * The internal, reason-carrying variant. For the audit, for this module's own
   * tests, and for nothing else.
   *
   * RETURNING THIS FROM A CONTROLLER WOULD BE THE D25-13 VIOLATION. A transport
   * calls `authenticate`, which answers `{ outcome: 'REFUSED' }` and nothing
   * more; the reasons this method carries are precisely the oracle the flat
   * refusal exists to withhold. It is separate rather than a flag on
   * `authenticate` so that the difference is a different call somebody has to
   * write on purpose.
   */
  async authenticateForAudit(input: EdgeRequestAuthenticationInput): Promise<EdgeAuthenticationOutcome> {
    const judged = await this.judge(input);
    await this.record(judged, input);
    return judged;
  }
}
