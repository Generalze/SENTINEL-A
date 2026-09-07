import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  DeviceEdgeReceiptSchema,
  canonicalDeviceEdgeReceiptStatement,
  deviceEdgeReceiptFingerprint,
  deviceEdgeReceiptStatementInput,
  deviceKeyStatePermitsNewOperations,
  type DeviceEdgeReceipt,
} from '@sentinel/contracts';
import { P256KeyImporter } from '../shield/p256-key.importer';
import { EDGE_TRUST_TRUSTED } from '../edge-registry/edge-registry.constants';
import { EdgeRegistryRepository } from '../edge-registry/edge-registry.repository';
import { EdgeRegistryService } from '../edge-registry/edge-registry.service';
import { isAuthenticatedEdgeContext, type AuthenticatedEdgeContext } from './edge-authentication.service';
import type { EdgeWitnessRefusal } from './edge-gateway.constants';

/**
 * ============================================================================
 * WP-29B EDGE-B — THE SECOND LAYER, AND THE RULE THAT KEEPS IT SECOND.
 *
 *     A VERIFIED `DeviceEdgeReceipt` IS NOT AN AUTHENTICATED CALLER.
 *     AN AUTHENTICATED CALLER IS NOT A VERIFIED RECEIPT.
 *
 * These are two independent facts and this service proves them independently.
 *
 * WHY THE RULE EXISTS AT ALL, IN THE CONCRETE
 * -------------------------------------------
 * An Edge signs BOTH statements with the SAME registered P-256 key. A receipt
 * is not a secret: it travels with the operation it witnesses, it is stored,
 * it is forwarded, and it appears in audit trails by design. So a receipt is
 * exactly the kind of artefact an attacker holds copies of.
 *
 * If a handler ever concluded "this receipt verifies against Edge 17's
 * registered key, therefore Edge 17 sent me this request", then possession of
 * ANY receipt Edge 17 ever produced would be a complete authentication for Edge
 * 17 — a bearer credential, minted by the thousand, distributed on purpose.
 * That is the C14-03 defect (a token whose possession is authority) arriving
 * through the Edge door, and it would collapse the whole D23-10 argument:
 * "Edge may witness, Edge may not authorize" is worth nothing if a witness
 * statement authenticates the witness.
 *
 * The contracts already keep the two statements in separate signature spaces
 * (`sentinel.edge.request.v1` vs `sentinel.device.edge-receipt.v1`), so one can
 * never verify as the other. This service is the SECOND, structural half: the
 * caller's identity is established by `EdgeAuthenticationService` and by
 * nothing else, and this code cannot even look at a receipt until it holds an
 * `AuthenticatedEdgeContext` — a value it has no way to manufacture.
 *
 * AND THE CONVERSE, WHICH IS EQUALLY LOAD-BEARING
 * -----------------------------------------------
 * An authenticated Edge does not get its receipts believed. Central
 * revalidates: it resolves the receipt's key from the registry UNDER THE
 * CALLER'S TENANT, re-derives the canonical statement, and verifies the
 * signature. An authenticated caller presenting a forged, altered or foreign
 * receipt is refused on the receipt, and its authentication survives untouched
 * — because "who are you" and "is this evidence real" are different questions
 * and neither answer may be borrowed for the other.
 * ============================================================================
 */

/**
 * WHAT A VERIFIED RECEIPT ACTUALLY ESTABLISHES — and read how little it is.
 *
 * "Edge E, which central currently trusts, states it saw operation F at time /
 * position Y." There is no verdict, no authorisation, no assertion about the
 * device, and no field in which one could be added: `DeviceEdgeReceiptSchema`
 * is `.strict()` and `DEVICE_EDGE_RECEIPT_FORBIDDEN_FIELDS` enumerates the
 * shapes that are refused.
 *
 * The tenant and the site are SERVER-OWNED, taken from the authenticated
 * caller's context, never from the receipt — the receipt has no such fields
 * and must never grow them.
 */
export interface AdmittedEdgeWitness {
  readonly organisationId: string;
  readonly siteId: string;
  readonly edgeId: string;
  readonly edgeKeyId: string;
  readonly edgeKeyVersion: number;
  readonly witnessedOperationFingerprint: string;
  readonly edgeTrustedTime: string | null;
  readonly edgeMonotonicPosition: number | null;
  /** The receipt statement's digest, for an audit row that must not carry the receipt. */
  readonly receiptFingerprint: string;
}

/** D25-13: one external answer, whatever went wrong. */
export type EdgeWitnessAdmission =
  | { readonly outcome: 'ADMITTED'; readonly witness: AdmittedEdgeWitness }
  | { readonly outcome: 'REFUSED' };

/** The internal, reason-carrying result. For the audit and for the tests. */
export type EdgeWitnessOutcome =
  | { readonly outcome: 'ADMITTED'; readonly witness: AdmittedEdgeWitness }
  | { readonly outcome: 'REFUSED'; readonly refusal: EdgeWitnessRefusal };

@Injectable()
export class EdgeWitnessService {
  private readonly logger = new Logger(EdgeWitnessService.name);

  constructor(
    @Inject(EdgeRegistryRepository) private readonly repository: EdgeRegistryRepository,
    @Inject(EdgeRegistryService) private readonly registry: EdgeRegistryService,
    @Inject(P256KeyImporter) private readonly keys: P256KeyImporter,
  ) {}

  /**
   * `caller` is `unknown` ON PURPOSE.
   *
   * Typing it `AuthenticatedEdgeContext | null` would make the compiler the
   * only guard, which is enough for code written in this repository and NOT
   * enough for a value that arrives through a queue payload, a deserialised
   * job, or a `JSON.parse`. Taking `unknown` and asking
   * `isAuthenticatedEdgeContext` means the brand is checked at RUNTIME too, so
   * a hand-built object carrying every field of a context — the exact thing a
   * future author would reach for in a hurry — is refused rather than believed.
   */
  async admitReceipt(caller: unknown, receipt: unknown, traceId: string): Promise<EdgeWitnessAdmission> {
    const judged = await this.judge(caller, receipt);
    await this.record(judged, caller, traceId);
    return judged.outcome === 'ADMITTED' ? { outcome: 'ADMITTED', witness: judged.witness } : { outcome: 'REFUSED' };
  }

  /** The internal, reason-carrying variant. For the audit, the tests, and nothing else. */
  async admitReceiptForAudit(caller: unknown, receipt: unknown, traceId: string): Promise<EdgeWitnessOutcome> {
    const judged = await this.judge(caller, receipt);
    await this.record(judged, caller, traceId);
    return judged;
  }

  private async judge(caller: unknown, receipt: unknown): Promise<EdgeWitnessOutcome> {
    const refused = (refusal: EdgeWitnessRefusal): EdgeWitnessOutcome => ({ outcome: 'REFUSED', refusal });

    // -- LAYER 1, AND IT IS FIRST BECAUSE IT IS FIRST ----------------------
    // The receipt is not parsed, not resolved and not verified until there is
    // an authenticated caller. A perfectly valid receipt presented by nobody
    // gets no further than this line — which is the property, stated as code
    // rather than as a comment. Reordering this below the parse would not
    // change the outcome today and WOULD be the first step towards a handler
    // that reads a receipt to decide who is calling.
    if (!isAuthenticatedEdgeContext(caller)) return refused('CALLER_NOT_AUTHENTICATED');
    const context: AuthenticatedEdgeContext = caller;

    // -- LAYER 2 -----------------------------------------------------------
    const parsed = DeviceEdgeReceiptSchema.safeParse(receipt);
    if (!parsed.success) return refused('RECEIPT_MALFORMED');
    const edgeReceipt: DeviceEdgeReceipt = parsed.data;

    // An Edge presents its OWN receipts. That is strictly narrower than the
    // frozen contract permits and can only cause more refusals, never fewer;
    // a relay topology in which one Edge forwards another's witness statements
    // would arrive as a visible diff against this line, with its own argument.
    if (edgeReceipt.edge_id !== context.edgeId) return refused('RECEIPT_EDGE_NOT_CALLER');

    // RESOLVED UNDER THE CALLER'S TENANT, which is server state. This is the
    // line that makes a foreign-tenant Edge and a nonexistent Edge
    // indistinguishable: `resolveEdgeRegistryKeyRecord` answers `null` for both
    // from one query, and there is no branch here in which they could diverge.
    const record = await this.registry.resolveEdgeRegistryKeyRecord(context.organisationId, edgeReceipt.edge_key_id);
    if (record === null) return refused('EDGE_KEY_NOT_RESOLVED');

    // The whole tuple, as `edge_registry_key_identity_tuple_key` ties it: a
    // record naming one Edge while carrying another's key cannot exist, and a
    // receipt naming a version the registry does not hold is refused rather
    // than verified against whatever version happened to resolve.
    if (record.edge_id !== edgeReceipt.edge_id || record.edge_key_version !== edgeReceipt.edge_key_version) {
      return refused('EDGE_IDENTITY_MISMATCH');
    }

    // CENTRAL REVALIDATES. The caller being authenticated a moment ago says
    // nothing about the standing of the key that signed this receipt now, and a
    // revocation between the two is exactly the case worth catching.
    if (!deviceKeyStatePermitsNewOperations(record.status) || record.revoked_at !== null) return refused('EDGE_KEY_NOT_USABLE');
    if (record.edge_trust !== EDGE_TRUST_TRUSTED) return refused('EDGE_NOT_TRUSTED');

    // C15-01: the receipt's claim is equality-bound to the registry's profile
    // before a verifier is reachable.
    if (edgeReceipt.claimed_edge_signature_profile !== record.signature_profile) return refused('SIGNATURE_PROFILE_CLAIM_MISMATCH');

    const statementInput = deviceEdgeReceiptStatementInput(edgeReceipt, record.signature_profile);
    const verified = this.keys.verifySignature({
      registeredPublicKey: record.public_key,
      message: canonicalDeviceEdgeReceiptStatement(statementInput),
      signature: edgeReceipt.edge_signature,
      serverResolvedProfile: record.signature_profile,
      claimedProfile: edgeReceipt.claimed_edge_signature_profile,
    });
    if (!verified) return refused('RECEIPT_SIGNATURE_NOT_VERIFIED');

    return {
      outcome: 'ADMITTED',
      witness: {
        // TENANT AND SITE FROM THE CONTEXT, NOT FROM THE RECEIPT. The receipt
        // has neither field and must never grow one.
        organisationId: context.organisationId,
        siteId: context.siteId,
        edgeId: record.edge_id,
        edgeKeyId: record.edge_key_id,
        edgeKeyVersion: record.edge_key_version,
        witnessedOperationFingerprint: edgeReceipt.witnessed_operation_fingerprint,
        edgeTrustedTime: edgeReceipt.edge_trusted_time,
        edgeMonotonicPosition: edgeReceipt.edge_monotonic_position,
        receiptFingerprint: deviceEdgeReceiptFingerprint(statementInput),
      },
    };
  }

  /**
   * The audit row, anchored on the CALLER's tenant — the only tenant this
   * decision ever established.
   *
   * A refusal with no authenticated caller has no tenant at all, so it is
   * logged and not filed, for the reason `EdgeAuthenticationService.record`
   * states at length. It is also the single most interesting line in an
   * incident: somebody presented a receipt without being anybody.
   */
  private async record(judged: EdgeWitnessOutcome, caller: unknown, traceId: string): Promise<void> {
    if (!isAuthenticatedEdgeContext(caller)) {
      this.logger.warn({ msg: 'edge receipt presented by an unauthenticated caller', traceId });
      return;
    }
    const common = {
      organisationId: caller.organisationId,
      edgeId: caller.edgeId,
      siteId: caller.siteId,
      actorUserId: null,
      occurredAt: new Date(),
      traceId,
    };
    if (judged.outcome === 'REFUSED') {
      await this.repository.appendSecurityEventOutsideTransaction({
        ...common,
        eventType: 'EDGE_RECEIPT_REFUSED',
        edgeKeyId: null,
        edgeKeyVersion: null,
        outcome: 'REFUSED',
        refusalCode: judged.refusal,
        payload: {},
      });
      return;
    }
    await this.repository.appendSecurityEventOutsideTransaction({
      ...common,
      eventType: 'EDGE_RECEIPT_ADMITTED',
      edgeKeyId: judged.witness.edgeKeyId,
      edgeKeyVersion: judged.witness.edgeKeyVersion,
      outcome: 'ADMITTED',
      refusalCode: null,
      payload: {
        // DIGESTS ONLY. Neither the receipt nor the operation it witnesses
        // reaches an audit payload (D23-14).
        receipt_fingerprint: judged.witness.receiptFingerprint,
        witnessed_operation_fingerprint: judged.witness.witnessedOperationFingerprint,
      },
    });
  }
}
