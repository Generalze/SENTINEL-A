import { HttpException, Inject, Injectable } from '@nestjs/common';
import {
  classifyOfflineSequence,
  deriveOfflineDownstreamIdempotencyKey,
  FieldOfflineOperationV2Schema,
  fingerprintOfflineSemanticRequest,
  nextExpectedOfflineSequence,
  offlineReceiptAdvancesCursor,
  OfflineOperationResultSchema,
  OfflineReceiptStatusSchema,
  OfflineReplayConflictSchema,
  type AuthenticatedFieldDeviceContext,
  type FieldOfflineOperationV2,
  type OfflineAssignmentTransitionPayload,
  type OfflineIncidentMessageAcknowledgePayload,
  type OfflineIncidentMessageSendPayload,
  type OfflineOperationOutcome,
  type OfflineReplayConflictCode,
  type OfflineReplayNamespace,
} from '@sentinel/contracts';
import type { Principal } from '../../common/security/principal';
import { FieldMessagingService } from '../field-messaging/field-messaging.service';
import { FieldService } from '../field/field.service';
import type { FieldAssignmentAction } from '../field/field.types';
import { intersectSiteScope, type SiteScope } from '../identity/list-pagination';
import { RECEIPT_STATUS_APPLYING, REQUIRED_ACTION_FOR_KIND } from './field-offline.constants';
import { FieldOfflineRepository, type FinalizeInput, type Tx } from './field-offline.repository';
import type { OfflineAdmission, OfflineExecutionEffect, OfflineStoredReceipt, OfflineSubmissionOutcome } from './field-offline.types';

/**
 * WP-20 Checkpoint B — the offline replay executor (directive C10-02..C10-11).
 *
 * THE INVARIANT
 * -------------
 * A reconnect may DELAY an authorised operation. It must never duplicate it,
 * reorder it, weaken its authorization, backdate server authority, or let a
 * changed request hide behind an old idempotency identity.
 *
 * WHAT THIS SERVICE OWNS, AND WHAT IT REFUSES TO OWN
 * -------------------------------------------------
 * It owns ORDERING (the per-device cursor), IDENTITY BINDING (C10-02),
 * REQUEST IDENTITY (the canonical fingerprint) and EFFECTIVELY-ONCE delivery
 * (the receipt lifecycle). It owns NO domain rule (C10-10): the assignment
 * status machine, the message eligibility chain, the acknowledgement state
 * rule and every idempotency table behind them stay exactly where WP-16 and
 * WP-18 put them. Re-implementing one here would create a second, quietly
 * divergent copy of a security decision — which is how offline paths become
 * the soft door into a system.
 *
 * THERE IS NO HTTP SURFACE IN THIS MODULE, deliberately. `device_id` from a
 * JSON body is not authenticated device identity, so the trusted
 * `AuthenticatedFieldDeviceContext` arrives as an ARGUMENT from whatever
 * genuine device-authentication facility is built later. Publishing a route
 * before that facility exists would ship exactly the trust hole C10-02 names.
 */

/** Everything an executor needs, so no executor reaches back into submit's locals. */
interface OfflineExecutionContext {
  principal: Principal;
  siteScope: SiteScope;
  operation: FieldOfflineOperationV2;
  /** C10-09: the SERVER-derived key stored on the receipt, never the client's. */
  downstreamIdempotencyKey: string;
}

interface ResultInput {
  offlineOperationId: string;
  deviceSequence: number;
  operationKind: string;
  outcome: OfflineOperationOutcome;
  replayed: boolean;
  finalizedAt: Date;
  lastFinalizedSequence: number | null;
  resultRef: string | null;
  resultSnapshot: Record<string, unknown> | null;
  traceId: string;
}

/**
 * B10-01: what one attempt's finalization actually achieved.
 *
 *  - `finalized` this attempt owned the receipt and recorded the outcome;
 *  - `lost`      the claim fence did not match, so a NEWER attempt owns the
 *                receipt and this one mutated nothing;
 *  - `unknown`   the finalizing write itself faulted, so the outcome is
 *                genuinely unknown and the receipt now says so.
 */
type FinalizeAttempt =
  | { kind: 'finalized'; finalizedAt: Date; lastFinalizedSequence: number | null }
  | { kind: 'lost' }
  | { kind: 'unknown' };

/**
 * C10-08: which failures consume a queue position.
 *
 * A 4xx from a domain service is that service's DETERMINISTIC judgement — the
 * expected status did not hold, the incident is not in scope, the recipient is
 * not eligible. Replaying it would produce the same answer, so it finalizes as
 * REJECTED and the cursor advances (C10-07: otherwise a rejected entry wedges
 * the queue behind a position nothing can ever fill).
 *
 * Anything else — a 5xx, a driver fault, a timeout — means we genuinely do not
 * know whether the effect happened. That is UNKNOWN: the cursor holds, and the
 * retry converges through the stored downstream idempotency key.
 */
function deterministicRejectionStatus(error: unknown): number | null {
  if (!(error instanceof HttpException)) return null;
  const status = error.getStatus();
  return status >= 400 && status < 500 ? status : null;
}

/**
 * Narrows a stored JSONB value back to a snapshot object. A receipt written by
 * this module is always an object or SQL NULL; anything else is treated as
 * absent rather than parsed, so a malformed row degrades to "no snapshot"
 * instead of throwing on the reconnect path.
 */
function toSnapshot(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

@Injectable()
export class FieldOfflineReplayService {
  constructor(
    @Inject(FieldOfflineRepository) private readonly repository: FieldOfflineRepository,
    @Inject(FieldService) private readonly field: FieldService,
    @Inject(FieldMessagingService) private readonly messaging: FieldMessagingService,
  ) {}

  /**
   * Submits one queued offline operation.
   *
   * `deviceContext` is a TRUSTED ARGUMENT (C10-02) — it is never derived from
   * `rawOperation`. The envelope's own `organisation_id`, `site_id` and
   * `device_id` are treated as untrusted claims and bound against this context
   * and the live principal, fail-closed, BEFORE any receipt is read.
   */
  async submit(
    principal: Principal,
    deviceContext: AuthenticatedFieldDeviceContext,
    rawOperation: unknown,
    /**
     * WP-29A / D29A-26 §16 — THE AUTHORITY PROVENANCE, WHEN THERE IS ONE.
     *
     * Optional, and deliberately so. This surface predates policy leases and
     * its existing callers have none to give; defaulting to `null` keeps them
     * exactly as they were and keeps their receipts honestly marked as the
     * pre-WP-29A era they belong to (§21). What must never happen is the
     * reverse — an envelope-backed submission arriving here without one — and
     * that is prevented upstream, where the frozen evaluator refuses
     * LEASE_MISSING before a receipt is ever created.
     */
    provenance: { policyLeaseId: string | null } = { policyLeaseId: null },
  ): Promise<OfflineSubmissionOutcome> {
    // C10-01: an unadmitted kind, or a payload that does not match its kind
    // exactly, never reaches the executor. This runs before ANY persistence,
    // so an invalid envelope leaves no trace and consumes no queue position.
    const parsed = FieldOfflineOperationV2Schema.safeParse(rawOperation);
    if (!parsed.success) return { kind: 'invalid', issues: parsed.error.issues.map((issue) => issue.message) };
    const operation = parsed.data;

    const requiredAction = REQUIRED_ACTION_FOR_KIND[operation.operation_kind];

    const bindingFailure = this.bindDeviceContext(principal, deviceContext, operation, requiredAction);
    if (bindingFailure !== null) return this.conflict(bindingFailure, operation, null);

    // C10-02/R2: the replay namespace is built from AUTHENTICATED values. The
    // site is the envelope's, but only after it has been proven to lie inside
    // both the device context and the principal's action scope above — an
    // unvalidated claim never reaches a cursor, a receipt or a fingerprint.
    const namespace: OfflineReplayNamespace = {
      organisation_id: deviceContext.organisationId,
      site_id: operation.site_id,
      user_id: deviceContext.userId,
      device_id: deviceContext.deviceId,
    };

    // WP-17A: the receipt table carries no Site foreign key by design, so the
    // site's existence in this organisation is proven here, before the
    // transaction that creates a cursor row and a receipt. A nonexistent site
    // and another tenant's real site are indistinguishable in the response —
    // SITE_SCOPE_MISMATCH for both, so this path cannot be used to discover
    // that some id is a real site somewhere else in the platform.
    if (!(await this.repository.siteExistsInOrganisation(namespace.organisation_id, namespace.site_id))) {
      return this.conflict('SITE_SCOPE_MISMATCH', operation, null);
    }

    // C10-04: request identity binds the AUTHENTICATED namespace, so the same
    // envelope replayed under a different device or user is a different
    // request. C10-09: the downstream key is derived here and never taken
    // from the client, so two queue entries cannot steer unrelated domain
    // calls into one idempotency namespace.
    const requestFingerprint = fingerprintOfflineSemanticRequest(namespace, operation);
    const downstreamIdempotencyKey = deriveOfflineDownstreamIdempotencyKey(namespace, operation.offline_operation_id, operation.operation_kind);

    await this.repository.ensureCursor(namespace);

    // ---- step tx1: classify and make the fingerprint durable -----------------
    const admission = await this.repository.transaction((tx) =>
      this.admit(tx, namespace, operation, requestFingerprint, downstreamIdempotencyKey, provenance.policyLeaseId),
    );

    if (admission.kind === 'refuse') return this.conflict(admission.conflictCode, operation, admission.expectedSequence);
    if (admission.kind === 'replay') return this.replayStoredResult(operation, admission.receipt, admission.lastFinalizedSequence);

    const expectedSequence = nextExpectedOfflineSequence(admission.lastFinalizedSequence);

    // ---- step tx2: claim the receipt under the recovery lease ----------------
    // A live attempt already holds it, so this submission must not fire a
    // second effect. The holder will finalize; this device retries and gets
    // the stored outcome as a REPLAY.
    // B10-01: the claim yields a GENERATION (`attemptCount` after the
    // increment), and every receipt write this attempt makes is fenced on it.
    const claimGeneration = await this.repository.claimForProcessing(admission.receipt.id);
    if (claimGeneration === null) {
      return this.conflict('OPERATION_IN_PROGRESS', operation, expectedSequence);
    }

    return this.executeAndFinalize(principal, namespace, operation, admission.receipt, requiredAction, expectedSequence, claimGeneration);
  }

  // ---------------------------------------------------------------------------
  // C10-02 identity binding
  // ---------------------------------------------------------------------------

  /**
   * Fail-closed binding of the operation's CLAIMED namespace against the live
   * principal and the trusted device context.
   *
   * One code covers all four identity checks on purpose: the caller learns
   * that the binding failed and nothing about WHICH side disagreed, so this
   * path cannot be used to probe which organisation, user or device an
   * envelope belongs to.
   *
   * ORDER MATTERS. `hasAction` is checked BEFORE the scope intersection
   * because `intersectSiteScope` returns an empty scope when no role grants
   * the action at all — checking scope first would report a missing capability
   * as SITE_SCOPE_MISMATCH and hide the real reason from the operator reading
   * the audit trail.
   */
  private bindDeviceContext(
    principal: Principal,
    context: AuthenticatedFieldDeviceContext,
    operation: FieldOfflineOperationV2,
    requiredAction: string,
  ): OfflineReplayConflictCode | null {
    if (principal.organisation_id !== context.organisationId) return 'DEVICE_CONTEXT_MISMATCH';
    if (principal.user.id !== context.userId) return 'DEVICE_CONTEXT_MISMATCH';
    if (operation.organisation_id !== context.organisationId) return 'DEVICE_CONTEXT_MISMATCH';
    if (operation.device_id !== context.deviceId) return 'DEVICE_CONTEXT_MISMATCH';
    if (!context.authorisedSiteIds.includes(operation.site_id)) return 'SITE_SCOPE_MISMATCH';
    if (!principal.hasAction(requiredAction)) return 'OPERATION_NOT_ALLOWED';
    const scope = intersectSiteScope(principal, requiredAction);
    if (!scope.orgWide && !scope.siteIds.includes(operation.site_id)) return 'SITE_SCOPE_MISMATCH';
    return null;
  }

  // ---------------------------------------------------------------------------
  // C10-08 step tx1
  // ---------------------------------------------------------------------------

  /**
   * Everything here runs while holding the cursor row (C10-08), so two
   * reconnects from the same device cannot both classify their sequence as
   * FRESH, and the receipts the classification reads cannot change underneath
   * it before the insert commits.
   */
  private async admit(
    tx: Tx,
    namespace: OfflineReplayNamespace,
    operation: FieldOfflineOperationV2,
    requestFingerprint: string,
    downstreamIdempotencyKey: string,
    /** D29A-26 §16: written onto the receipt this step creates. See `submit`. */
    policyLeaseId: string | null,
  ): Promise<OfflineAdmission> {
    const cursor = await this.repository.lockCursor(tx, namespace);
    // `ensureCursor` committed a row and no write path deletes one, so this is
    // an integrity fault rather than a client-visible conflict. Fail loudly.
    if (cursor === null) throw new Error('offline device cursor is missing after ensure');

    const lastFinalizedSequence = cursor.lastFinalizedSequence;
    const expectedSequence = nextExpectedOfflineSequence(lastFinalizedSequence);

    // C10-03/R4: one offline_operation_id may occupy exactly one queue
    // position in its namespace. The composite unique index is the real
    // backstop; pre-checking it here returns the safe code instead of a raw
    // P2002, and guarantees zero mutation.
    const byOperationId = await this.repository.findReceiptByOperationId(tx, namespace, operation.offline_operation_id);
    if (byOperationId !== null && byOperationId.deviceSequence !== operation.device_sequence) {
      return { kind: 'refuse', conflictCode: 'OPERATION_ID_REUSED', expectedSequence };
    }

    const receipt = await this.repository.findReceiptBySequence(tx, namespace, operation.device_sequence);
    const classification = classifyOfflineSequence({
      last_finalized_sequence: lastFinalizedSequence,
      incoming_sequence: operation.device_sequence,
      receipt: receipt === null ? { exists: false } : { exists: true, same_semantic_request: receipt.requestFingerprint === requestFingerprint },
    });

    if (classification === 'SEQUENCE_GAP' || classification === 'SEQUENCE_REUSED' || classification === 'SEQUENCE_STALE') {
      return { kind: 'refuse', conflictCode: classification, expectedSequence };
    }

    if (classification === 'REPLAY') {
      // REPLAY implies a same-fingerprint receipt at a CONSUMED position, and
      // only a finalized receipt ever advances the cursor past its own
      // position — so an unfinalized one here means the invariant is broken.
      // Fail closed rather than fabricate an outcome for it.
      if (receipt === null || !this.isFinalized(receipt)) return { kind: 'refuse', conflictCode: 'UNKNOWN_OUTCOME', expectedSequence };
      return { kind: 'replay', receipt, lastFinalizedSequence };
    }

    // FRESH. The locked integration rule (R3): the cursor ALONE never
    // authorizes a second effect. A receipt already sitting at next_expected
    // is an earlier attempt that crashed in RECEIVED/APPLYING/UNKNOWN, and it
    // must be examined before this submission is treated as new.
    if (receipt !== null) {
      // A DIFFERENT request under the same queue position is reuse, even
      // though the position is unconsumed — a changed request may never hide
      // behind an identity an earlier one established (C10-04).
      if (receipt.requestFingerprint !== requestFingerprint) return { kind: 'refuse', conflictCode: 'SEQUENCE_REUSED', expectedSequence };
      // Finalized at next_expected cannot happen (finalization advances the
      // cursor in the same transaction), but if it ever did, replaying the
      // stored outcome is the safe answer — never a second effect.
      if (this.isFinalized(receipt)) return { kind: 'replay', receipt, lastFinalizedSequence };
      return { kind: 'proceed', receipt, lastFinalizedSequence };
    }

    // C10-08: the fingerprint and the derived downstream key become durable
    // BEFORE any downstream effect, so a crash after this commit is
    // recoverable rather than invisible.
    const created = await this.repository.createReceipt(tx, {
      namespace,
      offlineOperationId: operation.offline_operation_id,
      deviceSequence: operation.device_sequence,
      operationKind: operation.operation_kind,
      requestFingerprint,
      downstreamIdempotencyKey,
      // C10-06: telemetry. It is recorded, and it is never server authority.
      clientCreatedAt: new Date(operation.created_at),
      firstTraceId: operation.trace_id,
      // D29A-26 §16/§24: written ONCE, with the receipt, in the same statement
      // that makes the fingerprint durable. A retry converges on this receipt
      // rather than creating a second, so the lease recorded here is the lease
      // the operation is answered under for the rest of its life — no later
      // step can substitute a different one.
      policyLeaseId,
    });
    return { kind: 'proceed', receipt: created, lastFinalizedSequence };
  }

  /** C10-08: only APPLIED and deterministic REJECTED consume a queue position. */
  private isFinalized(receipt: OfflineStoredReceipt): boolean {
    const status = OfflineReceiptStatusSchema.safeParse(receipt.status);
    // An unrecognised status is not treated as finalized. That is the
    // fail-closed direction: the CAS claim admits only the three known
    // in-flight statuses, so such a row yields OPERATION_IN_PROGRESS and no
    // effect, rather than being replayed as an outcome nobody recorded.
    return status.success && offlineReceiptAdvancesCursor(status.data);
  }

  // ---------------------------------------------------------------------------
  // C10-08 step 3 (domain) and step tx3 (finalize)
  // ---------------------------------------------------------------------------

  private async executeAndFinalize(
    principal: Principal,
    namespace: OfflineReplayNamespace,
    operation: FieldOfflineOperationV2,
    receipt: OfflineStoredReceipt,
    requiredAction: string,
    expectedSequence: number | null,
    claimGeneration: number,
  ): Promise<OfflineSubmissionOutcome> {
    const finalizeIdentity = {
      namespace,
      receiptId: receipt.id,
      offlineOperationId: receipt.offlineOperationId,
      deviceSequence: receipt.deviceSequence,
      operationKind: receipt.operationKind,
      requestFingerprint: receipt.requestFingerprint,
      traceId: operation.trace_id,
      claimGeneration,
    };

    /**
     * B10-02: TRUTHFUL RECOVERY BEFORE RE-EXECUTION.
     *
     * Generation 1 is the first attempt — nothing can have committed under
     * this receipt yet, so it goes straight to the domain. Generation > 1
     * means an earlier attempt reached the domain and we do not know what
     * happened to it. Re-running the domain call cannot answer that honestly:
     * every one of these services re-evaluates CURRENT mutable eligibility
     * (the assignment's status and assignee, the sender's incident
     * eligibility, the recipient's DELIVERED precondition) BEFORE control ever
     * reaches its idempotency table. If that eligibility has drifted since the
     * first attempt, the re-run returns a deterministic 4xx and we would
     * finalize REJECTED for an effect that HAS ALREADY COMMITTED — false
     * history, written into a receipt the device replays as final.
     *
     * So we ask the OWNING domain for evidence first. On evidence we recover
     * APPLIED, build the snapshot from the EVIDENCE (never from current
     * mutable state, which may have moved on), and skip the domain call
     * entirely — there is nothing left to do and re-running it could only
     * misreport. C10-02 binding is untouched and still ran before the claim:
     * a caller who lost authorization never reaches this line, so the probe
     * discloses nothing to anyone not already entitled to the receipt.
     */
    const recovered = claimGeneration > 1 ? await this.probeCommittedEffect(principal, operation, receipt) : null;

    let effect: OfflineExecutionEffect;
    if (recovered !== null) {
      effect = recovered;
    } else {
      try {
        // NO transaction of ours wraps this call (C10-10). The domain service
        // owns its own transaction and its own idempotency table; nesting it
        // inside a replay transaction would put this module in charge of a
        // commit boundary it has no business deciding. The key it receives is
        // the STORED downstream key, so a retry after a crash converges on the
        // same domain identity instead of double-firing.
        effect = await this.execute({
          principal,
          siteScope: intersectSiteScope(principal, requiredAction),
          operation,
          downstreamIdempotencyKey: receipt.downstreamIdempotencyKey,
        });
      } catch (error) {
        const httpStatus = deterministicRejectionStatus(error);
        if (httpStatus === null) {
          // Infrastructure. The outcome is genuinely unknown, so the cursor
          // holds and the operation is retried into convergence (C10-08).
          const marked = await this.repository.markUnknown(finalizeIdentity);
          if (marked.kind === 'lost') return this.reportLostFence(operation, namespace, receipt.id);
          return this.conflict('UNKNOWN_OUTCOME', operation, expectedSequence);
        }
        // R6: the snapshot for a rejection is the status code and NOTHING else.
        // Domain error text may name an incident, a site or a recipient the
        // caller is not entitled to know exists, so none of it is stored, logged
        // or returned — a 404 must never become "exists but belongs to someone
        // else" (C10-11).
        //
        // B10-02: this REJECTED is now provably truthful. At generation > 1 the
        // probe above found NO evidence, and every evidence row is written in
        // the same transaction as the effect it records — so absence proves no
        // prior effect committed, and a deterministic 4xx here is the real,
        // first-and-only answer rather than a re-evaluation that might be
        // contradicting a commit we forgot about.
        const rejected = await this.finalize({
          ...finalizeIdentity,
          outcome: 'REJECTED',
          conflictCode: 'DOMAIN_REJECTED',
          resultRef: null,
          resultSnapshot: { http_status: httpStatus },
        });
        if (rejected.kind === 'lost') return this.reportLostFence(operation, namespace, receipt.id);
        if (rejected.kind === 'unknown') return this.conflict('UNKNOWN_OUTCOME', operation, expectedSequence);
        return this.result({
          offlineOperationId: receipt.offlineOperationId,
          deviceSequence: receipt.deviceSequence,
          operationKind: receipt.operationKind,
          outcome: 'REJECTED',
          replayed: false,
          finalizedAt: rejected.finalizedAt,
          lastFinalizedSequence: rejected.lastFinalizedSequence,
          resultRef: null,
          resultSnapshot: { http_status: httpStatus },
          traceId: operation.trace_id,
        });
      }
    }

    const applied = await this.finalize({
      ...finalizeIdentity,
      outcome: 'APPLIED',
      conflictCode: null,
      resultRef: effect.resultRef,
      resultSnapshot: effect.resultSnapshot,
    });
    if (applied.kind === 'lost') return this.reportLostFence(operation, namespace, receipt.id);
    if (applied.kind === 'unknown') return this.conflict('UNKNOWN_OUTCOME', operation, expectedSequence);
    return this.result({
      offlineOperationId: receipt.offlineOperationId,
      deviceSequence: receipt.deviceSequence,
      operationKind: receipt.operationKind,
      outcome: 'APPLIED',
      replayed: false,
      finalizedAt: applied.finalizedAt,
      lastFinalizedSequence: applied.lastFinalizedSequence,
      resultRef: effect.resultRef,
      resultSnapshot: effect.resultSnapshot,
      traceId: operation.trace_id,
    });
  }

  /**
   * C10-08: THE FINALIZATION ITSELF CAN FAIL, and when it does the downstream
   * effect may already have committed. That is precisely the "we genuinely do
   * not know" case the ruling names, so it is RECORDED as UNKNOWN and answered
   * with UNKNOWN_OUTCOME — the cursor holds and the retry converges through
   * the stored downstream idempotency key.
   *
   * Letting the fault escape instead would break two invariants at once: this
   * service's three-outcome contract (an exception may only escape BEFORE a
   * receipt exists), and crash recovery — a receipt abandoned in APPLYING is
   * only reclaimable after the 60s lease, so a reconnecting device would be
   * told OPERATION_IN_PROGRESS about an attempt no process is running. Marking
   * UNKNOWN leaves it immediately reclaimable, exactly as a domain-call fault
   * already does. Anything other than `finalized` means "no outcome was
   * recorded by THIS attempt"; the caller must not fabricate a result for it.
   *
   * B10-01: both writes carry the claim fence, so a third answer is possible —
   * `lost`, meaning a newer attempt owns the receipt and this one changed
   * nothing.
   */
  private async finalize(input: FinalizeInput): Promise<FinalizeAttempt> {
    try {
      const outcome = await this.repository.finalizeAndAdvance(input);
      return outcome.kind === 'lost' ? { kind: 'lost' } : outcome;
    } catch {
      const marked = await this.repository.markUnknown(input);
      return marked.kind === 'lost' ? { kind: 'lost' } : { kind: 'unknown' };
    }
  }

  /**
   * B10-01: this attempt's claim fence did not match, so a NEWER attempt owns
   * the receipt and this attempt wrote nothing.
   *
   * THE CORRUPTION THIS FENCES. Worker A claims the receipt at generation 1
   * and stalls — a GC pause, a hung socket, a paused container — until its
   * 60s lease expires. Worker B legally reclaims at generation 2, calls the
   * domain, and finalizes APPLIED. A then wakes up holding a verdict computed
   * from a world that no longer exists. Unfenced, A's `update by id` would
   * land on top of B's: a stale REJECTED overwriting a real APPLIED, or A's
   * `markUnknown` downgrading B's finalized receipt back to UNKNOWN and
   * re-opening a queue position whose effect has already committed — inviting
   * a third attempt to fire it a second time. The fence turns A's write into a
   * no-op, and this method makes A report B's truth instead of A's.
   *
   * So: re-read the receipt. If the newer attempt already finalized it, answer
   * with THAT stored outcome down the ordinary replay path (C10-11/R7 — built
   * purely from receipt columns, never refetched from domain state). If it has
   * not finalized yet, the newer attempt is still live and this caller is told
   * to come back: OPERATION_IN_PROGRESS while the receipt sits in APPLYING,
   * UNKNOWN_OUTCOME for anything else — a receipt that vanished, or one in a
   * state no outcome can honestly be read from.
   */
  private async reportLostFence(
    operation: FieldOfflineOperationV2,
    namespace: OfflineReplayNamespace,
    receiptId: string,
  ): Promise<OfflineSubmissionOutcome> {
    const current = await this.repository.getReceiptById(receiptId);
    // The cursor may have been advanced by the attempt that won, so the reply's
    // next_expected_sequence must come from the cursor as it stands NOW.
    const lastFinalizedSequence = await this.repository.readCursor(namespace);
    if (current !== null && this.isFinalized(current)) {
      return this.replayStoredResult(operation, current, lastFinalizedSequence);
    }
    const inProgress = current !== null && current.status === RECEIPT_STATUS_APPLYING;
    return this.conflict(inProgress ? 'OPERATION_IN_PROGRESS' : 'UNKNOWN_OUTCOME', operation, nextExpectedOfflineSequence(lastFinalizedSequence));
  }

  // ---------------------------------------------------------------------------
  // B10-02 domain-owned evidence probes
  // ---------------------------------------------------------------------------

  /**
   * Asks the OWNING domain whether this receipt's server-derived downstream
   * idempotency identity has already committed, and if so rebuilds the effect
   * from the EVIDENCE.
   *
   * Each probe is a pure lookup of the row the domain writes in the SAME
   * transaction as its effect. That atomicity is the whole argument: presence
   * proves the effect committed, absence proves it did not. Neither branch
   * consults mutable state — not the assignment's current status, not the
   * recipient's current delivery state, not current eligibility — because all
   * of those may have drifted since the attempt we are recovering.
   *
   * The switch mirrors `execute` exactly, kind for kind, so the allowlist
   * stays checked by the type system: a seventh operation kind fails to
   * compile here until someone decides what evidence proves IT committed.
   */
  private async probeCommittedEffect(
    principal: Principal,
    operation: FieldOfflineOperationV2,
    receipt: OfflineStoredReceipt,
  ): Promise<OfflineExecutionEffect | null> {
    const key = receipt.downstreamIdempotencyKey;
    switch (operation.operation_kind) {
      case 'FIELD_ASSIGNMENT_ACCEPT':
        return this.probeAssignmentTransition(principal, operation.payload, 'accept', key);
      case 'FIELD_ASSIGNMENT_DECLINE':
        return this.probeAssignmentTransition(principal, operation.payload, 'decline', key);
      case 'FIELD_ASSIGNMENT_START':
        return this.probeAssignmentTransition(principal, operation.payload, 'start', key);
      case 'FIELD_ASSIGNMENT_COMPLETE':
        return this.probeAssignmentTransition(principal, operation.payload, 'complete', key);
      case 'INCIDENT_FIELD_MESSAGE_SEND': {
        const evidence = await this.messaging.probeSendEvidence(principal, operation.payload.incident_id, key);
        if (evidence === null) return null;
        // R6 allowlist, rebuilt from the evidence row: identifiers and a
        // COUNT. Never the body, never the recipient list.
        return {
          resultRef: evidence.id,
          resultSnapshot: { incident_field_message_id: evidence.id, incident_id: evidence.incidentId, recipient_count: evidence.recipientCount },
        };
      }
      case 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE': {
        const committed = await this.messaging.probeAcknowledgeEvidence(principal, operation.payload.message_id, key);
        if (!committed) return null;
        return { resultRef: operation.payload.message_id, resultSnapshot: { incident_field_message_id: operation.payload.message_id } };
      }
      default: {
        const exhaustive: never = operation;
        return exhaustive;
      }
    }
  }

  /**
   * The status in the snapshot is the ORIGINAL intended post-transition status
   * — WP-16's own ACTION_TARGETS mapping, returned by the domain — and NOT the
   * assignment's current status. The evidence proves this action by this actor
   * under this key landed; what it landed was that target. Reading live status
   * instead would write a value the recovered attempt never produced into a
   * receipt the device replays as final.
   */
  private async probeAssignmentTransition(
    principal: Principal,
    payload: OfflineAssignmentTransitionPayload,
    action: FieldAssignmentAction,
    downstreamIdempotencyKey: string,
  ): Promise<OfflineExecutionEffect | null> {
    const evidence = await this.field.probeTransitionEvidence(principal, payload.assignment_id, action, downstreamIdempotencyKey);
    if (!evidence.committed) return null;
    return { resultRef: payload.assignment_id, resultSnapshot: { assignment_id: payload.assignment_id, status: evidence.status } };
  }

  // ---------------------------------------------------------------------------
  // C10-05 executor registry
  // ---------------------------------------------------------------------------

  /**
   * The six admitted kinds and nothing else. The discriminated switch is what
   * makes the registry exhaustive: a seventh kind added to the contract fails
   * to compile here until someone decides, explicitly, what it maps to — which
   * is the point of an allowlist that is checked by the type system rather
   * than by a lookup table that silently returns undefined.
   */
  private async execute(context: OfflineExecutionContext): Promise<OfflineExecutionEffect> {
    const operation = context.operation;
    switch (operation.operation_kind) {
      case 'FIELD_ASSIGNMENT_ACCEPT':
        return this.executeAssignmentTransition(context, operation.payload, 'accept');
      case 'FIELD_ASSIGNMENT_DECLINE':
        return this.executeAssignmentTransition(context, operation.payload, 'decline');
      case 'FIELD_ASSIGNMENT_START':
        return this.executeAssignmentTransition(context, operation.payload, 'start');
      case 'FIELD_ASSIGNMENT_COMPLETE':
        return this.executeAssignmentTransition(context, operation.payload, 'complete');
      case 'INCIDENT_FIELD_MESSAGE_SEND':
        return this.executeMessageSend(context, operation.payload);
      case 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE':
        return this.executeMessageAcknowledge(context, operation.payload);
      default: {
        const exhaustive: never = operation;
        return exhaustive;
      }
    }
  }

  /**
   * WP-16 owns the assignment status machine, the operative-only boundary and
   * the expected-status CAS (C10-10). The payload only names the intent; the
   * domain parses its own input, so a payload it refuses is a BadRequest —
   * a DETERMINISTIC rejection — and never a bypass.
   */
  private async executeAssignmentTransition(
    context: OfflineExecutionContext,
    payload: OfflineAssignmentTransitionPayload,
    action: FieldAssignmentAction,
  ): Promise<OfflineExecutionEffect> {
    const input = this.field.parseAssignmentAction({
      expected_status: payload.expected_status,
      idempotency_key: context.downstreamIdempotencyKey,
    });
    const view = await this.field.transitionAssignment(context.principal, context.siteScope, payload.assignment_id, action, input);
    // R6 allowlist: identifier and state. The assignment view also carries the
    // need-to-know summary, which must never enter a receipt.
    return { resultRef: view.id, resultSnapshot: { assignment_id: view.id, status: view.status } };
  }

  /**
   * WP-18 owns sender/recipient eligibility, incident scope resolution and the
   * server-derived site. `sent_at` is stamped by the domain at REPLAY time, not
   * from `created_at` — C10-06: client time is telemetry, so a queued message
   * cannot be backdated into an incident's history.
   */
  private async executeMessageSend(context: OfflineExecutionContext, payload: OfflineIncidentMessageSendPayload): Promise<OfflineExecutionEffect> {
    const input = this.messaging.parseSend({
      recipient_user_ids: payload.recipient_user_ids,
      body: payload.body ?? null,
      media_refs: payload.media_refs ?? [],
      retention_class: payload.retention_class,
      expires_at: payload.expires_at ?? null,
      idempotency_key: context.downstreamIdempotencyKey,
      trace_id: context.operation.trace_id,
    });
    const view = await this.messaging.send(context.principal, context.siteScope, payload.incident_id, input);
    // R6 allowlist: identifiers and a COUNT. Never the body, never the
    // recipient list — a receipt is read back on reconnect, so it must carry
    // nothing the §62.1 access guard would have to re-evaluate at read time.
    return {
      resultRef: view.id,
      resultSnapshot: { incident_field_message_id: view.id, incident_id: view.incident_id, recipient_count: view.recipients.length },
    };
  }

  /**
   * WP-18/C8-01 owns the acknowledgement rule: only a named recipient, and
   * only from DELIVERED. A replayed acknowledgement cannot manufacture an
   * earlier one — the domain stamps its own clock (C10-06).
   */
  private async executeMessageAcknowledge(
    context: OfflineExecutionContext,
    payload: OfflineIncidentMessageAcknowledgePayload,
  ): Promise<OfflineExecutionEffect> {
    const input = this.messaging.parseAcknowledge({ idempotency_key: context.downstreamIdempotencyKey });
    const view = await this.messaging.acknowledge(context.principal, context.siteScope, payload.message_id, input);
    return { resultRef: view.id, resultSnapshot: { incident_field_message_id: view.id } };
  }

  // ---------------------------------------------------------------------------
  // C10-11 safe outcomes
  // ---------------------------------------------------------------------------

  /**
   * C10-11/R7: a replay is rebuilt PURELY from receipt columns — outcome,
   * finalized_at, result_ref, result_snapshot, operation_kind and sequence.
   * Nothing is refetched from current domain state, so a message later
   * redacted, an assignment later cancelled, or an entitlement later revoked
   * cannot leak through the reconnect path, and a finalized REJECTED replays
   * as the same rejection rather than being re-evaluated.
   *
   * `trace_id` is the exception, and deliberately so: it is non-semantic
   * (C10-04), so the reply carries the CURRENT request's trace to correlate
   * with, not the first attempt's — the first one is retained on the receipt.
   */
  private replayStoredResult(
    operation: FieldOfflineOperationV2,
    receipt: OfflineStoredReceipt,
    lastFinalizedSequence: number | null,
  ): OfflineSubmissionOutcome {
    const outcome = receipt.outcome;
    if ((outcome !== 'APPLIED' && outcome !== 'REJECTED') || receipt.finalizedAt === null) {
      // A finalized status with no coherent outcome is an integrity fault. Fail
      // closed to UNKNOWN_OUTCOME rather than invent an answer for the device.
      return this.conflict('UNKNOWN_OUTCOME', operation, nextExpectedOfflineSequence(lastFinalizedSequence));
    }
    return this.result({
      offlineOperationId: receipt.offlineOperationId,
      deviceSequence: receipt.deviceSequence,
      operationKind: receipt.operationKind,
      outcome,
      replayed: true,
      finalizedAt: receipt.finalizedAt,
      lastFinalizedSequence,
      resultRef: receipt.resultRef,
      resultSnapshot: toSnapshot(receipt.resultSnapshot),
      traceId: operation.trace_id,
    });
  }

  /**
   * R8: nothing leaves this service without round-tripping its contract. The
   * parse is the last gate — a snapshot that grew past the bounded budget, or
   * an outcome the contract does not admit, becomes an internal fault here
   * rather than a malformed answer on a device's reconnect path.
   */
  private result(input: ResultInput): OfflineSubmissionOutcome {
    return {
      kind: 'result',
      result: OfflineOperationResultSchema.parse({
        schema_version: 2,
        offline_operation_id: input.offlineOperationId,
        device_sequence: input.deviceSequence,
        operation_kind: input.operationKind,
        outcome: input.outcome,
        replayed: input.replayed,
        // SERVER time. `created_at` has no field here by contract design.
        finalized_at: input.finalizedAt.toISOString(),
        next_expected_sequence: nextExpectedOfflineSequence(input.lastFinalizedSequence),
        result_ref: input.resultRef,
        result_snapshot: input.resultSnapshot,
        trace_id: input.traceId,
      }),
    };
  }

  /**
   * A refusal described without domain disclosure. Only the code, the caller's
   * OWN echoed identifiers, and the sequence arithmetic it needs to resynchronise.
   */
  private conflict(
    conflictCode: OfflineReplayConflictCode,
    operation: FieldOfflineOperationV2,
    expectedSequence: number | null,
  ): OfflineSubmissionOutcome {
    return {
      kind: 'conflict',
      conflict: OfflineReplayConflictSchema.parse({
        schema_version: 2,
        conflict_code: conflictCode,
        offline_operation_id: operation.offline_operation_id,
        device_sequence: operation.device_sequence,
        expected_sequence: expectedSequence,
        received_sequence: operation.device_sequence,
        trace_id: operation.trace_id,
      }),
    };
  }
}
