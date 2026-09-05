import { Inject, Injectable } from '@nestjs/common';
import {
  DeviceOfflineOperationEnvelopeSchema,
  bindClaimedSignatureProfile,
  canonicalDeviceOfflineOperationStatement,
  deviceCanonicalDigest,
  deviceOfflineOperationFingerprint,
  deviceOfflineOperationReplayKey,
  deviceOfflineOperationStatementInput,
  evaluateOfflineOperationAdmissibility,
  type AuthenticatedDeviceContext,
  type DeviceNonceConsumption,
  type DeviceOfflineOperationEnvelope,
} from '@sentinel/contracts';
import type { Principal } from '../../common/security/principal';
import { FieldOfflineReplayService } from '../field-offline/field-offline.service';
import type { OfflineSubmissionOutcome } from '../field-offline/field-offline.types';
import { DeviceRegistryService } from '../shield/device-registry.service';
import { ShieldRepository } from '../shield/shield.repository';
import { DeviceReplayService } from '../shield/device-replay.service';
import { P256KeyImporter } from '../shield/p256-key.importer';
import { DeviceGatewayRepository } from './device-gateway.repository';
import { DeviceGatewayService } from './device-gateway.service';
import { DevicePolicyLeaseService, WP29A_ADMITTED_OFFLINE_OPERATION_KINDS } from './device-policy-lease.service';

/** The ceremony label WP-29A spends the QUEUED statement's one-shot identity under. */
export const DEVICE_OFFLINE_OPERATION_CEREMONY = 'OFFLINE_OPERATION';

export type DeviceOfflineIngressResult =
  | { readonly outcome: 'ACCEPTED'; readonly submission: OfflineSubmissionOutcome }
  | { readonly outcome: 'REFUSED' }
  | { readonly outcome: 'CONFLICT' };

/**
 * WP-29A / D29A-26 §22 — WHERE A QUEUED OPERATION ENTERS CENTRAL SENTINEL.
 *
 * The whole path, and the reason each step is where it is:
 *
 *   DeviceOfflineOperationEnvelope
 *      -> the AUTHENTICATED WP-25 gateway            (is this device on the line, now?)
 *      -> AuthenticatedDeviceContext
 *      -> resolve envelope.policy_lease_id           (what authority does it CLAIM?)
 *      -> the SERVER's DevicePolicyLease             (what authority did we ISSUE?)
 *      -> evaluateOfflineOperationAdmissibility      (may this statement take effect?)
 *      -> FieldOfflineReplayService                  (apply it exactly once)
 *
 * TWO SIGNATURES, TWO QUESTIONS, AND THEY ARE NOT THE SAME QUESTION.
 *
 * The fresh WP-25 request proof says the device holding the registered key is
 * connected right now. The queued envelope's own signature — made hours
 * earlier, possibly on a different shift — says THIS STATEMENT is the one that
 * device produced, unaltered, under the lease it names. Neither substitutes for
 * the other: a live device could otherwise submit a statement it never signed,
 * and a signed statement could otherwise arrive from anywhere.
 *
 * WHAT THIS SERVICE NEVER DOES
 * ----------------------------
 * It never re-derives the operation's identity from anything the request said.
 * The organisation, the device and the actor come from the context WP-25
 * committed; the site comes from the signed proof and has already been bound to
 * that context; the operation kind, the sequence and the lease id come from the
 * SIGNED envelope. Where the two could disagree, they are compared and the
 * disagreement is a refusal — never a preference for one source.
 *
 * It also never substitutes a lease. If the envelope names a lease that has
 * expired, been revoked, or never existed, the answer is LEASE_MISSING or
 * LEASE_NOT_IN_FORCE. Reaching for "the device's current lease" instead would
 * mean judging the operation under authority it never claimed, which is exactly
 * the backdating the signed `policy_lease_id` exists to prevent.
 */
@Injectable()
export class DeviceOfflineIngressService {
  constructor(
    @Inject(DeviceGatewayService) private readonly gateway: DeviceGatewayService,
    @Inject(DevicePolicyLeaseService) private readonly leases: DevicePolicyLeaseService,
    @Inject(DeviceGatewayRepository) private readonly repository: DeviceGatewayRepository,
    @Inject(DeviceRegistryService) private readonly registry: DeviceRegistryService,
    @Inject(ShieldRepository) private readonly shield: ShieldRepository,
    @Inject(DeviceReplayService) private readonly replay: DeviceReplayService,
    @Inject(P256KeyImporter) private readonly keys: P256KeyImporter,
    @Inject(FieldOfflineReplayService) private readonly offline: FieldOfflineReplayService,
  ) {}

  async submit(
    principal: Principal,
    request: { proof: unknown; body: unknown; traceId: string },
  ): Promise<DeviceOfflineIngressResult> {
    // The queued envelope is read from the body BEFORE authentication only to
    // learn which queue position this request is about, because the WP-25
    // canonical envelope binds a target id and this kind's target IS the queued
    // operation. It is an untrusted read, and every field of it is re-parsed
    // and re-bound below; nothing here is believed.
    const claimedTargetId = readClaimedOfflineOperationId(request.body);

    const authenticated = await this.gateway.authenticateQueueSubmission(principal, {
      proof: request.proof,
      body: request.body,
      targetId: claimedTargetId,
      traceId: request.traceId,
    });
    if (authenticated.outcome === 'CONFLICT') return { outcome: 'CONFLICT' };
    if (authenticated.outcome !== 'AUTHENTICATED') return { outcome: 'REFUSED' };

    const { context, envelope: gatewayEnvelope, siteId } = authenticated;

    // The gateway parsed and digested the submission; this is the same object
    // it covered with the payload digest the device signed in its fresh proof.
    const submission = gatewayEnvelope.semantic_payload as {
      envelope: DeviceOfflineOperationEnvelope;
      payload: Record<string, unknown>;
    };
    const parsedEnvelope = DeviceOfflineOperationEnvelopeSchema.safeParse(submission.envelope);
    if (!parsedEnvelope.success) return { outcome: 'REFUSED' };
    const offlineEnvelope = parsedEnvelope.data;

    // The outer target and the inner signed id must be the same queue position.
    // Without this, the canonical envelope the device proved freshly could
    // describe one operation while the statement it carried described another.
    if (gatewayEnvelope.target_id !== offlineEnvelope.offline_operation_id) return { outcome: 'REFUSED' };

    const bound = this.bindEnvelopeToContext(offlineEnvelope, context, siteId);
    if (!bound) return { outcome: 'REFUSED' };

    // WP-29A executes one kind. Anything else would reach
    // NO_TRUSTWORTHY_TIME_WITNESS in the evaluator below anyway — there is no
    // Edge to witness it — but refusing here names the real reason rather than
    // letting it surface as a witness complaint.
    if (!WP29A_ADMITTED_OFFLINE_OPERATION_KINDS.includes(offlineEnvelope.operation_kind)) return { outcome: 'REFUSED' };

    // -----------------------------------------------------------------------
    // The four inputs the frozen evaluator judges, each resolved from SERVER
    // state and none of them from the request.
    // -----------------------------------------------------------------------
    const registeredKey = await this.registry.resolveRegistryKeyRecord(context.organisation_id, context.key_id);
    if (registeredKey === null) return { outcome: 'REFUSED' };

    // The envelope must name the key the registry currently holds for this
    // device. A rotation between queueing and reconnecting is a real event, and
    // the evaluator's own REGISTRY_KEY_MISMATCH covers it; checking here means
    // the signature below is verified against the key the statement CLAIMS
    // rather than against whichever key happens to be current.
    if (offlineEnvelope.key_id !== registeredKey.key_id || offlineEnvelope.key_version !== registeredKey.key_version) {
      return { outcome: 'REFUSED' };
    }

    // The SERVER re-digests the payload it actually received. The digest inside
    // the envelope is a claim; this is the fact it is compared against, and the
    // evaluator refuses PAYLOAD_DIGEST_MISMATCH when they differ.
    const expectedPayloadDigest = deviceCanonicalDigest(submission.payload);

    const profileBinding = bindClaimedSignatureProfile(offlineEnvelope.claimed_signature_profile, registeredKey.signature_profile);
    if (!profileBinding.bound) return { outcome: 'REFUSED' };

    const statementInput = deviceOfflineOperationStatementInput(offlineEnvelope, profileBinding.profile);
    const signatureVerified = this.keys.verifySignature({
      registeredPublicKey: registeredKey.public_key,
      message: canonicalDeviceOfflineOperationStatement(statementInput),
      signature: offlineEnvelope.signature,
      serverResolvedProfile: registeredKey.signature_profile,
      claimedProfile: offlineEnvelope.claimed_signature_profile,
    });

    const lease = await this.leases.resolve(context.organisation_id, offlineEnvelope.policy_lease_id);

    /**
     * D23-08 — REVOCATION IS TWO FACTS, AND THEY DO NOT MOVE TOGETHER.
     *
     * `shield.prisma` says it in terms: `devices.revoked_at` and
     * `device_keys.revoked_at` are separate answers, asked independently,
     * because a device can be withdrawn without its key being touched and a key
     * can be withdrawn while the device stands. Passing only the key's instant
     * — which this did at first — would let a DEVICE-level withdrawal reach the
     * evaluator as `null`, and the evaluator would judge the queued operation
     * as though the credential were intact.
     *
     * In practice authentication has already refused a withdrawn device before
     * this line is reached, so this is defence in depth rather than the only
     * guard. It is still worth being exact: the two checks are independent
     * precisely so that neither is relied on to cover the other.
     *
     * The EARLIER instant wins, because the question the evaluator asks is
     * "was this credential withdrawn?", and the honest answer is when it FIRST
     * was.
     */
    const deviceRow = await this.shield.findDevice(context.organisation_id, context.device_id);
    const deviceRevokedAt = earliestInstant(deviceRow?.revokedAt?.toISOString() ?? null, registeredKey.revoked_at);

    const replayKey = deviceOfflineOperationReplayKey(offlineEnvelope);
    const fingerprint = deviceOfflineOperationFingerprint(statementInput);
    const peeked = await this.repository.readOnly((tx) => this.replay.peek(tx, { organisationId: context.organisation_id, replayKey }));
    const consumption = buildConsumptionFact(replayKey, fingerprint, peeked);

    const admissibility = evaluateOfflineOperationAdmissibility({
      envelope: offlineEnvelope,
      lease,
      // WP-29A HAS NO EDGE, AND SAYS SO. `NONE` is the honest answer, and it is
      // sufficient only because the one admitted kind is stale-tolerant. When
      // WP-29B builds Edge this becomes a real witness for the other kinds; it
      // must never become a fabricated one to make a kind pass.
      witness: { kind: 'NONE' },
      now: (await this.repository.now()).toISOString(),
      expectedPayloadDigest,
      deviceRevokedAt,
      signatureVerified,
      registeredKey,
      consumption,
    });
    if (!admissibility.admitted) {
      return admissibility.refusal === 'NONCE_REUSED_WITH_CHANGED_SEMANTICS' ? { outcome: 'CONFLICT' } : { outcome: 'REFUSED' };
    }

    // Spend the QUEUED statement's one-shot identity. It is separate from the
    // fresh proof's identity spent during authentication: one retires this
    // connection, the other retires this statement.
    //
    // The outcome a later exact retry converges on is the operation id, because
    // the durable receipt for that operation IS the outcome. Convergence does
    // not short-circuit the replay call below — the receipt is what answers,
    // and claiming an effect this layer never observed would be the C15-R1
    // defect in a new place.
    await this.repository.transaction(async (tx) => {
      await this.replay.consume(tx, {
        organisationId: context.organisation_id,
        ceremony: DEVICE_OFFLINE_OPERATION_CEREMONY,
        replayKey,
        statementFingerprint: fingerprint,
        candidateOutcomeRef: offlineEnvelope.offline_operation_id,
        traceId: request.traceId,
      });
    });

    // -----------------------------------------------------------------------
    // WP-20 owns everything from here: the cursor, the receipt, the recovery
    // lease, the downstream idempotency key and the single domain effect.
    // -----------------------------------------------------------------------
    const submissionOutcome = await this.offline.submit(
      principal,
      {
        organisationId: context.organisation_id,
        userId: context.actor_user_id,
        deviceId: context.device_id,
        authorisedSiteIds: context.authorised_site_ids,
      },
      {
        schema_version: 2,
        offline_operation_id: offlineEnvelope.offline_operation_id,
        organisation_id: offlineEnvelope.organisation_id,
        site_id: offlineEnvelope.site_id,
        device_id: offlineEnvelope.device_id,
        device_sequence: offlineEnvelope.device_sequence,
        idempotency_key: offlineEnvelope.idempotency_key,
        created_at: offlineEnvelope.created_at,
        trace_id: request.traceId,
        operation_kind: offlineEnvelope.operation_kind,
        payload: submission.payload,
      },
      // D29A-26 §16: the resolved lease, recorded on the receipt. `lease` is
      // non-null here — the evaluator refuses LEASE_MISSING otherwise — so the
      // envelope-backed path has no branch that writes a null provenance.
      { policyLeaseId: offlineEnvelope.policy_lease_id },
    );

    return { outcome: 'ACCEPTED', submission: submissionOutcome };
  }

  /**
   * The signed envelope's claimed identity, bound against the established one.
   *
   * Every comparison is an equality, and a mismatch on any of them is the same
   * single refusal. The envelope may CLAIM any tenant, device, actor or site it
   * likes; what it cannot do is claim one the WP-25 ceremony did not establish
   * for this exact connection.
   */
  private bindEnvelopeToContext(
    envelope: DeviceOfflineOperationEnvelope,
    context: AuthenticatedDeviceContext,
    proofSiteId: string,
  ): boolean {
    if (envelope.organisation_id !== context.organisation_id) return false;
    if (envelope.device_id !== context.device_id) return false;
    // C15-06: the actor half. On a CONTROLLED_SHARED device the operative who
    // queued the work and the operative on shift now may differ, and the lease
    // check refuses that separately — but a statement whose actor is not even
    // the one this context authenticated never gets that far.
    if (envelope.actor_user_id !== context.actor_user_id) return false;
    // The site must be the one the fresh proof was made for AND one the context
    // established. The second half is not redundant: the proof's site is signed
    // by the device, and a device must not be able to move its own queued work
    // to a site the ceremony never granted.
    if (envelope.site_id !== proofSiteId) return false;
    if (!context.authorised_site_ids.includes(envelope.site_id)) return false;
    return true;
  }
}

/**
 * The queued operation id, read from an UNVERIFIED body.
 *
 * `null` when the body is not the expected shape, which lets authentication
 * refuse it on the canonical-envelope parse rather than here — one refusal
 * boundary, not two. Nothing downstream trusts this value: it is compared
 * against the signed envelope's own id and a mismatch refuses.
 */
export function readClaimedOfflineOperationId(body: unknown): string | null {
  if (typeof body !== 'object' || body === null) return null;
  // `body.payload`, not `body` — the gateway's canonical envelope carries every
  // operation's semantic content under `payload`, and its outer schema is
  // `.strict()`, so a submission that put the envelope at the top level would
  // be refused ENVELOPE_MALFORMED before reaching here. An earlier revision of
  // this function read the top level and would have made every submission fail
  // the target-id binding below; it was caught by the client implementer
  // building against the same contract from the other side.
  const payload = (body as { payload?: unknown }).payload;
  if (typeof payload !== 'object' || payload === null) return null;
  const envelope = (payload as { envelope?: unknown }).envelope;
  if (typeof envelope !== 'object' || envelope === null) return null;
  const id = (envelope as { offline_operation_id?: unknown }).offline_operation_id;
  return typeof id === 'string' ? id : null;
}

/**
 * The store's report on this statement's one-shot identity, in the shape the
 * frozen evaluator requires.
 *
 * C15-R1 is why this is built explicitly rather than coalesced: an
 * EXACT_DUPLICATE that names no stored outcome must not become a `null` that
 * falls through to a second application. A duplicate whose stored reference is
 * missing or blank is reported as REUSED_WITH_CHANGED_SEMANTICS — the evaluator
 * then refuses, which is the correct fail-closed answer for a fact we cannot
 * act on, rather than the admission that reading it charitably would produce.
 */
export function buildConsumptionFact(
  replayKey: string,
  fingerprint: string,
  peeked: { statementFingerprint: string; storedOutcomeRef: string | null } | null,
): DeviceNonceConsumption {
  if (peeked === null) {
    return {
      source: 'SENTINEL_NONCE_STORE',
      outcome: 'FIRST_SEEN',
      replay_key: replayKey,
      statement_fingerprint: fingerprint,
      stored_outcome_ref: null,
    };
  }
  const sameBytes = peeked.statementFingerprint === fingerprint;
  const ref = peeked.storedOutcomeRef?.trim() ?? '';
  if (sameBytes && ref.length > 0) {
    return {
      source: 'SENTINEL_NONCE_STORE',
      outcome: 'EXACT_DUPLICATE',
      replay_key: replayKey,
      statement_fingerprint: peeked.statementFingerprint,
      stored_outcome_ref: ref,
    };
  }
  return {
    source: 'SENTINEL_NONCE_STORE',
    outcome: 'REUSED_WITH_CHANGED_SEMANTICS',
    replay_key: replayKey,
    statement_fingerprint: peeked.statementFingerprint,
    stored_outcome_ref: null,
  };
}

/**
 * The earlier of two optional instants, or `null` when neither is set.
 *
 * An unparseable instant is treated as PRESENT rather than absent: a
 * withdrawal timestamp we cannot read is still a withdrawal, and resolving it
 * to `null` would turn an unreadable revocation into no revocation at all.
 */
function earliestInstant(left: string | null, right: string | null): string | null {
  if (left === null) return right;
  if (right === null) return left;
  const leftMs = Date.parse(left);
  const rightMs = Date.parse(right);
  if (Number.isNaN(leftMs)) return left;
  if (Number.isNaN(rightMs)) return right;
  return leftMs <= rightMs ? left : right;
}
