import { Injectable, Logger } from '@nestjs/common';
import { EdgeConfigService } from '../../config/config.service';
import { EdgeRequestSigner } from './edge-request.signer';

/**
 * M3B §14 — THE EDGE EVIDENCE FORWARDER.
 *
 * WHAT IT IS, AFTER THE CORRECTION
 * --------------------------------
 * The earlier design ended this chain by submitting the operation to central's
 * offline replay ingress. That was revoked, because it would have required an
 * Edge to satisfy `userAuthenticated`, and an authenticated Edge is not an
 * authenticated human (C17-01).
 *
 * So this forwards EVIDENCE and reads back STANDING:
 *
 *     queue.forwardableHeads()
 *       -> claimForForwarding()
 *       -> fresh Edge request_id, signed with the enrolled application key
 *       -> POST the evidence bundle
 *       -> map central's answer onto the queue's own vocabulary
 *
 * IT CANNOT CAUSE A DOMAIN EFFECT AND IT DOES NOT TRY. The Field operation is
 * applied when the device reconnects with a live human session and replays
 * through the WP-29A ingress. This channel exists so central holds the Edge's
 * provenance the moment the WAN returns, rather than waiting for a handset.
 *
 * WHY THE TERMINAL STATES ARE NOT REACHABLE FROM HERE
 * ---------------------------------------------------
 * `CENTRAL_APPLIED` and `FAILED_TERMINAL` require an AUTHORITATIVE replay
 * outcome. Evidence verification is not one. The mapping below can produce
 * `CENTRAL_RECEIVED` from an evidence success and nothing stronger, and the
 * queue's own transition rules refuse anything else -- which is the second
 * place the same rule is enforced, deliberately.
 */

/** What central answered, in the vocabulary M3B §6 fixes. */
type CentralStanding =
  | 'EVIDENCE_RECORDED'
  | 'AUTHORITATIVE_REPLAY_RECEIVED'
  | 'AUTHORITATIVE_REPLAY_APPLYING'
  | 'AUTHORITATIVE_REPLAY_APPLIED'
  | 'AUTHORITATIVE_REPLAY_REJECTED'
  | 'UNKNOWN';

/** What the forwarder decided to do with one entry. */
export type EdgeForwardOutcome =
  | { readonly kind: 'PROGRESS'; readonly progress: 'CENTRAL_RECEIVED' | 'CENTRAL_APPLYING' }
  | { readonly kind: 'SETTLE_APPLIED'; readonly centralRef: string }
  | { readonly kind: 'SETTLE_REFUSED'; readonly reason: string }
  | { readonly kind: 'UNKNOWN'; readonly reason: string }
  | { readonly kind: 'NOT_ATTEMPTED'; readonly reason: string };

/**
 * Central's standing, mapped onto what the Edge queue may record.
 *
 * A PURE FUNCTION, EXPORTED, AND TESTED ON ITS OWN. This is the single place
 * where "central said X" becomes "the queue believes Y", and it is the place a
 * false terminal state would be introduced. Keeping it free of HTTP, clocks
 * and the store means every row of the table can be asserted directly.
 */
export function mapStandingToOutcome(standing: CentralStanding): EdgeForwardOutcome {
  switch (standing) {
    // EVIDENCE IS NOT APPLICATION. Central holds the witness; the Field action
    // is still awaiting authorised replay. This is the state an Edge sits in
    // for as long as the handset stays away, and it must never be mistaken for
    // completion or for failure.
    case 'EVIDENCE_RECORDED':
    case 'AUTHORITATIVE_REPLAY_RECEIVED':
      return { kind: 'PROGRESS', progress: 'CENTRAL_RECEIVED' };

    // A real replay is in flight. Still not terminal.
    case 'AUTHORITATIVE_REPLAY_APPLYING':
      return { kind: 'PROGRESS', progress: 'CENTRAL_APPLYING' };

    // The only two answers that may settle an entry, and both come from the
    // authoritative replay record rather than from anything this channel did.
    case 'AUTHORITATIVE_REPLAY_APPLIED':
      return { kind: 'SETTLE_APPLIED', centralRef: 'AUTHORITATIVE_REPLAY_APPLIED' };
    case 'AUTHORITATIVE_REPLAY_REJECTED':
      return { kind: 'SETTLE_REFUSED', reason: 'CENTRAL_DETERMINISTIC_REJECTION' };

    // UNKNOWN IS A FIRST-CLASS TRUTHFUL ANSWER, never a retry hint dressed up
    // as a result. The entry stays unsettled and is re-synchronised later.
    case 'UNKNOWN':
    default:
      return { kind: 'UNKNOWN', reason: 'CENTRAL_STANDING_UNKNOWN' };
  }
}

@Injectable()
export class EdgeEvidenceForwarder {
  private readonly logger = new Logger(EdgeEvidenceForwarder.name);

  constructor(
    private readonly config: EdgeConfigService,
    private readonly signer: EdgeRequestSigner,
  ) {}

  /**
   * Forwards one evidence bundle and reports what central said.
   *
   * The caller owns the queue transitions. This function performs no store
   * mutation at all, so a transport concern cannot move a queue entry as a
   * side effect -- the store's own transition rules stay the only thing that
   * decides what a state may become.
   */
  async forward(bundle: {
    readonly envelope: unknown;
    readonly payload: unknown;
    readonly receipt: unknown;
    readonly trustedTimeEvidence: unknown;
  }): Promise<EdgeForwardOutcome> {
    if (!this.signer.canSign()) {
      // An Edge with no signing identity still buffers. It simply has no way
      // to prove who it is, and forwarding unsigned would be asking central to
      // trust an assertion.
      return { kind: 'NOT_ATTEMPTED', reason: 'NO_SIGNING_IDENTITY' };
    }

    // The body is serialised ONCE and both signed and sent. Re-serialising for
    // the wire would digest one byte sequence and transmit another, and the
    // failure would look like tampering.
    const body = JSON.stringify({
      envelope: bundle.envelope,
      payload: bundle.payload,
      receipt: bundle.receipt,
      trusted_time_evidence: bundle.trustedTimeEvidence ?? null,
    });

    const route = '/api/v1/edge-gateway/witness';
    const proof = this.signer.sign({ method: 'POST', route, body, purpose: 'OFFLINE_OPERATION_INGRESS' });
    if (proof === null) return { kind: 'NOT_ATTEMPTED', reason: 'NO_SIGNING_IDENTITY' };

    // `globalThis.fetch`'s own response type. Named through `Awaited` rather
    // than as the ambient DOM `Response`, which the Node lint environment does
    // not declare -- the type is the same, the reference is one the linter can
    // actually resolve.
    let response: Awaited<ReturnType<typeof fetch>>;
    try {
      response = await fetch(`${this.config.values.SENTINEL_CENTRAL_URL}${route}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          // The proof travels in a header so the BODY stays exactly the bytes
          // the digest covers. Putting the proof inside the body would make it
          // part of what it attests to.
          'x-edge-proof': Buffer.from(JSON.stringify(proof), 'utf8').toString('base64url'),
        },
        body,
      });
    } catch {
      // THE CASE THIS WHOLE SYSTEM EXISTS FOR. A severed WAN is not a failure
      // of the operation; the entry stays queued and is retried with a NEW
      // request id.
      return { kind: 'UNKNOWN', reason: 'TRANSPORT_UNREACHABLE' };
    }

    if (response.status === 409) {
      // §5: the same evidence identity carrying changed semantics.
      //
      // AN EARLIER DRAFT SETTLED THIS AS `SETTLE_REFUSED`, WHICH WAS WRONG and
      // contradicted this file's own header. `SETTLE_REFUSED` becomes
      // `FAILED_TERMINAL`, and §4 forbids a terminal state arising from
      // evidence verification alone -- terminal requires an AUTHORITATIVE
      // replay outcome.
      //
      // The reasoning that made it look right was "retrying identical bytes
      // gives the same answer forever", which is true and irrelevant: the
      // EVIDENCE is stuck, but the OPERATION's fate is entirely undecided and
      // may still apply perfectly when the handset reconnects. Settling here
      // would mark a Field action failed on the strength of an Edge-side
      // bookkeeping conflict.
      return { kind: 'UNKNOWN', reason: 'EDGE_EVIDENCE_CONFLICT' };
    }
    if (response.status === 403) {
      // Authentication or receipt verification refused. Retrying unchanged
      // bytes cannot help, but this is NOT a domain rejection and must not be
      // recorded as one -- the operation may still replay perfectly when the
      // handset reconnects. The entry is left for an operator.
      return { kind: 'UNKNOWN', reason: 'CENTRAL_REFUSED_EVIDENCE' };
    }
    if (!response.ok) {
      // A LOST OR FAILED RESPONSE IS NOT A REFUSAL. Central may have recorded
      // the evidence and failed to tell us.
      return { kind: 'UNKNOWN', reason: `CENTRAL_HTTP_${response.status}` };
    }

    let answer: { standing?: unknown };
    try {
      answer = (await response.json()) as { standing?: unknown };
    } catch {
      return { kind: 'UNKNOWN', reason: 'CENTRAL_ANSWER_UNREADABLE' };
    }

    const standing = typeof answer.standing === 'string' ? (answer.standing as CentralStanding) : 'UNKNOWN';
    return mapStandingToOutcome(standing);
  }
}
