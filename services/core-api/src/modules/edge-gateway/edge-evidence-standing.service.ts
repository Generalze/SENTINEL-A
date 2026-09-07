import { Inject, Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * M3B §6 — WHAT CENTRAL CURRENTLY KNOWS ABOUT AN OPERATION.
 *
 * WHY THIS IS A READ AND NOTHING ELSE
 * -----------------------------------
 * The Edge evidence ingress must tell a synchronising Edge where the operation
 * actually stands, so the Edge can settle its own queue. It must do that
 * WITHOUT executing anything, and this service is the shape of that
 * restriction: it opens no transaction, writes no row, and has no method that
 * could advance a cursor or mint an outcome.
 *
 * THE AUTHORITATIVE RECORD IS THE DEVICE'S, NOT THE EDGE'S
 * --------------------------------------------------------
 * `FieldOfflineOperationReceipt` is written by the human-authenticated replay
 * path (WP-29A) and by nothing else. An Edge observation NEVER creates one.
 * So the two questions stay visibly distinct:
 *
 *     EdgeReceiptObservation          central verified an Edge witness
 *     FieldOfflineOperationReceipt    central actually replayed the operation
 *
 * A standing derived from the first would be a standing invented by the party
 * that delivered the evidence. Every terminal answer below comes from the
 * second.
 *
 * CORRELATION IS EXACT, NEVER NEAREST (§8). The lookup is by tenant AND the
 * device's own `offline_operation_id`. There is no fuzzy match, no "most
 * recent for this device", and no fallback to the fingerprint alone -- an
 * approximate correlation would let one operation's outcome settle a different
 * operation's queue entry.
 */

/**
 * The standing, in the vocabulary §6 fixes.
 *
 * `EVIDENCE_RECORDED` is deliberately distinct from every replay state: it
 * says central holds the Edge's evidence and nothing more. It is the honest
 * answer while the Field device has not yet reconnected, and it is the one
 * that must never be mistaken for completion.
 */
export type EdgeOperationStanding =
  | 'EVIDENCE_RECORDED'
  | 'AUTHORITATIVE_REPLAY_RECEIVED'
  | 'AUTHORITATIVE_REPLAY_APPLYING'
  | 'AUTHORITATIVE_REPLAY_APPLIED'
  | 'AUTHORITATIVE_REPLAY_REJECTED'
  | 'UNKNOWN';

@Injectable()
export class EdgeEvidenceStandingService {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  /**
   * The current standing of one operation.
   *
   * `offlineOperationId` may be `null` when the forwarded envelope carried no
   * readable operation id. That yields `EVIDENCE_RECORDED`, not `UNKNOWN`: we
   * know exactly what we hold (the evidence) and exactly what we lack (a
   * correlation), and reporting uncertainty we do not have would push the Edge
   * into retrying a lookup that can never resolve.
   */
  async standingOf(organisationId: string, offlineOperationId: string | null): Promise<EdgeOperationStanding> {
    if (offlineOperationId === null) return 'EVIDENCE_RECORDED';

    const receipt = await this.prisma.fieldOfflineOperationReceipt.findFirst({
      where: { organisationId, offlineOperationId },
      select: { status: true, outcome: true },
    });

    // NO AUTHORITATIVE REPLAY HAS HAPPENED. The Field device has not reconnected
    // with a live human session, so the operation is still awaiting authorised
    // replay. This is the §9 case that must stay truthful: not FAILED, not
    // APPLIED, and not an invitation to invent an escape hatch so a queue can
    // go green.
    if (receipt === null) return 'EVIDENCE_RECORDED';

    switch (receipt.status) {
      case 'RECEIVED':
        return 'AUTHORITATIVE_REPLAY_RECEIVED';
      case 'APPLYING':
        return 'AUTHORITATIVE_REPLAY_APPLYING';
      case 'APPLIED':
        return 'AUTHORITATIVE_REPLAY_APPLIED';
      case 'REJECTED':
        // Only a DETERMINISTIC rejection is terminal. The replay path records
        // `outcome` when it finalises; a row marked REJECTED without one has
        // not finished deciding, and calling it terminal here would let the
        // Edge prune an entry central may still apply.
        return receipt.outcome === 'REJECTED' ? 'AUTHORITATIVE_REPLAY_REJECTED' : 'UNKNOWN';
      default:
        // Includes the replay path's own UNKNOWN. A first-class truthful
        // outcome, propagated rather than collapsed into a guess.
        return 'UNKNOWN';
    }
  }
}
