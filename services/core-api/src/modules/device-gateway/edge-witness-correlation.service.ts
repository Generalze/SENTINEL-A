import { Inject, Injectable } from '@nestjs/common';
import type { AuthenticatedDeviceContext } from '@sentinel/contracts';
import { PrismaService } from '../../prisma/prisma.service';

/**
 * M3B §8 — RESOLVING THE EDGE WITNESS A REPLAYED OPERATION ALREADY HAS.
 *
 * WHAT THIS IS FOR
 * ----------------
 * When the WAN returns, the Edge synchronises its evidence first and central
 * records an `EdgeReceiptObservation`. Later -- possibly much later -- the
 * Field device reconnects with a live human session and replays the operation
 * through the WP-29A ingress. At that moment central may ALREADY hold a
 * verified witness for it.
 *
 * The device does not have to re-present a raw Edge receipt for central to use
 * that provenance. What it must not do is inherit provenance that belongs to
 * some other operation.
 *
 * EXACT MATCH, NEVER NEAREST
 * --------------------------
 * Five facts must agree: tenant, site, device, the operation id, and the
 * operation fingerprint. A mismatch on ANY of them makes the observation
 * unusable, and unusable means `null` -- not "the closest one", not "the most
 * recent for this device", not "the only one at this site".
 *
 * The temptation is real, because a near-match usually IS the right row and
 * the code would look like it worked. But provenance is exactly the thing that
 * must not be approximate: an Edge witness attached to the wrong operation
 * would place a shift's offline work inside a lease window it never occupied,
 * and would do so with central's own verification behind it.
 *
 * IT IS A READ. This service has no write method, opens no transaction, and
 * cannot create the observation it looks for. An operation with no verified
 * witness replays perfectly well without one; the witness is provenance, not
 * permission.
 */

export interface ResolvedEdgeWitness {
  readonly observationId: string;
  readonly edgeId: string;
  readonly edgeKeyId: string;
  readonly edgeKeyVersion: number;
  /** NULL when central could not establish a trustworthy time for the witness. */
  readonly verifiedEdgeTrustedTime: Date | null;
  readonly trustedTimeAnchorId: string | null;
  readonly edgeMonotonicPosition: number | null;
  readonly observedAt: Date;
}

@Injectable()
export class EdgeWitnessCorrelationService {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  /**
   * The verified Edge witness for exactly this operation, or `null`.
   *
   * `null` is a completely ordinary answer. It means no Edge synchronised
   * evidence for this operation -- because none was deployed, because the Edge
   * has not reconnected yet, or because the device reached central directly.
   * None of those is an error and none of them refuses the replay.
   */
  async resolve(
    /**
     * C17-02 — THE TENANT AND DEVICE COME FROM THE AUTHENTICATED CONTEXT.
     *
     * An earlier revision took `organisationId` as a loose string, and the
     * architecture tripwire caught it. It was right to: a caller could then
     * have passed a CLAIMED tenant, and this lookup would have selected rows
     * with it. The identical defect was found in `DevicePolicyLeaseService`
     * during WP-29A, and the fix there was the same -- take the context, not
     * the ids, so the wrong thing cannot be passed rather than merely should
     * not be.
     *
     * `siteId` remains a parameter because a context authorises SEVERAL sites
     * and the caller has already bound the one being replayed; it is checked
     * for membership below rather than trusted.
     */
    context: AuthenticatedDeviceContext,
    input: {
      readonly siteId: string;
      readonly offlineOperationId: string;
      readonly operationFingerprint: string;
    },
  ): Promise<ResolvedEdgeWitness | null> {
    // The site must be one this context actually authorises. Without this the
    // caller could name any site and read its witnesses.
    if (!context.authorised_site_ids.includes(input.siteId)) return null;

    const observation = await this.prisma.edgeReceiptObservation.findFirst({
      // EVERY correlating fact is in the WHERE clause rather than checked
      // afterwards. A post-hoc comparison is a place where one `if` can be
      // dropped and the query still returns a row; this cannot return the
      // wrong row at all.
      where: {
        organisationId: context.organisation_id,
        siteId: input.siteId,
        offlineOperationId: input.offlineOperationId,
        witnessedOperationFingerprint: input.operationFingerprint,
      },
      select: {
        id: true,
        edgeId: true,
        edgeKeyId: true,
        edgeKeyVersion: true,
        verifiedEdgeTrustedTime: true,
        trustedTimeAnchorId: true,
        edgeMonotonicPosition: true,
        observedAt: true,
      },
      // Deterministic, so a pathological duplicate cannot make this answer
      // differently on two reads. The unique index on
      // (organisation_id, receipt_fingerprint) means two rows here would be two
      // DIFFERENT receipts witnessing one operation, which is legitimate -- an
      // Edge that re-signed. The earliest is the one that observed it first.
      orderBy: { observedAt: 'asc' },
    });

    if (observation === null) return null;

    return {
      observationId: observation.id,
      edgeId: observation.edgeId,
      edgeKeyId: observation.edgeKeyId,
      edgeKeyVersion: observation.edgeKeyVersion,
      verifiedEdgeTrustedTime: observation.verifiedEdgeTrustedTime,
      trustedTimeAnchorId: observation.trustedTimeAnchorId,
      edgeMonotonicPosition: observation.edgeMonotonicPosition,
      observedAt: observation.observedAt,
    };
  }
}
