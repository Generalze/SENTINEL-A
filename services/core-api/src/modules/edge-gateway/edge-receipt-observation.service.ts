import { Inject, Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import type { VerifiedEdgeTrustedTimeEvidence } from '../edge-trusted-time/central-edge-trusted-time.verifier';
import type { AdmittedEdgeWitness } from './edge-witness.service';

/**
 * M3B §3 / §8 — WRITING DOWN WHAT CENTRAL VERIFIED.
 *
 * WHY THIS EXISTS
 * ---------------
 * WP-31's Proof D collector had no central-side Edge source. It could only
 * report `SOURCE_NOT_PRESENT` and decline eligibility, because the only record
 * that an Edge had witnessed anything lived on the Edge itself. Reading that as
 * proof would mean the party being evidenced writes its own evidence.
 *
 * This is the central-side counterpart: a row written only after central has
 * authenticated the caller, verified the receipt signature against its own
 * registry, and (where evidence was supplied) independently derived and matched
 * the trusted time.
 *
 * WHAT A ROW MEANS, AND WHAT IT DOES NOT
 * --------------------------------------
 *     it means      CENTRAL VERIFIED THIS EDGE WITNESS
 *     it does NOT
 *     mean          CENTRAL AUTHORISED THE OPERATION
 *
 * The operation still goes through the existing offline replay and authority
 * checks and may be refused there AFTER this row exists. Those are different
 * questions -- "can we prove when this was witnessed" and "was this allowed" --
 * and the whole offline design depends on keeping them apart. A reader that
 * treats an observation as an admission decision has merged them.
 *
 * THE TIME ARGUMENT IS A TYPE, NOT AN INSTANT
 * -------------------------------------------
 * `verifiedTime` is `VerifiedEdgeTrustedTimeEvidence | null` and there is no
 * overload accepting a string or a Date. An unverified Edge timestamp cannot
 * reach this table, because there is no parameter it would fit in. `null` is
 * the honest outcome for "no evidence arrived, or it did not verify", and it is
 * recorded as NULL rather than as the Edge's unverified claim.
 */
/**
 * What happened to the evidence, in the vocabulary the effectively-once model
 * already uses. `NOT_RECORDED` is a truthful fourth answer: the write failed
 * and the caller must not report a witness central does not hold.
 */
export type EdgeObservationOutcome = 'FIRST_SEEN' | 'CONVERGED' | 'CONFLICT' | 'NOT_RECORDED';

@Injectable()
export class EdgeReceiptObservationService {
  private readonly logger = new Logger(EdgeReceiptObservationService.name);

  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  /**
   * Records one verified witness. Idempotent.
   *
   * A LOST RESPONSE IS THE NORMAL CASE, NOT THE EXCEPTION. When the Edge does
   * not learn the outcome it forwards the same receipt again, and it must:
   * that is what makes the queue effectively-once rather than at-most-once.
   * So a repeat arrival converges on the existing row instead of recording a
   * second observation of one witness -- otherwise Proof D would count a single
   * witnessed operation twice and the duplicate would be indistinguishable from
   * two genuine ones.
   *
   * Convergence is on `(organisation_id, receipt_fingerprint)`, which is the
   * receipt's own identity. Two DIFFERENT receipts for the same operation are
   * two observations, correctly: an Edge that re-signed is a distinct witness
   * event, and collapsing them would hide a re-signing.
   */
  async record(input: {
    readonly witness: AdmittedEdgeWitness;
    readonly verifiedTime: VerifiedEdgeTrustedTimeEvidence | null;
    readonly offlineOperationId: string | null;
    readonly traceId: string | null;
  }): Promise<EdgeObservationOutcome> {
    const { witness, verifiedTime } = input;

    // §5 — THREE IDEMPOTENCIES, KEPT APART.
    //
    //     Edge transport anti-replay   a fresh request_id per HTTP attempt
    //     EVIDENCE identity            this: one witness, recorded once
    //     device domain replay         the human-authenticated path's own
    //
    // Collapsing any two would mean a retried HTTP attempt looked like a second
    // witness, or a second witness looked like a retried attempt. The check
    // below is on the EVIDENCE identity only.
    const existing = await this.prisma.edgeReceiptObservation.findUnique({
      where: {
        organisationId_receiptFingerprint: {
          organisationId: witness.organisationId,
          receiptFingerprint: witness.receiptFingerprint,
        },
      },
      select: { witnessedOperationFingerprint: true, offlineOperationId: true },
    });

    if (existing !== null) {
      // THE SAME EVIDENCE IDENTITY MUST NOT CARRY CHANGED SEMANTICS.
      //
      // `receipt_fingerprint` digests the Edge's signed statement, so a
      // re-signed receipt arrives under a different identity and is a second
      // observation, correctly. What this catches is the SAME signed receipt
      // arriving bound to a DIFFERENT envelope -- the operation id and the
      // witnessed fingerprint come from bytes the receipt does not itself
      // cover, so that substitution is possible and must be refused rather
      // than silently converged.
      const semanticsChanged =
        existing.witnessedOperationFingerprint !== witness.witnessedOperationFingerprint ||
        (existing.offlineOperationId !== null &&
          input.offlineOperationId !== null &&
          existing.offlineOperationId !== input.offlineOperationId);
      if (semanticsChanged) {
        this.logger.warn(
          `edge receipt observation conflict: organisation_id=${witness.organisationId} edge_id=${witness.edgeId}`,
        );
        return 'CONFLICT';
      }
      return 'CONVERGED';
    }

    try {
      await this.prisma.edgeReceiptObservation.upsert({
        where: {
          organisationId_receiptFingerprint: {
            organisationId: witness.organisationId,
            receiptFingerprint: witness.receiptFingerprint,
          },
        },
        // A REPEAT CHANGES NOTHING. The first verified observation is the
        // record; a later arrival of the same receipt must not be able to move
        // `observed_at` forward, because that instant is central's evidence of
        // WHEN it learned of the witness, and rewriting it would erase the very
        // interval Proof D measures.
        update: {},
        create: {
          organisationId: witness.organisationId,
          siteId: witness.siteId,
          edgeId: witness.edgeId,
          edgeKeyId: witness.edgeKeyId,
          edgeKeyVersion: witness.edgeKeyVersion,
          offlineOperationId: input.offlineOperationId,
          witnessedOperationFingerprint: witness.witnessedOperationFingerprint,
          receiptFingerprint: witness.receiptFingerprint,
          // PROVENANCE OF THE TIME, NOT MERELY THE TIME. All four move
          // together: either central verified an anchor and can name it, or it
          // could not and every one of them is NULL. There is deliberately no
          // state in which a time is recorded without the anchor that justified
          // it, because that row would be indistinguishable from a claim.
          trustedTimeAnchorId: verifiedTime?.anchorId ?? null,
          trustedTimeAnchorFingerprint: verifiedTime?.anchorFingerprint ?? null,
          verifiedEdgeTrustedTime: verifiedTime?.verifiedTrustedTime ?? null,
          edgeMonotonicPosition: verifiedTime?.edgeMonotonicPosition ?? witness.edgeMonotonicPosition,
          traceId: input.traceId,
        },
      });
    } catch (error) {
      // A FAILED OBSERVATION MUST NOT FAIL THE OPERATION. This table is
      // evidence, not authority: the receipt has already been verified and the
      // operation's own admission is decided elsewhere. Throwing here would let
      // an evidence-write fault refuse work that central had already accepted,
      // which is a worse outcome than a gap in the evidence -- and the gap is
      // itself visible, because a bundle whose observation is missing reports
      // that rather than inventing one.
      this.logger.error(
        `edge receipt observation not recorded: organisation_id=${witness.organisationId} edge_id=${witness.edgeId} ` +
          `reason=${error instanceof Error ? error.name : 'unknown'}`,
      );
      return 'NOT_RECORDED';
    }

    return 'FIRST_SEEN';
  }
}
