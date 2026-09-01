import { Injectable } from '@nestjs/common';
import { randomUUID, createHash } from 'node:crypto';
import { Prisma } from '@prisma/client';
import { classifyDeviceNonceConsumption, type DeviceNonceConsumption } from '@sentinel/contracts';

/**
 * WP-24/D24-11 — THE WP-23 ANTI-REPLAY SEAM AS DURABLE TRANSACTIONAL STATE.
 *
 * `classifyDeviceNonceConsumption` is a pure classifier: given what is being
 * presented and what (if anything) the store already holds for that identity,
 * it names one of three outcomes. WP-23 could go no further, because the store
 * is I/O and I/O does not belong in a contracts package (D23-16). This service
 * is the store, and it does exactly three things:
 *
 *     digest the contract's canonical replay key
 *     insert-or-read that identity ATOMICALLY, inside the caller's transaction
 *     hand what it found to the contract classifier
 *
 * It takes NO decision of its own. It does not decide that a duplicate may
 * proceed, it does not decide that changed semantics conflict, and it never
 * short-circuits: those are `evaluateDeviceEnrollmentCommit`'s and
 * `evaluateDeviceKeyRotation`'s rulings, and restating either here would put a
 * second copy of a security decision in a place nobody reviews as one.
 *
 * THE UNIQUE KEY IS THE IDENTITY, NEVER THE FINGERPRINT (D24-11)
 * -------------------------------------------------------------
 * `(organisation_id, replay_identity_digest)`. The entire purpose of the row
 * is to detect CHANGED SEMANTICS hiding behind a reused one-shot identity.
 * Keying on the statement fingerprint instead would file two different
 * requests as two unrelated rows and detect nothing at all — the row would
 * become a duplicate-suppressor for byte-identical retries and no more, which
 * is the one case that was never the problem.
 *
 * The canonical replay KEY is stored beside its digest for the reason the
 * contract gives for keeping identities structural: a hash cannot be queried,
 * audited or reasoned about, so an operator investigating a burned identity
 * can read what it was. The digest exists only because a canonical JSON string
 * is an unbounded value and a B-tree index is not.
 *
 * WHY INSERT ... ON CONFLICT AND NOT create/catch
 * ----------------------------------------------
 * The WP-20 repository already documents the hazard: a P2002 raised inside a
 * Prisma interactive transaction aborts the whole Postgres transaction, since
 * no savepoint is taken. Handling a unique-violation in place would therefore
 * poison the very transaction that must go on to commit an enrollment. The
 * conflict is resolved by the DATABASE, in one statement, and the transaction
 * is never put into a failed state.
 *
 * The conflict target is spelled as the COLUMN PAIR rather than by name,
 * because `device_nonce_consumption_identity_key` is a unique INDEX in the
 * migration and `ON CONFLICT ON CONSTRAINT` accepts only a table constraint.
 * The columns are exactly the ones that index covers, so the D24-11 rule — the
 * unique key is the replay identity, never the fingerprint — is stated here in
 * the terms Postgres actually matches on.
 */

/**
 * What the caller is presenting, and what it would create if this is the first
 * time it has been presented.
 */
export interface DeviceReplayConsumptionInput {
  readonly organisationId: string;
  /** A label for operators. NOT part of the uniqueness — see the header. */
  readonly ceremony: string;
  /** The canonical replay key from the CONTRACT's own identity function. */
  readonly replayKey: string;
  /** The canonical-statement fingerprint the identity is being spent on. */
  readonly statementFingerprint: string;
  /**
   * The reference a LATER exact retry must converge on.
   *
   * It is supplied by the caller BEFORE the effect exists — the enrollment
   * commit pre-generates the device id, the rotation commit pre-generates the
   * new key row id — because a row written with a null ref would be a
   * duplicate that names no outcome, and the contract's own union makes that
   * unrepresentable for precisely the reason C15-R1 records: such a fact fell
   * through every convergence branch and caused a SECOND effect.
   *
   * On a retry the caller's freshly generated candidate is DISCARDED and the
   * stored one is returned, which is what makes an exact retry converge on the
   * same device identity rather than minting a second.
   */
  readonly candidateOutcomeRef: string;
  readonly traceId: string;
}

/** The classified fact, plus the digest the caller may need for an audit row. */
export interface DeviceReplayConsumptionResult {
  readonly consumption: DeviceNonceConsumption;
  readonly replayIdentityDigest: string;
}

interface ExistingConsumptionRow {
  statement_fingerprint: string;
  stored_outcome_ref: string | null;
}

/**
 * C16-02/C16-03: what the store already holds for one identity, WITHOUT
 * consuming it. `null` means the identity has never been presented.
 */
export interface DeviceReplayPeek {
  readonly replayIdentityDigest: string;
  readonly statementFingerprint: string;
  /** C15-R1: honestly `null` when the stored row names no outcome at all. */
  readonly storedOutcomeRef: string | null;
}

@Injectable()
export class DeviceReplayService {
  /**
   * C16-02/C16-03 — LOOK BEFORE YOU BURN.
   *
   * A pure read of what an identity already holds, taken inside the caller's
   * transaction and taking no decision of its own (this service never does).
   *
   * WHY IT EXISTS, STATED PLAINLY
   * -----------------------------
   * `consume` must be given the reference a later exact retry will converge
   * on, and it must be given it BEFORE the effect exists. The original code
   * therefore handed it a freshly minted candidate id every time — which is
   * correct for a first attempt and WRONG for a retry, because a retry's
   * freshly minted id is not what the first attempt actually produced. The old
   * design papered over that by writing the candidate anyway and letting the
   * classifier discard it, which is exactly how a FIRST_SEEN row came to name
   * an outcome that never committed.
   *
   * Peeking first lets the caller RESOLVE the real committed outcome against
   * the database and consume BOTH of a ceremony's identities against that ONE
   * canonical reference. The lagging identity's first-seen row is then written
   * pointing at the effect that actually exists, rather than at a candidate the
   * transaction is about to throw away.
   *
   * It reads without locking on purpose: a concurrent `consume` of the same
   * identity is serialised by the unique index inside `consume` itself, and the
   * classification that matters is still taken there. This read informs which
   * reference is offered, never whether the identity may be spent.
   */
  async peek(tx: Prisma.TransactionClient, input: { organisationId: string; replayKey: string }): Promise<DeviceReplayPeek | null> {
    const replayIdentityDigest = createHash('sha256').update(input.replayKey, 'utf8').digest('hex');
    const rows = await tx.$queryRaw<ExistingConsumptionRow[]>(Prisma.sql`
      SELECT statement_fingerprint, stored_outcome_ref
      FROM device_nonce_consumptions
      WHERE organisation_id = ${input.organisationId}
        AND replay_identity_digest = ${replayIdentityDigest}`);
    const existing = rows[0];
    if (existing === undefined) return null;
    return {
      replayIdentityDigest,
      statementFingerprint: existing.statement_fingerprint,
      storedOutcomeRef: existing.stored_outcome_ref,
    };
  }

  /**
   * Consumes one one-shot identity inside the CALLER's transaction.
   *
   * Taking `tx` rather than opening one is the whole point. The consumption
   * row and the effect it authorises must commit or roll back together: a row
   * that survives a rolled-back enrollment burns an identity for an enrollment
   * that never happened, and an effect that commits without its row is an
   * effect a replay can cause again.
   */
  async consume(tx: Prisma.TransactionClient, input: DeviceReplayConsumptionInput): Promise<DeviceReplayConsumptionResult> {
    const replayIdentityDigest = createHash('sha256').update(input.replayKey, 'utf8').digest('hex');

    // The id and `updated_at` are supplied explicitly because this is raw SQL:
    // `@default(uuid())` and `@updatedAt` are Prisma-client behaviours, not
    // column defaults, and the migration reflects that.
    const inserted = await tx.$queryRaw<Array<{ id: string }>>(Prisma.sql`
      INSERT INTO device_nonce_consumptions (
        id, organisation_id, ceremony, replay_identity_digest, replay_key,
        statement_fingerprint, stored_outcome_ref, first_seen_at, trace_id, updated_at
      ) VALUES (
        ${randomUUID()}::uuid, ${input.organisationId}, ${input.ceremony},
        ${replayIdentityDigest}, ${input.replayKey}, ${input.statementFingerprint},
        ${input.candidateOutcomeRef}, clock_timestamp(), ${input.traceId}, clock_timestamp()
      )
      ON CONFLICT (organisation_id, replay_identity_digest) DO NOTHING
      RETURNING id`);

    if (inserted.length === 1) {
      // Nothing had ever been presented under this identity, so there is
      // nothing stored to compare against and the classifier says FIRST_SEEN.
      return {
        replayIdentityDigest,
        consumption: classifyDeviceNonceConsumption({
          replay_key: input.replayKey,
          statement_fingerprint: input.statementFingerprint,
          stored: null,
        }),
      };
    }

    // The insert lost to an existing row. Read it back INSIDE the same
    // transaction: the conflicting row is committed (a concurrent uncommitted
    // insert would have blocked the statement above until its outcome was
    // known), so this read sees the identity as it actually stands.
    const rows = await tx.$queryRaw<ExistingConsumptionRow[]>(Prisma.sql`
      SELECT statement_fingerprint, stored_outcome_ref
      FROM device_nonce_consumptions
      WHERE organisation_id = ${input.organisationId}
        AND replay_identity_digest = ${replayIdentityDigest}`);

    const existing = rows[0];
    if (existing === undefined) {
      // The insert conflicted with a row that is not there. That is an
      // integrity fault, not a race, and there is no honest classification of
      // it — inventing FIRST_SEEN would authorise a second effect on an
      // identity the database has just said is taken.
      throw new Error('device nonce consumption row vanished between insert conflict and read');
    }

    return {
      replayIdentityDigest,
      consumption: classifyDeviceNonceConsumption({
        replay_key: input.replayKey,
        statement_fingerprint: input.statementFingerprint,
        stored: {
          statement_fingerprint: existing.statement_fingerprint,
          // C15-R1: a stored row with no reference names no outcome. It is
          // reported HONESTLY as the empty string rather than papered over,
          // and `isConsistentDeviceNonceConsumption` — which every contract
          // evaluator runs before it touches the fact — then refuses it with a
          // `*_CONSUMPTION_INCONSISTENT` verdict. Substituting the caller's
          // fresh candidate here would hand a duplicate a reference to an
          // outcome that does not exist.
          stored_outcome_ref: existing.stored_outcome_ref ?? '',
        },
      }),
    };
  }
}
