import { createHash } from 'node:crypto';
import { Prisma } from '@prisma/client';
import { deviceBootstrapGrantReplayKey, isConsistentDeviceNonceConsumption } from '@sentinel/contracts';
import { describe, expect, it } from 'vitest';
import { DeviceReplayService } from './device-replay.service';

/**
 * WP-24/D24-11 — the replay store's WIRING, tested as a pure unit.
 *
 * The three-way classification itself is the CONTRACT's and is already proven
 * in `device-identity.test.ts`. What is proven here is the part that is this
 * module's: that the store digests the contract's canonical replay key, keys
 * on the IDENTITY rather than the fingerprint, and hands the classifier
 * exactly what the row said — including the pathological row whose stored
 * reference is missing, which must fail closed rather than be papered over.
 *
 * The transaction client is a stand-in, deliberately: the property under test
 * is which values cross the seam, and a live database would prove that only
 * incidentally while making the failure modes hard to construct. The live
 * behaviour — atomic insert-or-read under real concurrency — is exercised by
 * `shield.registry.integration.spec.ts` against real Postgres.
 */

interface StubRow {
  statement_fingerprint: string;
  stored_outcome_ref: string | null;
}

/**
 * A transaction client that answers the two statements the service issues:
 * the `INSERT ... ON CONFLICT DO NOTHING RETURNING id`, and the follow-up
 * SELECT. Which one it is answering is decided by call order, which is the
 * service's own fixed sequence.
 */
function stubTx(existing: StubRow | null): { tx: Prisma.TransactionClient; sql: string[] } {
  const sql: string[] = [];
  let call = 0;
  const queryRaw = async (query: Prisma.Sql): Promise<unknown[]> => {
    sql.push(query.sql);
    call += 1;
    if (call === 1) return existing === null ? [{ id: 'inserted' }] : [];
    return existing === null ? [] : [existing];
  };
  return { tx: { $queryRaw: queryRaw } as unknown as Prisma.TransactionClient, sql };
}

const REPLAY_KEY = deviceBootstrapGrantReplayKey({
  organisation_id: 'org-1',
  site_id: 'site-1',
  intended_user_id: 'user-1',
  grant_id: 'grant-1',
});
const FINGERPRINT = 'a'.repeat(64);

describe('WP-24/D24-11 DeviceReplayService', () => {
  const service = new DeviceReplayService();

  const consume = async (existing: StubRow | null, fingerprint = FINGERPRINT) => {
    const { tx, sql } = stubTx(existing);
    const result = await service.consume(tx, {
      organisationId: 'org-1',
      ceremony: 'BOOTSTRAP_GRANT',
      replayKey: REPLAY_KEY,
      statementFingerprint: fingerprint,
      candidateOutcomeRef: 'candidate-device',
      traceId: 'trace-1',
    });
    return { result, sql };
  };

  it('digests the CONTRACT canonical replay key, and that digest is the identity', async () => {
    const { result } = await consume(null);
    expect(result.replayIdentityDigest).toBe(createHash('sha256').update(REPLAY_KEY, 'utf8').digest('hex'));
  });

  it('D24-11: the unique constraint is the replay IDENTITY, never the fingerprint', async () => {
    const { sql } = await consume(null);
    // Keying on the fingerprint would file two different requests as two
    // unrelated rows and detect nothing — the entire failure D24-11 names.
    expect(sql[0]).toContain('ON CONFLICT (organisation_id, replay_identity_digest)');
    expect(sql[0]).not.toContain('statement_fingerprint)');
    expect(sql[0]).toContain('DO NOTHING');
  });

  it('never uses create/catch: the conflict is resolved by ONE database statement', async () => {
    // A P2002 raised inside a Prisma interactive transaction aborts the whole
    // Postgres transaction, which would poison the very transaction that must
    // go on to commit an enrollment (the WP-20 repository documents the same
    // hazard). Insert-or-nothing never puts the transaction into a failed state.
    const { sql } = await consume({ statement_fingerprint: FINGERPRINT, stored_outcome_ref: 'device-1' });
    expect(sql).toHaveLength(2);
    expect(sql[0]).toContain('INSERT INTO device_nonce_consumptions');
    expect(sql[1]).toContain('SELECT statement_fingerprint');
  });

  it('FIRST_SEEN when nothing was stored, carrying no outcome to converge on', async () => {
    const { result } = await consume(null);
    expect(result.consumption.outcome).toBe('FIRST_SEEN');
    expect(result.consumption.stored_outcome_ref).toBeNull();
    expect(isConsistentDeviceNonceConsumption(result.consumption)).toBe(true);
  });

  it('EXACT_DUPLICATE converges on the STORED reference, not this attempt candidate', async () => {
    const { result } = await consume({ statement_fingerprint: FINGERPRINT, stored_outcome_ref: 'device-first-attempt' });
    expect(result.consumption.outcome).toBe('EXACT_DUPLICATE');
    // This is what makes D24-06's "an exact retry converges on the SAME device
    // identity" work: the retry's own freshly minted candidate is discarded.
    expect(result.consumption.stored_outcome_ref).toBe('device-first-attempt');
    expect(isConsistentDeviceNonceConsumption(result.consumption)).toBe(true);
  });

  it('REUSED_WITH_CHANGED_SEMANTICS when the identity was spent on different bytes', async () => {
    const { result } = await consume({ statement_fingerprint: 'b'.repeat(64), stored_outcome_ref: 'device-first-attempt' });
    expect(result.consumption.outcome).toBe('REUSED_WITH_CHANGED_SEMANTICS');
    expect(result.consumption.stored_outcome_ref).toBeNull();
    expect(isConsistentDeviceNonceConsumption(result.consumption)).toBe(true);
  });

  it('C15-R1: a stored row with NO reference is reported honestly and fails closed', async () => {
    const { result } = await consume({ statement_fingerprint: FINGERPRINT, stored_outcome_ref: null });
    expect(result.consumption.outcome).toBe('EXACT_DUPLICATE');
    // Substituting this attempt's candidate would hand a duplicate a pointer
    // to an outcome that does not exist — the exact C15-R1 defect, arriving
    // through the store instead of through the type. Reported as empty, the
    // contract's own runtime guard refuses it.
    expect(result.consumption.stored_outcome_ref).toBe('');
    expect(isConsistentDeviceNonceConsumption(result.consumption)).toBe(false);
  });

  it('an insert that conflicts with a row that is not there is a fault, not a FIRST_SEEN', async () => {
    // Inventing FIRST_SEEN here would authorise a second effect on an identity
    // the database has just said is taken.
    let call = 0;
    const tx = {
      $queryRaw: async (): Promise<unknown[]> => {
        call += 1;
        return [];
      },
    } as unknown as Prisma.TransactionClient;
    await expect(
      service.consume(tx, {
        organisationId: 'org-1',
        ceremony: 'BOOTSTRAP_GRANT',
        replayKey: REPLAY_KEY,
        statementFingerprint: FINGERPRINT,
        candidateOutcomeRef: 'candidate',
        traceId: 'trace-1',
      }),
    ).rejects.toThrow(/vanished/u);
    expect(call).toBe(2);
  });
});
