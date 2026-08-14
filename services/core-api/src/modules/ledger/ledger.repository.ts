import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type DecisionLedgerEntry as LedgerRow } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { decodeCursor, encodeCursor } from './ledger.pagination';
import type { LedgerApproval, LedgerEntry, LedgerListFilter } from './ledger.types';

export interface InsertLedgerEntryData {
  entryId: string;
  organisationId: string;
  decidedAt: Date;
  decisionType: string;
  inputsSnapshot: Prisma.InputJsonValue;
  ruleOrModelVersions: string[];
  policyVersion: string;
  evidenceFor: string[];
  evidenceAgainst: string[];
  confidence: number | null;
  approvals: Prisma.InputJsonValue;
  actionTaken: string;
  outcome: string | null;
  traceId: string;
  schemaVersion: number;
  contentHash: string;
  supersedesEntryId: string | null;
}

function toLedgerEntry(row: LedgerRow): LedgerEntry {
  return {
    // The Prisma column is a general Int (future schema evolution); the contract narrows it to
    // the literal 1 (the only schema version that exists today), same as decision-record.ts's
    // CONSTITUTION_DECISION_TYPE-shaped output — every row currently in the table was written
    // with schemaVersion 1 by LedgerService.append.
    schema_version: row.schemaVersion as 1,
    entry_id: row.entryId,
    organisation_id: row.organisationId,
    decided_at: row.decidedAt.toISOString(),
    decision_type: row.decisionType,
    inputs_snapshot: row.inputsSnapshot as Record<string, unknown>,
    rule_or_model_versions: row.ruleOrModelVersions,
    policy_version: row.policyVersion,
    evidence_for: row.evidenceFor,
    evidence_against: row.evidenceAgainst,
    confidence: row.confidence,
    approvals: row.approvals as unknown as readonly LedgerApproval[],
    action_taken: row.actionTaken,
    outcome: row.outcome,
    trace_id: row.traceId,
    content_hash: row.contentHash,
    previous_hash: row.previousHash,
    supersedes_entry_id: row.supersedesEntryId,
    created_at: row.createdAt.toISOString(),
  };
}

/**
 * Append-only data access for the Decision Ledger. Exposes append + reads (query listing and
 * the chain-order scan `verifyChain` needs) ONLY. No `.update(`/`.delete(` against the
 * `DecisionLedgerEntry` model exists anywhere in this module — see
 * ledger.append-only.spec.ts, which enforces this as an automated source scan.
 */
@Injectable()
export class LedgerRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  /**
   * Appends one entry to the organisation's chain.
   *
   * Concurrency (directive #2): two concurrent appends for the SAME organisation must never
   * both compute `previous_hash` from the same predecessor — that would fork the chain, two
   * entries each claiming to be the true successor of the same prior entry. A Postgres
   * transaction-scoped advisory lock keyed by a hash of the organisation id serialises the
   * "read the current head, then insert" critical section per organisation; appends for
   * DIFFERENT organisations proceed fully in parallel (the lock key is organisation-specific).
   * The lock is released automatically when the transaction commits or rolls back, so a crashed
   * request can never leave the org's chain permanently blocked.
   *
   * A burst of concurrent appends for the same organisation legitimately serialises on the
   * advisory lock (that is the point), so later transactions in the burst can be left waiting
   * for both a free pool connection and their turn on the lock; Prisma's interactive-transaction
   * defaults (`maxWait` 2s, `timeout` 5s) are sized for independent transactions, not a
   * deliberately-serialised queue, so both are raised here to accommodate a legitimate burst
   * rather than surfacing it as a spurious "unable to start a transaction" error.
   */
  async append(data: InsertLedgerEntryData): Promise<LedgerEntry> {
    const row = await this.prisma.$transaction(
      async (tx) => {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${data.organisationId})::bigint)`;

        const latest = await tx.decisionLedgerEntry.findFirst({
          where: { organisationId: data.organisationId },
          orderBy: { seq: 'desc' },
          select: { contentHash: true },
        });

        return tx.decisionLedgerEntry.create({
          data: {
            entryId: data.entryId,
            organisationId: data.organisationId,
            decidedAt: data.decidedAt,
            decisionType: data.decisionType,
            inputsSnapshot: data.inputsSnapshot,
            ruleOrModelVersions: data.ruleOrModelVersions,
            policyVersion: data.policyVersion,
            evidenceFor: data.evidenceFor,
            evidenceAgainst: data.evidenceAgainst,
            confidence: data.confidence,
            approvals: data.approvals,
            actionTaken: data.actionTaken,
            outcome: data.outcome,
            traceId: data.traceId,
            schemaVersion: data.schemaVersion,
            contentHash: data.contentHash,
            previousHash: latest?.contentHash ?? null,
            supersedesEntryId: data.supersedesEntryId,
          },
        });
      },
      { maxWait: 10_000, timeout: 20_000 },
    );

    return toLedgerEntry(row);
  }

  async findByEntryId(entryId: string): Promise<LedgerEntry | null> {
    const row = await this.prisma.decisionLedgerEntry.findUnique({ where: { entryId } });
    return row === null ? null : toLedgerEntry(row);
  }

  async countByOrganisation(organisationId: string): Promise<number> {
    return this.prisma.decisionLedgerEntry.count({ where: { organisationId } });
  }

  /** Deliverable #4: tenant-scoped, filterable, cursor-paginated, newest first. */
  async list(filter: LedgerListFilter): Promise<{ items: LedgerEntry[]; nextCursor: string | null }> {
    const where: Prisma.DecisionLedgerEntryWhereInput = {
      organisationId: filter.organisationId,
      ...(filter.decisionType ? { decisionType: filter.decisionType } : {}),
      ...(filter.decidedFrom || filter.decidedTo
        ? {
            decidedAt: {
              ...(filter.decidedFrom ? { gte: filter.decidedFrom } : {}),
              ...(filter.decidedTo ? { lte: filter.decidedTo } : {}),
            },
          }
        : {}),
    };

    if (filter.cursor) {
      const cursor = decodeCursor(filter.cursor);
      const cursorDate = new Date(cursor.decidedAt);
      where.OR = [{ decidedAt: { lt: cursorDate } }, { decidedAt: cursorDate, entryId: { lt: cursor.entryId } }];
    }

    const rows = await this.prisma.decisionLedgerEntry.findMany({
      where,
      orderBy: [{ decidedAt: 'desc' }, { entryId: 'desc' }],
      take: filter.limit + 1,
    });

    const hasMore = rows.length > filter.limit;
    const items = hasMore ? rows.slice(0, filter.limit) : rows;
    const last = items[items.length - 1];
    const nextCursor =
      hasMore && last ? encodeCursor({ decidedAt: last.decidedAt.toISOString(), entryId: last.entryId }) : null;

    return { items: items.map(toLedgerEntry), nextCursor };
  }

  /**
   * Oldest -> newest, for `verifyChain` (directive #5). Ordered by `seq` (the DB-assigned,
   * append-serialised insertion counter), not `decidedAt` — see the `seq` field doc on the
   * Prisma model for why `decidedAt` alone is not a safe chain-order key.
   *
   * A full per-organisation scan; bounded by that organisation's entry count, which is
   * acceptable at this milestone's scale (§29 — an independent, indexed Black Box store is a
   * later milestone).
   */
  async listChainOrder(organisationId: string): Promise<LedgerEntry[]> {
    const rows = await this.prisma.decisionLedgerEntry.findMany({
      where: { organisationId },
      orderBy: { seq: 'asc' },
    });
    return rows.map(toLedgerEntry);
  }
}
