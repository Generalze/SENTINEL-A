import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type Event as EventRow } from '@prisma/client';
import type { NormalisedEvent } from '@sentinel/contracts';
import { PrismaService } from '../../prisma/prisma.service';
import { mapNormalisedEventToRow } from './events.mapper';
import { decodeCursor, encodeCursor } from './pagination.util';
import type { EventsListFilter } from './events.types';

const UNIQUE_CONSTRAINT_VIOLATION = 'P2002';

/**
 * True when `error` is the unique-constraint violation on the idempotency
 * key. WP-14/C1: the constraint is now the COMPOSITE
 * `@@unique([organisationId, idempotencyKey])`, so Prisma's `meta.target`
 * may surface the column list (`['organisation_id','idempotency_key']`),
 * the field list, or the constraint name — all of which mention
 * "idempotency". We normalise to a string and match on that substring so
 * the detection is robust across Prisma target-shape variations.
 */
export function isIdempotencyKeyConflict(error: unknown): boolean {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== UNIQUE_CONSTRAINT_VIOLATION) {
    return false;
  }
  const target = error.meta?.target;
  const asText = Array.isArray(target) ? target.join(',') : String(target ?? '');
  return asText.includes('idempotency');
}

/**
 * Append-only data access for the Event model.
 *
 * `markPublished` and the `receivedCount` increment inside
 * `recordDuplicateDelivery` are the ONLY two mutations against an existing
 * Event row anywhere in this service layer — see the class doc on the
 * `Event` Prisma model (prisma/schema/events.prisma) for why each exists.
 * Every other method here is a pure insert or a pure read. No `.update(`
 * or `.delete(` against the Event model exists anywhere else in this
 * module.
 */
@Injectable()
export class EventsRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  /**
   * WP-14/C1: the lookup is scoped to the caller's organisation and uses
   * `findFirst`, never a global `findUnique` on `idempotencyKey`. Even
   * though the derived key now leads with the organisation id, scoping the
   * query by `organisationId` too is defence in depth: a canonical row is
   * only ever matched within its own tenant, so a cross-tenant collision
   * can neither suppress nor reveal another org's event.
   */
  async findByIdempotencyKey(organisationId: string, key: string): Promise<EventRow | null> {
    return this.prisma.event.findFirst({ where: { organisationId, idempotencyKey: key } });
  }

  async findById(id: string): Promise<EventRow | null> {
    return this.prisma.event.findUnique({ where: { id } });
  }

  /** Insert-only: creates the canonical row for a brand-new idempotency key. */
  async createCanonical(event: NormalisedEvent, idempotencyKey: string): Promise<EventRow> {
    return this.prisma.event.create({
      data: { ...mapNormalisedEventToRow(event), idempotencyKey },
    });
  }

  /**
   * Records a redelivery: inserts a new row linked to the canonical event
   * (idempotencyKey left NULL — see the Prisma model doc for why this
   * doesn't collide with the unique index) and increments the canonical
   * row's `receivedCount`, atomically.
   *
   * EXCEPTION #1 to "no update on Event": the `receivedCount` increment
   * below.
   */
  async recordDuplicateDelivery(canonicalId: string, event: NormalisedEvent): Promise<EventRow> {
    return this.prisma.$transaction(async (tx) => {
      const duplicate = await tx.event.create({
        data: { ...mapNormalisedEventToRow(event), duplicateOfEventId: canonicalId },
      });
      await tx.event.update({
        where: { id: canonicalId },
        data: { receivedCount: { increment: 1 } },
      });
      return duplicate;
    });
  }

  /**
   * EXCEPTION #2 to "no update on Event": sets `publishedAt` after a
   * successful JetStream publish (initial attempt or retry sweep). Never
   * touches any other column.
   */
  async markPublished(id: string, publishedAt: Date = new Date()): Promise<void> {
    await this.prisma.event.update({ where: { id }, data: { publishedAt } });
  }

  async findUnpublishedOlderThan(cutoff: Date, limit: number): Promise<EventRow[]> {
    return this.prisma.event.findMany({
      // WP-14/M5: only canonical rows are ever published. Duplicate rows
      // (duplicateOfEventId set) are never independently published — their
      // publishedAt stays null forever — so without this filter the retry
      // sweep would try to republish every redelivery indefinitely.
      where: { publishedAt: null, duplicateOfEventId: null, createdAt: { lt: cutoff } },
      orderBy: { createdAt: 'asc' },
      take: limit,
    });
  }

  async list(filter: EventsListFilter): Promise<{ items: EventRow[]; nextCursor: string | null }> {
    const where: Prisma.EventWhereInput = {
      organisationId: filter.organisationId,
      // WP-14/M5: list only canonical events. Duplicate rows are internal
      // delivery bookkeeping (§64.1) and must never surface as if they were
      // distinct events.
      duplicateOfEventId: null,
      ...(filter.siteId ? { siteId: filter.siteId } : {}),
      ...(filter.sourceType ? { sourceType: filter.sourceType } : {}),
      ...(filter.occurredFrom || filter.occurredTo
        ? {
            occurredAt: {
              ...(filter.occurredFrom ? { gte: filter.occurredFrom } : {}),
              ...(filter.occurredTo ? { lte: filter.occurredTo } : {}),
            },
          }
        : {}),
    };

    if (filter.cursor) {
      const cursor = decodeCursor(filter.cursor);
      const cursorDate = new Date(cursor.occurredAt);
      where.OR = [{ occurredAt: { lt: cursorDate } }, { occurredAt: cursorDate, id: { lt: cursor.id } }];
    }

    const rows = await this.prisma.event.findMany({
      where,
      orderBy: [{ occurredAt: 'desc' }, { id: 'desc' }],
      take: filter.limit + 1,
    });

    const hasMore = rows.length > filter.limit;
    const items = hasMore ? rows.slice(0, filter.limit) : rows;
    const last = items[items.length - 1];
    const nextCursor = hasMore && last ? encodeCursor({ occurredAt: last.occurredAt.toISOString(), id: last.id }) : null;

    return { items, nextCursor };
  }
}
