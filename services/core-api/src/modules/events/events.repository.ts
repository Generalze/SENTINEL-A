import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type Event as EventRow } from '@prisma/client';
import type { NormalisedEvent } from '@sentinel/contracts';
import { PrismaService } from '../../prisma/prisma.service';
import { mapNormalisedEventToRow } from './events.mapper';
import { decodeCursor, encodeCursor } from './pagination.util';
import type { EventsListFilter } from './events.types';

const UNIQUE_CONSTRAINT_VIOLATION = 'P2002';

/** True when `error` is the unique-constraint violation on `idempotency_key`. */
export function isIdempotencyKeyConflict(error: unknown): boolean {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== UNIQUE_CONSTRAINT_VIOLATION) {
    return false;
  }
  const target = error.meta?.target;
  return Array.isArray(target) ? target.includes('idempotency_key') : target === 'idempotency_key';
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

  async findByIdempotencyKey(key: string): Promise<EventRow | null> {
    return this.prisma.event.findUnique({ where: { idempotencyKey: key } });
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
      where: { publishedAt: null, createdAt: { lt: cutoff } },
      orderBy: { createdAt: 'asc' },
      take: limit,
    });
  }

  async list(filter: EventsListFilter): Promise<{ items: EventRow[]; nextCursor: string | null }> {
    const where: Prisma.EventWhereInput = {
      organisationId: filter.organisationId,
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
