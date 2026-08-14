import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type Evidence as EvidenceRow, type EvidenceCustodyEvent as CustodyRow, type Event as EventRow } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import type { EvidenceListFilter } from './evidence.types';

/**
 * Append-only data access for the Evidence and EvidenceCustodyEvent
 * models. Directive WP-09: "No update/delete on either model anywhere" —
 * every method below is a pure insert or a pure read; no Prisma update or
 * delete call against either model's delegate exists anywhere in this
 * module. Enforced by evidence.append-only.spec.ts (the same source-scan
 * pattern events.append-only.spec.ts uses for the Event model) — unlike
 * Event, neither model here has any documented mutation exception.
 */
@Injectable()
export class EvidenceRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  /** Insert-only: the sole write path for a new Evidence row (original or derived). */
  async createEvidence(data: Prisma.EvidenceUncheckedCreateInput): Promise<EvidenceRow> {
    return this.prisma.evidence.create({ data });
  }

  /** Insert-only: the sole write path for a custody log line. */
  async createCustodyEvent(data: Prisma.EvidenceCustodyEventUncheckedCreateInput): Promise<CustodyRow> {
    return this.prisma.evidenceCustodyEvent.create({ data });
  }

  /** Tenant-scoped lookup — `organisationId` is part of the WHERE, not checked after the fact. */
  async findById(id: string, organisationId: string): Promise<EvidenceRow | null> {
    return this.prisma.evidence.findFirst({ where: { id, organisationId } });
  }

  async list(filter: EvidenceListFilter): Promise<EvidenceRow[]> {
    return this.prisma.evidence.findMany({
      where: {
        organisationId: filter.organisationId,
        ...(filter.incidentId ? { incidentId: filter.incidentId } : {}),
      },
      orderBy: [{ storedAt: 'desc' }, { id: 'desc' }],
      take: filter.limit,
    });
  }

  /**
   * Cross-model read for preserveEventSnapshot (deliverable 6): the Event
   * model belongs to the events module's schema file, but Prisma generates
   * one shared client for the whole database, so reading it here does not
   * touch any file in modules/events — this repository still only ever
   * writes Evidence/EvidenceCustodyEvent rows. Tenant-scoped: `eventIds`
   * belonging to another organisation are silently excluded from the
   * result, exactly like `findById` above.
   */
  async findEventsByIds(organisationId: string, eventIds: string[]): Promise<EventRow[]> {
    if (eventIds.length === 0) return [];
    return this.prisma.event.findMany({ where: { id: { in: eventIds }, organisationId } });
  }
}
