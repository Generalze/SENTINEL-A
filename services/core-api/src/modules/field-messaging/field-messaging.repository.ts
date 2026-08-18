import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type IncidentFieldMessage, type IncidentFieldMessageRecipient } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { TIMELINE_MESSAGE_ACKNOWLEDGED, TIMELINE_MESSAGE_SENT } from './field-messaging.constants';
import type { SiteScope } from './field-messaging.types';

export type MessageWithRecipients = IncidentFieldMessage & { recipients: IncidentFieldMessageRecipient[] };

function siteScopeWhere(siteScope: SiteScope): Prisma.IncidentFieldMessageWhereInput {
  return siteScope.orgWide ? {} : { siteId: { in: siteScope.siteIds } };
}

export interface IncidentScope {
  incidentId: string;
  organisationId: string;
  siteId: string;
}

export interface SendMessageInput {
  organisationId: string;
  siteId: string;
  incidentId: string;
  senderUserId: string;
  recipientUserIds: string[];
  body: string | null;
  mediaRefs: string[];
  retentionClass: string;
  expiresAt: Date | null;
  idempotencyKey: string;
  traceId: string;
}

export type AcknowledgeResult =
  | { kind: 'acknowledged' | 'duplicate'; message: MessageWithRecipients }
  | { kind: 'not_recipient' }
  | { kind: 'conflict'; currentState: string };

const withRecipients = { recipients: true } as const;

@Injectable()
export class FieldMessagingRepository {
  constructor(@Inject(PrismaService) private readonly prisma: PrismaService) {}

  /**
   * WP-18: the incident is resolved by id WITHIN the caller's organisation, and
   * its site is returned so the service can derive scope server-side. The
   * request body never supplies organisation_id or site_id.
   */
  async findIncidentScope(organisationId: string, incidentId: string): Promise<IncidentScope | null> {
    const incident = await this.prisma.incident.findFirst({
      where: { id: incidentId, organisationId },
      select: { id: true, organisationId: true, siteId: true },
    });
    return incident ? { incidentId: incident.id, organisationId: incident.organisationId, siteId: incident.siteId } : null;
  }

  /** WP-17A precedent: the site must exist AND belong to the same organisation. */
  async siteExistsInOrganisation(organisationId: string, siteId: string): Promise<boolean> {
    const site = await this.prisma.site.findFirst({ where: { id: siteId, organisationId }, select: { id: true } });
    return site !== null;
  }

  /** Recipients must be real users in the caller's own tenant. Returns the ids that are not. */
  async unknownRecipients(organisationId: string, recipientUserIds: readonly string[]): Promise<string[]> {
    const found = await this.prisma.user.findMany({
      where: { organisationId, id: { in: [...recipientUserIds] } },
      select: { id: true },
    });
    const known = new Set(found.map((user) => user.id));
    return recipientUserIds.filter((id) => !known.has(id));
  }

  /**
   * WP-18/D6: message, immutable recipient rows, the incident timeline entry,
   * and one outbox row per recipient are written in ONE transaction. A partial
   * write would leave either an unaddressable message or a signal pointing at
   * content that does not exist.
   */
  async send(input: SendMessageInput): Promise<{ message: MessageWithRecipients; created: boolean }> {
    try {
      const created = await this.prisma.$transaction(async (tx) => {
        const message = await tx.incidentFieldMessage.create({
          data: {
            organisationId: input.organisationId,
            siteId: input.siteId,
            incidentId: input.incidentId,
            senderUserId: input.senderUserId,
            body: input.body,
            mediaRefs: input.mediaRefs,
            retentionClass: input.retentionClass,
            expiresAt: input.expiresAt,
            idempotencyKey: input.idempotencyKey,
            traceId: input.traceId,
          },
        });

        await tx.incidentFieldMessageRecipient.createMany({
          data: input.recipientUserIds.map((recipientUserId) => ({
            messageId: message.id,
            organisationId: input.organisationId,
            siteId: input.siteId,
            recipientUserId,
            deliveryState: 'REQUESTED',
          })),
        });

        // Audit link on the incident's own timeline. Deliberately records that a
        // message exists and how many may see it — never the body or media.
        await tx.incidentTimelineEntry.create({
          data: {
            incidentId: input.incidentId,
            kind: TIMELINE_MESSAGE_SENT,
            actorUserId: input.senderUserId,
            payload: {
              incident_field_message_id: message.id,
              recipient_count: input.recipientUserIds.length,
              retention_class: input.retentionClass,
              trace_id: input.traceId,
            },
          },
        });

        // One content-free signal per entitled recipient.
        await tx.incidentFieldMessageOutbox.createMany({
          data: input.recipientUserIds.map((recipientUserId) => ({
            organisationId: input.organisationId,
            siteId: input.siteId,
            recipientUserId,
            payload: {
              kind: 'incident_field_message.updated',
              incident_id: input.incidentId,
              message_id: message.id,
            },
          })),
        });

        return tx.incidentFieldMessage.findUniqueOrThrow({ where: { id: message.id }, include: withRecipients });
      });
      return { message: created, created: true };
    } catch (error) {
      if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== 'P2002') throw error;
      const existing = await this.prisma.incidentFieldMessage.findFirst({
        where: { organisationId: input.organisationId, incidentId: input.incidentId, idempotencyKey: input.idempotencyKey },
        include: withRecipients,
      });
      if (!existing) throw error;
      return { message: existing, created: false };
    }
  }

  /** Scoped read. Entitlement (sender/recipient/oversight) is decided by the service, never here. */
  async findMessage(organisationId: string, messageId: string, siteScope: SiteScope): Promise<MessageWithRecipients | null> {
    return this.prisma.incidentFieldMessage.findFirst({
      where: { id: messageId, organisationId, ...siteScopeWhere(siteScope) },
      include: withRecipients,
    });
  }

  /** Messages on one incident that the caller is entitled to as sender or named recipient. */
  async listEntitled(organisationId: string, incidentId: string, userId: string, siteScope: SiteScope): Promise<MessageWithRecipients[]> {
    return this.prisma.incidentFieldMessage.findMany({
      where: {
        organisationId,
        incidentId,
        ...siteScopeWhere(siteScope),
        OR: [{ senderUserId: userId }, { recipients: { some: { recipientUserId: userId } } }],
      },
      include: withRecipients,
      orderBy: [{ sentAt: 'desc' }, { id: 'desc' }],
      take: 200,
    });
  }

  /** Oversight listing: every message on the incident, no entitlement filter, and no recipient row is created. */
  async listForOversight(organisationId: string, incidentId: string, siteScope: SiteScope): Promise<MessageWithRecipients[]> {
    return this.prisma.incidentFieldMessage.findMany({
      where: { organisationId, incidentId, ...siteScopeWhere(siteScope) },
      include: withRecipients,
      orderBy: [{ sentAt: 'desc' }, { id: 'desc' }],
      take: 200,
    });
  }

  /**
   * Advances ONE recipient's delivery state. Acknowledgement is attributable to
   * a named recipient only; there is deliberately no path here for an oversight
   * reader, because an oversight reader has no recipient row to advance.
   */
  async acknowledge(
    organisationId: string,
    messageId: string,
    recipientUserId: string,
    idempotencyKey: string,
    siteScope: SiteScope,
    resolvePath: (from: string) => readonly string[] | null,
  ): Promise<AcknowledgeResult> {
    return this.prisma.$transaction(async (tx) => {
      const message = await tx.incidentFieldMessage.findFirst({
        where: { id: messageId, organisationId, ...siteScopeWhere(siteScope) },
        include: withRecipients,
      });
      if (!message) return { kind: 'not_recipient' };

      const recipient = message.recipients.find((row) => row.recipientUserId === recipientUserId);
      if (!recipient) return { kind: 'not_recipient' };

      const duplicate = await tx.incidentFieldMessageActionIdempotency.findUnique({
        where: {
          messageId_recipientUserId_action_idempotencyKey: {
            messageId,
            recipientUserId,
            action: 'acknowledge',
            idempotencyKey,
          },
        },
      });
      if (duplicate) return { kind: 'duplicate', message };
      if (recipient.deliveryState === 'ACKNOWLEDGED') return { kind: 'duplicate', message };

      // Section 76 has no REQUESTED -> ACKNOWLEDGED edge; the path walks
      // through DELIVERED, and every hop was validated by the caller against
      // the shared transition table. An unreachable state is refused here
      // WITHOUT mutating anything.
      const path = resolvePath(recipient.deliveryState);
      if (path === null) return { kind: 'conflict', currentState: recipient.deliveryState };

      const at = new Date();
      const passedThroughDelivered = path.includes('DELIVERED');
      await tx.incidentFieldMessageRecipient.update({
        where: { id: recipient.id },
        data: {
          deliveryState: 'ACKNOWLEDGED',
          acknowledgedAt: at,
          // The acknowledgement is the proof of delivery when none was recorded.
          deliveredAt: recipient.deliveredAt ?? (passedThroughDelivered ? at : recipient.deliveredAt),
        },
      });
      await tx.incidentFieldMessageActionIdempotency.create({
        data: { messageId, recipientUserId, action: 'acknowledge', idempotencyKey },
      });
      await tx.incidentTimelineEntry.create({
        data: {
          incidentId: message.incidentId,
          kind: TIMELINE_MESSAGE_ACKNOWLEDGED,
          actorUserId: recipientUserId,
          payload: { incident_field_message_id: messageId, acknowledged_at: at.toISOString() },
        },
      });
      await tx.incidentFieldMessageOutbox.create({
        data: {
          organisationId: message.organisationId,
          siteId: message.siteId,
          recipientUserId,
          payload: { kind: 'incident_field_message.updated', incident_id: message.incidentId, message_id: messageId },
        },
      });

      const refreshed = await tx.incidentFieldMessage.findUniqueOrThrow({ where: { id: messageId }, include: withRecipients });
      return { kind: 'acknowledged', message: refreshed };
    });
  }
}
