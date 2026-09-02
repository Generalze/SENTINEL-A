import { Inject, Injectable } from '@nestjs/common';
import { Prisma, type IncidentFieldMessage, type IncidentFieldMessageRecipient } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { TIMELINE_MESSAGE_ACKNOWLEDGED, TIMELINE_MESSAGE_SENT } from './field-messaging.constants';
import { OPERATIONAL_ASSIGNMENT_STATUSES } from './field-messaging.eligibility';
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

  /**
   * WP-18/C8-03: loads exactly what the eligibility rules need for a set of
   * users — their role assignments, and whether each holds an operational Field
   * assignment for this precise organisation + site + incident.
   *
   * Users absent from the returned map do not exist in this tenant. The caller
   * must NOT tell the sender which of the two it was: distinguishing them would
   * turn send into a tenant/user/role/assignment probe.
   */
  async loadEligibilityFacts(
    organisationId: string,
    siteId: string,
    incidentId: string,
    userIds: readonly string[],
  ): Promise<Map<string, { roles: Array<{ role: string; siteId: string | null }>; hasOperationalAssignment: boolean }>> {
    const ids = [...new Set(userIds)];
    const [users, assignments] = await Promise.all([
      this.prisma.user.findMany({
        where: { organisationId, id: { in: ids } },
        select: { id: true, roles: { select: { role: true, siteId: true } } },
      }),
      this.prisma.fieldAssignment.findMany({
        where: {
          organisationId,
          siteId,
          incidentId,
          assigneeUserId: { in: ids },
          status: { in: [...OPERATIONAL_ASSIGNMENT_STATUSES] },
        },
        select: { assigneeUserId: true },
      }),
    ]);

    const assigned = new Set(assignments.map((row) => row.assigneeUserId));
    return new Map(users.map((user) => [user.id, { roles: user.roles, hasOperationalAssignment: assigned.has(user.id) }]));
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
      // C8-05: the replay lookup is sender-scoped, matching the uniqueness
      // identity. A replay may only ever return a message this same
      // authenticated sender created.
      const existing = await this.prisma.incidentFieldMessage.findFirst({
        where: {
          organisationId: input.organisationId,
          incidentId: input.incidentId,
          senderUserId: input.senderUserId,
          idempotencyKey: input.idempotencyKey,
        },
        include: withRecipients,
      });
      if (!existing) throw error;
      return { message: existing, created: false };
    }
  }

  /**
   * WP-20/B10-02 idempotency recovery probe — pure evidence lookup, no mutable
   * eligibility re-evaluation, actor-scoped per the C8-05 lesson.
   *
   * The where-clause is EXACTLY the sender-scoped one the P2002 replay lookup
   * in `send` uses, and for the same reason: the send-idempotency identity
   * includes the sender, so a probe must never surface a message this
   * authenticated sender did not create. The projection is narrower than the
   * replay's on purpose — an id, its incident, and a COUNT. No body, no media,
   * no recipient ids: this feeds a receipt snapshot that is read back on
   * reconnect (C10-11/R6).
   */
  async findSendEvidence(
    organisationId: string,
    incidentId: string,
    senderUserId: string,
    idempotencyKey: string,
  ): Promise<{ id: string; incidentId: string; recipientCount: number } | null> {
    const existing = await this.prisma.incidentFieldMessage.findFirst({
      where: { organisationId, incidentId, senderUserId, idempotencyKey },
      select: { id: true, incidentId: true, _count: { select: { recipients: true } } },
    });
    if (!existing) return null;
    return { id: existing.id, incidentId: existing.incidentId, recipientCount: existing._count.recipients };
  }

  /**
   * WP-20/B10-02 idempotency recovery probe — pure evidence lookup, no mutable
   * eligibility re-evaluation, actor-scoped per the C8-05 lesson.
   *
   * The idempotency row is written in the SAME transaction as the delivery
   * state change, so its presence proves the acknowledgement committed and its
   * absence proves it did not. `recipientUserId` binds the actor and the
   * parent message's `organisationId` binds the tenant — the row itself
   * carries no organisation column, so without that join a key from another
   * tenant's message could answer this probe.
   */
  async findAcknowledgeEvidence(organisationId: string, messageId: string, recipientUserId: string, idempotencyKey: string): Promise<boolean> {
    const evidence = await this.prisma.incidentFieldMessageActionIdempotency.findFirst({
      where: { messageId, recipientUserId, action: 'acknowledge', idempotencyKey, message: { organisationId } },
      select: { id: true },
    });
    return evidence !== null;
  }

  /**
   * WP-18/C8-01: the system-owned transport-evidence step.
   *
   * Called ONLY when a recipient's own authenticated socket has positively
   * acknowledged receipt of the notification. There is deliberately no public
   * route onto this path, and publishing to NATS does not reach it.
   *
   * Validated against the shared section 76 table (REQUESTED -> DELIVERED) and
   * a no-op for any row already past REQUESTED, so a reconnect storm cannot
   * rewrite an established state or an acknowledgement.
   */
  async recordTransportDelivery(
    organisationId: string,
    incidentId: string,
    messageId: string,
    recipientUserId: string,
    canAdvance: (from: string) => boolean,
  ): Promise<boolean> {
    // C8-06: every authoritative scope value available on the wire is bound
    // before the row may move. The organisation and recipient come from the
    // NATS subject, the incident and message from the validated payload, and
    // all four must agree with the stored row AND its parent message. This
    // closes both the missing subject-organisation binding (the C4-01
    // precedent) and a same-tenant integrity gap where a forged internal event
    // could pair a real message_id with a different incident_id.
    const recipient = await this.prisma.incidentFieldMessageRecipient.findFirst({
      where: {
        messageId,
        recipientUserId,
        organisationId,
        message: { organisationId, incidentId },
      },
      select: { id: true, deliveryState: true },
    });
    if (!recipient) return false;
    // C8-04: several sockets can race to supply the same evidence. Refuse a
    // re-stamp locally rather than trusting the caller's predicate to encode
    // it — the invariant belongs to the row, not to the call site.
    if (recipient.deliveryState === 'DELIVERED') return false;
    if (!canAdvance(recipient.deliveryState)) return false;

    const updated = await this.prisma.incidentFieldMessageRecipient.updateMany({
      where: { id: recipient.id, deliveryState: recipient.deliveryState },
      data: { deliveryState: 'DELIVERED', deliveredAt: new Date() },
    });
    return updated.count === 1;
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
   *
   * WP-25/D25-16: the optional `tx` is an internal COMPOSITION SEAM, not a
   * public API concern. The acknowledgement logic below is unchanged and this
   * remains the only implementation of DELIVERED -> ACKNOWLEDGED; the seam
   * exists so an orchestrator that must commit this transition together with
   * its own rows can supply the transaction rather than reconstruct the rule.
   * Existing human callers supply nothing and are unaffected.
   *
   * WP-25/D25-16A: the recipient row is now locked `FOR UPDATE` and its state
   * RE-READ under that lock before any decision is taken. This is NOT a new
   * delivery rule — the rule is C8-01's, unchanged — it makes the existing
   * rule SERIALIZABLE. Before, this method read the recipient through the
   * message relation, checked its state and updated, with nothing holding the
   * row: two acknowledgements carrying DIFFERENT idempotency identities could
   * both observe DELIVERED before either committed, and both would transition,
   * writing two timeline entries and two outbox rows for one transition.
   * Assignment transition has been fenced this way since WP-16; this is the
   * same fence, and the human path gets it too.
   */
  async acknowledge(
    organisationId: string,
    messageId: string,
    recipientUserId: string,
    idempotencyKey: string,
    siteScope: SiteScope,
    requiredState: string,
    tx?: Prisma.TransactionClient,
  ): Promise<AcknowledgeResult> {
    const execute = async (db: Prisma.TransactionClient): Promise<AcknowledgeResult> => {
      const message = await db.incidentFieldMessage.findFirst({
        where: { id: messageId, organisationId, ...siteScopeWhere(siteScope) },
        include: withRecipients,
      });
      if (!message) return { kind: 'not_recipient' };

      const named = message.recipients.find((row) => row.recipientUserId === recipientUserId);
      if (!named) return { kind: 'not_recipient' };

      // D25-16A: lock THIS recipient row, then re-read. Prisma's query API
      // cannot express `SELECT ... FOR UPDATE`, so the lock is raw — the same
      // technique field.repository.ts and patrol.repository.ts already use.
      // The scoped resolution above stays where it is: locking is a
      // concurrency fence, never an entitlement check, and a caller with no
      // claim on this row must still be refused by scope, not by a lock.
      await db.$queryRaw(Prisma.sql`SELECT id FROM incident_field_message_recipients WHERE id = ${named.id}::uuid FOR UPDATE`);

      // The authoritative state, read AFTER the lock. Everything below decides
      // on `locked`, never on the pre-lock read: a value observed before the
      // fence is exactly the stale read this correction exists to eliminate.
      const current = await db.incidentFieldMessage.findUniqueOrThrow({ where: { id: messageId }, include: withRecipients });
      const locked = current.recipients.find((row) => row.recipientUserId === recipientUserId);
      if (!locked) return { kind: 'not_recipient' };

      const duplicate = await db.incidentFieldMessageActionIdempotency.findUnique({
        where: {
          messageId_recipientUserId_action_idempotencyKey: {
            messageId,
            recipientUserId,
            action: 'acknowledge',
            idempotencyKey,
          },
        },
      });
      if (duplicate) return { kind: 'duplicate', message: current };
      if (locked.deliveryState === 'ACKNOWLEDGED') return { kind: 'duplicate', message: current };

      // C8-01: acknowledgement may ONLY advance a row that transport evidence
      // already moved to DELIVERED. Acknowledging a REQUESTED row is refused
      // here without mutating anything — a human acknowledgement must never
      // manufacture the transport evidence that should have preceded it.
      if (locked.deliveryState !== requiredState) return { kind: 'conflict', currentState: locked.deliveryState };

      const at = new Date();
      await db.incidentFieldMessageRecipient.update({
        where: { id: locked.id },
        // deliveredAt is deliberately NOT written here: it belongs to the
        // transport-evidence step and must keep its own timestamp.
        data: { deliveryState: 'ACKNOWLEDGED', acknowledgedAt: at },
      });
      await db.incidentFieldMessageActionIdempotency.create({
        data: { messageId, recipientUserId, action: 'acknowledge', idempotencyKey },
      });
      await db.incidentTimelineEntry.create({
        data: {
          incidentId: current.incidentId,
          kind: TIMELINE_MESSAGE_ACKNOWLEDGED,
          actorUserId: recipientUserId,
          payload: { incident_field_message_id: messageId, acknowledged_at: at.toISOString() },
        },
      });
      await db.incidentFieldMessageOutbox.create({
        data: {
          organisationId: current.organisationId,
          siteId: current.siteId,
          recipientUserId,
          payload: { kind: 'incident_field_message.updated', incident_id: current.incidentId, message_id: messageId },
        },
      });

      const refreshed = await db.incidentFieldMessage.findUniqueOrThrow({ where: { id: messageId }, include: withRecipients });
      return { kind: 'acknowledged', message: refreshed };
    };
    return tx ? execute(tx) : this.prisma.$transaction(execute);
  }
}
