import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { canTransition, IncidentFieldMessageSchema, MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES, MAX_INCIDENT_FIELD_MESSAGE_MEDIA_REFS } from '@sentinel/contracts';
import { z } from 'zod';
import type { Principal } from '../../common/security/principal';
import { acknowledgementPath } from './field-messaging.constants';
import { mapMessage } from './field-messaging.mapper';
import { FieldMessagingRepository, type MessageWithRecipients } from './field-messaging.repository';
import type { IncidentFieldMessageView, SiteScope } from './field-messaging.types';

/**
 * WP-18 send input.
 *
 * `organisation_id` and `site_id` are deliberately ABSENT and `.strict()`
 * rejects them: scope is derived server-side from the incident, so a caller
 * cannot choose the tenant or site a message is filed under.
 */
const SendMessageInputSchema = z
  .object({
    recipient_user_ids: z.array(z.string().min(1).max(256)).min(1).max(128),
    body: z.string().min(1).nullable().optional(),
    media_refs: z.array(z.string().min(1).max(512)).max(MAX_INCIDENT_FIELD_MESSAGE_MEDIA_REFS).optional(),
    retention_class: z.string().min(1).max(128),
    expires_at: z.string().datetime().nullable().optional(),
    idempotency_key: z.string().min(1).max(256),
    trace_id: z.string().min(1).max(256),
  })
  .strict();
export type SendMessageInput = z.infer<typeof SendMessageInputSchema>;

const AcknowledgeInputSchema = z.object({ idempotency_key: z.string().min(1).max(256) }).strict();
export type AcknowledgeInput = z.infer<typeof AcknowledgeInputSchema>;

function parseOrBadRequest<T>(schema: z.ZodSchema<T>, raw: unknown): T {
  const parsed = schema.safeParse(raw);
  if (!parsed.success) throw new BadRequestException({ message: parsed.error.issues.map((issue) => issue.message) });
  return parsed.data;
}

function siteAllowed(siteScope: SiteScope, siteId: string): boolean {
  return siteScope.orgWide || siteScope.siteIds.includes(siteId);
}

@Injectable()
export class FieldMessagingService {
  private readonly logger = new Logger(FieldMessagingService.name);

  constructor(@Inject(FieldMessagingRepository) private readonly repository: FieldMessagingRepository) {}

  parseSend(raw: unknown): SendMessageInput {
    return parseOrBadRequest(SendMessageInputSchema, raw);
  }

  parseAcknowledge(raw: unknown): AcknowledgeInput {
    return parseOrBadRequest(AcknowledgeInputSchema, raw);
  }

  /**
   * Resolves the incident and derives its scope, applying the WP-18 chain up to
   * incident scope. Returns the server-derived site.
   *
   * Two distinct failures, deliberately shaped differently:
   *  - the incident is not in the caller's tenant/site scope -> 404, so the
   *    endpoint cannot be used to discover that an incident id exists;
   *  - the incident is real but its site does not resolve to an operational
   *    Site -> generic 409. It does NOT say whether the site is missing or
   *    belongs to another tenant; the integrity problem is logged internally
   *    against the trace id instead.
   */
  private async resolveIncidentScope(principal: Principal, siteScope: SiteScope, incidentId: string, traceId: string): Promise<string> {
    const incident = await this.repository.findIncidentScope(principal.organisation_id, incidentId);
    if (!incident) throw new NotFoundException('Incident not found');
    if (!siteAllowed(siteScope, incident.siteId)) throw new NotFoundException('Incident not found');

    if (!(await this.repository.siteExistsInOrganisation(principal.organisation_id, incident.siteId))) {
      this.logger.error(
        `Field messaging integrity: incident ${incidentId} (organisation ${principal.organisation_id}) names site ${incident.siteId}, which does not resolve to an operational Site in that organisation (trace_id=${traceId})`,
      );
      throw new ConflictException('Incident is not eligible for Field messaging');
    }
    return incident.siteId;
  }

  async send(principal: Principal, siteScope: SiteScope, incidentId: string, input: SendMessageInput): Promise<IncidentFieldMessageView> {
    const siteId = await this.resolveIncidentScope(principal, siteScope, incidentId, input.trace_id);

    const body = input.body ?? null;
    const mediaRefs = input.media_refs ?? [];
    if (body === null && mediaRefs.length === 0) throw new BadRequestException('a message requires body or media_refs');
    if (body !== null && Buffer.byteLength(body, 'utf8') > MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES) {
      throw new BadRequestException(`body must be at most ${MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES} bytes`);
    }

    const recipientUserIds = [...new Set(input.recipient_user_ids)];
    if (recipientUserIds.length !== input.recipient_user_ids.length) throw new BadRequestException('recipient_user_ids must be unique');

    const unknown = await this.repository.unknownRecipients(principal.organisation_id, recipientUserIds);
    // Never echo which ids were unknown: that would turn send into a user
    // directory probe across the tenant boundary.
    if (unknown.length > 0) throw new BadRequestException('one or more recipients are not users in this organisation');

    const expiresAt = input.expires_at ? new Date(input.expires_at) : null;
    const sentAt = new Date();
    if (expiresAt !== null && expiresAt < sentAt) throw new BadRequestException('expires_at must be >= sent_at');

    const result = await this.repository.send({
      organisationId: principal.organisation_id,
      siteId,
      incidentId,
      senderUserId: principal.user.id,
      recipientUserIds,
      body,
      mediaRefs,
      retentionClass: input.retention_class,
      expiresAt,
      idempotencyKey: input.idempotency_key,
      traceId: input.trace_id,
    });

    this.assertContract(result.message);
    return mapMessage(result.message);
  }

  /**
   * Sender/recipient read. A caller who is neither gets 404 rather than 403 —
   * the recipient set of a message is itself need-to-know, so the endpoint must
   * not confirm that the message exists.
   */
  async readEntitled(principal: Principal, siteScope: SiteScope, messageId: string): Promise<IncidentFieldMessageView> {
    const message = await this.repository.findMessage(principal.organisation_id, messageId, siteScope);
    if (!message || !this.isEntitled(message, principal.user.id)) throw new NotFoundException('Message not found');
    return mapMessage(message);
  }

  async listEntitled(principal: Principal, siteScope: SiteScope, incidentId: string): Promise<IncidentFieldMessageView[]> {
    const rows = await this.repository.listEntitled(principal.organisation_id, incidentId, principal.user.id, siteScope);
    return rows.map(mapMessage);
  }

  /**
   * Command oversight read. Reached only through the dedicated
   * `incident.field-message.oversight.read` route, never by widening the
   * recipient guard, and it creates no recipient row and no delivery state.
   */
  async readForOversight(principal: Principal, siteScope: SiteScope, messageId: string): Promise<IncidentFieldMessageView> {
    const message = await this.repository.findMessage(principal.organisation_id, messageId, siteScope);
    if (!message) throw new NotFoundException('Message not found');
    return mapMessage(message);
  }

  async listForOversight(principal: Principal, siteScope: SiteScope, incidentId: string): Promise<IncidentFieldMessageView[]> {
    const rows = await this.repository.listForOversight(principal.organisation_id, incidentId, siteScope);
    return rows.map(mapMessage);
  }

  /** Only a named recipient may acknowledge, and only for their own delivery row. */
  async acknowledge(principal: Principal, siteScope: SiteScope, messageId: string, input: AcknowledgeInput): Promise<IncidentFieldMessageView> {
    const result = await this.repository.acknowledge(
      principal.organisation_id,
      messageId,
      principal.user.id,
      input.idempotency_key,
      siteScope,
      (from) => acknowledgementPath(from, (a, b) => canTransition(a as Parameters<typeof canTransition>[0], b as Parameters<typeof canTransition>[1])),
    );

    if (result.kind === 'not_recipient') throw new NotFoundException('Message not found');
    if (result.kind === 'conflict') throw new ConflictException(`Delivery state is ${result.currentState}`);
    return mapMessage(result.message);
  }

  private isEntitled(message: MessageWithRecipients, userId: string): boolean {
    return message.senderUserId === userId || message.recipients.some((row) => row.recipientUserId === userId);
  }

  /** Round-trips the persisted row through the WP-15 contract before it leaves the service. */
  private assertContract(message: MessageWithRecipients): void {
    IncidentFieldMessageSchema.parse({
      schema_version: 1,
      incident_field_message_id: message.id,
      organisation_id: message.organisationId,
      site_id: message.siteId,
      incident_id: message.incidentId,
      sender_user_id: message.senderUserId,
      recipient_user_ids: message.recipients.map((row) => row.recipientUserId),
      body: message.body,
      media_refs: message.mediaRefs,
      // Message-level delivery is the aggregate view; per-recipient state is
      // authoritative and lives on the recipient rows.
      delivery_state: 'REQUESTED',
      retention_class: message.retentionClass,
      sent_at: message.sentAt.toISOString(),
      expires_at: message.expiresAt?.toISOString() ?? null,
      trace_id: message.traceId,
    });
  }
}

/** Re-exported so the controller can keep its guard imports in one place. */
export { ForbiddenException };
