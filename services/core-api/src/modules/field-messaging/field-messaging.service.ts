import { BadRequestException, ConflictException, ForbiddenException, Inject, Injectable, Logger, NotFoundException } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import { IncidentFieldMessageSchema, MAX_INCIDENT_FIELD_MESSAGE_BODY_BYTES, MAX_INCIDENT_FIELD_MESSAGE_MEDIA_REFS } from '@sentinel/contracts';
import { z } from 'zod';
import type { Principal } from '../../common/security/principal';
import { ACKNOWLEDGE_REQUIRES_STATE, ACTION_MESSAGE_SEND } from './field-messaging.constants';
import { isEligibleRecipient, isEligibleSender } from './field-messaging.eligibility';
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

/**
 * WP-25/D25-16: forwards the composition transaction ONLY when there is one.
 *
 * Passing an explicit `undefined` would be semantically identical, and that is
 * not the standard this seam is held to: an existing human caller must reach
 * the repository with EXACTLY the arguments it always did, so "existing
 * callers are unchanged" is true at the call boundary and not merely true in
 * effect.
 */
function txArg(tx?: Prisma.TransactionClient): [] | [Prisma.TransactionClient] {
  return tx === undefined ? [] : [tx];
}

/**
 * WP-20 Checkpoint B integration correction: a stand-in for the message id
 * while the aggregate size is measured BEFORE the row exists. It is exactly
 * uuid-length, so the measurement matches what the real id will serialize to.
 */
const AGGREGATE_SIZE_PROBE_ID = '00000000-0000-0000-0000-000000000000';

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

    // WP-18/C8-03. Same-tenant membership is not sufficient for either side.
    // One query loads the facts for the sender and every proposed recipient.
    const facts = await this.repository.loadEligibilityFacts(principal.organisation_id, siteId, incidentId, [
      principal.user.id,
      ...recipientUserIds,
    ]);

    // The sender must be eligible for THIS incident. A site-scoped operative
    // must not be able to inject into every incident at their site.
    const senderFacts = facts.get(principal.user.id);
    if (
      !senderFacts ||
      !isEligibleSender({ roles: senderFacts.roles, siteId, hasOperationalAssignment: senderFacts.hasOperationalAssignment }, ACTION_MESSAGE_SEND)
    ) {
      throw new ForbiddenException('Not permitted to send on this incident');
    }

    // Every named recipient must be eligible. One indistinguishable failure for
    // all causes — nonexistent, foreign tenant, wrong site, role without
    // field.message.read, unassigned operative, terminal assignment — so the
    // endpoint cannot be used to probe users, roles, or assignments.
    const ineligible = recipientUserIds.filter((id) => {
      const recipient = facts.get(id);
      return !recipient || !isEligibleRecipient({ roles: recipient.roles, siteId, hasOperationalAssignment: recipient.hasOperationalAssignment });
    });
    if (ineligible.length > 0) throw new BadRequestException('one or more recipients are not eligible for this incident');

    const expiresAt = input.expires_at ? new Date(input.expires_at) : null;
    const sentAt = new Date();
    if (expiresAt !== null && expiresAt < sentAt) throw new BadRequestException('expires_at must be >= sent_at');

    // WP-20 Checkpoint B integration correction: aggregate size must fail
    // BEFORE the durable transaction. Every individual bound is already
    // checked above — recipient count and uniqueness, media-ref count, body
    // bytes — so the only remaining way for `assertContract` to fail is the
    // CANONICAL AGGREGATE size, and it used to fail AFTER repository.send()
    // had already committed the message, its recipient rows, the incident
    // timeline entry and the outbox row. A refused aggregate must leave ZERO
    // rows behind. Re-using IncidentFieldMessageSchema itself, rather than a
    // local byte count, is what stops this gate drifting from the contract it
    // enforces: the size rule lives in exactly one place.
    const candidate = IncidentFieldMessageSchema.safeParse({
      schema_version: 1,
      incident_field_message_id: AGGREGATE_SIZE_PROBE_ID,
      organisation_id: principal.organisation_id,
      site_id: siteId,
      incident_id: incidentId,
      sender_user_id: principal.user.id,
      recipient_user_ids: recipientUserIds,
      body,
      media_refs: mediaRefs,
      delivery_state: 'REQUESTED',
      retention_class: input.retention_class,
      sent_at: sentAt.toISOString(),
      expires_at: expiresAt?.toISOString() ?? null,
      trace_id: input.trace_id,
    });
    if (!candidate.success) {
      // The aggregate-size rule is the only issue the contract raises at the
      // ROOT path; every other superRefine issue names a field. The fallback
      // branch keeps this fail-closed rather than letting an unexpected
      // contract failure fall through to the write it was meant to precede.
      const oversized = candidate.error.issues.some((issue) => issue.path.length === 0 && issue.code === z.ZodIssueCode.custom);
      throw new BadRequestException(oversized ? 'message exceeds the canonical serialized size limit' : 'message failed canonical contract validation');
    }

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

  /**
   * Only a named recipient may acknowledge, and only for their own delivery row.
   *
   * WP-25/D25-16: `tx` is an internal composition seam, not a public API
   * concern. An orchestrator that must commit this acknowledgement together
   * with its own rows supplies its transaction; the recipiency check, the
   * C8-01 DELIVERED precondition, the idempotency identity and the returned
   * view are unchanged, and Field Messaging remains the only implementation of
   * acknowledgement semantics. Existing human callers pass nothing.
   */
  async acknowledge(
    principal: Principal,
    siteScope: SiteScope,
    messageId: string,
    input: AcknowledgeInput,
    tx?: Prisma.TransactionClient,
  ): Promise<IncidentFieldMessageView> {
    const result = await this.repository.acknowledge(
      principal.organisation_id,
      messageId,
      principal.user.id,
      input.idempotency_key,
      siteScope,
      ACKNOWLEDGE_REQUIRES_STATE,
      ...txArg(tx),
    );

    if (result.kind === 'not_recipient') throw new NotFoundException('Message not found');
    if (result.kind === 'conflict') throw new ConflictException(`Delivery state is ${result.currentState}`);
    return mapMessage(result.message);
  }

  /**
   * WP-20/B10-02 idempotency recovery probe — pure evidence lookup, no mutable
   * eligibility re-evaluation, actor-scoped per the C8-05 lesson.
   *
   * The offline replay executor asks THIS domain whether the send identity it
   * derived has already committed. It cannot learn that by calling `send`
   * again: `send` re-runs sender eligibility, incident scope resolution and
   * the aggregate bound BEFORE the repository's idempotency layer, so an
   * eligibility that drifted since the first attempt would turn an effect that
   * already committed into a REJECTED receipt — false history the device would
   * then treat as final.
   *
   * The sender is `principal.user.id` and the tenant `principal.organisation_id`,
   * matching the send-idempotency identity exactly (C8-05).
   */
  async probeSendEvidence(
    principal: Principal,
    incidentId: string,
    idempotencyKey: string,
  ): Promise<{ id: string; incidentId: string; recipientCount: number } | null> {
    return this.repository.findSendEvidence(principal.organisation_id, incidentId, principal.user.id, idempotencyKey);
  }

  /**
   * WP-20/B10-02 idempotency recovery probe — pure evidence lookup, no mutable
   * eligibility re-evaluation, actor-scoped per the C8-05 lesson.
   *
   * Same argument as `probeSendEvidence`: `acknowledge` re-checks recipiency
   * and the C8-01 DELIVERED precondition before reaching its idempotency row,
   * so a re-run cannot distinguish "never happened" from "already happened and
   * the state moved on". The evidence row can.
   */
  async probeAcknowledgeEvidence(principal: Principal, messageId: string, idempotencyKey: string): Promise<boolean> {
    return this.repository.findAcknowledgeEvidence(principal.organisation_id, messageId, principal.user.id, idempotencyKey);
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
