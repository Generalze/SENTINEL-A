import { Inject, Injectable } from '@nestjs/common';
import type { Prisma } from '@prisma/client';
import type { Principal } from '../../common/security/principal';
import { FieldMessagingService } from '../field-messaging/field-messaging.service';
import type { IncidentFieldMessageView } from '../field-messaging/field-messaging.types';
import { FieldService } from '../field/field.service';
import type { FieldAssignmentView, FieldOperativeStateView } from '../field/field.types';
import type { SiteScope } from '../identity/list-pagination';
import {
  DEVICE_GATEWAY_ASSIGNMENT_ACTION,
  type AssignmentSemanticPayload,
  type DeviceGatewayOperationKind,
  type FieldStateSemanticPayload,
} from './device-gateway.envelope';

/**
 * WP-25/D25-16 — THE THREE DOMAIN ADAPTERS, AND WHAT THEY ARE FORBIDDEN TO BE.
 *
 * ```text
 * Device Gateway owns   orchestration, authentication, replay,
 *                       the final cross-domain transaction
 * Field owns            Field semantics
 * Field Messaging owns  acknowledgement semantics
 * Shield owns           registry / trust semantics
 * ```
 *
 * Every method below is a CALL INTO A DOMAIN SERVICE with the gateway's
 * transaction handed in. Not one of them copies a transition rule, writes a
 * Field row, reconstructs DELIVERED -> ACKNOWLEDGED, creates a Field audit or
 * outbox row, or reaches for a repository. The eligibility rules, the
 * expected-status compare-and-set, the transition table, the C8-01 DELIVERED
 * precondition, the D25-16A recipient lock, the domain idempotency tables and
 * the outbox writes all stay exactly where they already are, and run inside the
 * gateway's transaction because that is what the D25-16 seam is for.
 *
 * ONLY ACCEPT AND DECLINE (D25-10)
 * --------------------------------
 * `start`, `complete`, `cancel` and reassignment are not refused by a check
 * somebody could delete — they are UNREACHABLE. `DEVICE_GATEWAY_ASSIGNMENT_ACTION`
 * is keyed on the two operation kinds that exist, and nothing in this module
 * constructs any other action string. The only way to add one is to add an
 * operation kind, which is a visible change to a frozen route table.
 *
 * THE AUTHORITATIVE RESULT IS VERIFIED, NOT ASSUMED (D25-02)
 * ----------------------------------------------------------
 * Each adapter returns the domain's own view AND a verdict on whether that view
 * actually shows the effect the gateway is about to attest to. A gateway that
 * recorded "committed" because a call returned without throwing would be
 * recording its own optimism. When the verdict is `false` the caller rolls the
 * whole transaction back — no outcome, no replay consumption, no audit of a
 * success that did not happen.
 */

export interface DeviceGatewayDomainCall {
  readonly kind: DeviceGatewayOperationKind;
  /** The CURRENT actor, rebuilt from live rows. Never a session. */
  readonly principal: Principal;
  /** Derived from that principal exactly as an HTTP route derives it. */
  readonly siteScope: SiteScope;
  readonly siteId: string;
  /** The Shield device id, so the domain row names the authenticated hardware. */
  readonly deviceId: string;
  readonly targetId: string;
  readonly semanticPayload: Record<string, unknown>;
  /** D25-16B: SERVER-derived. The device cannot choose it. */
  readonly domainIdempotencyKey: string;
  readonly traceId: string;
}

export interface DeviceGatewayDomainResult {
  readonly view: unknown;
  /** Whether the authoritative domain row shows the effect that was asked for. */
  readonly authoritative: boolean;
}

@Injectable()
export class DeviceGatewayDomainAdapters {
  constructor(
    @Inject(FieldService) private readonly field: FieldService,
    @Inject(FieldMessagingService) private readonly messaging: FieldMessagingService,
  ) {}

  /** Runs the domain effect inside the gateway's transaction. */
  async apply(tx: Prisma.TransactionClient, call: DeviceGatewayDomainCall): Promise<DeviceGatewayDomainResult> {
    switch (call.kind) {
      case 'FIELD_STATE_UPDATE':
        return this.recordState(tx, call);
      case 'ASSIGNMENT_ACCEPT':
      case 'ASSIGNMENT_DECLINE':
        return this.transitionAssignment(tx, call, call.kind);
      case 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE':
        return this.acknowledge(tx, call);
    }
  }

  /**
   * D25-02's convergence resolution: has the DOMAIN already committed this
   * server-derived identity?
   *
   * PURE EVIDENCE. Every branch is a read-only probe — the WP-20/B10-02 family
   * plus the state-update member WP-25 added — and none of them can cause an
   * effect. That is the whole point: proving a duplicate by re-running the
   * mutating path would CREATE the effect whose absence is the thing being
   * detected, and "unresolvable" would become impossible to observe.
   *
   * `false` means FAIL CLOSED. A stored outcome reference that cannot be proved
   * against the actual authoritative domain row never manufactures convergence.
   */
  async resolveCommitted(call: DeviceGatewayDomainCall): Promise<boolean> {
    switch (call.kind) {
      case 'FIELD_STATE_UPDATE':
        return this.field.probeStateEvidence(call.principal, {
          siteId: call.siteId,
          deviceId: call.deviceId,
          idempotencyKey: call.domainIdempotencyKey,
        });
      case 'ASSIGNMENT_ACCEPT':
      case 'ASSIGNMENT_DECLINE': {
        const evidence = await this.field.probeTransitionEvidence(
          call.principal,
          call.targetId,
          DEVICE_GATEWAY_ASSIGNMENT_ACTION[call.kind],
          call.domainIdempotencyKey,
        );
        return evidence.committed;
      }
      case 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE':
        return this.messaging.probeAcknowledgeEvidence(call.principal, call.targetId, call.domainIdempotencyKey);
    }
  }

  /**
   * The view a converged retry is answered with, read back from the domain
   * AFTER the evidence proved the effect exists.
   *
   * Read-only, through the domain's own read surfaces, so a convergence answer
   * is the domain's current truth rather than a receipt the gateway
   * reconstructed from the request that asked for it.
   */
  async readCommittedView(call: DeviceGatewayDomainCall): Promise<unknown> {
    switch (call.kind) {
      case 'FIELD_STATE_UPDATE':
        return this.field.getCurrentState(call.principal, call.siteScope, call.principal.user.id);
      case 'ASSIGNMENT_ACCEPT':
      case 'ASSIGNMENT_DECLINE':
        return this.field.getOwnAssignment(call.principal, call.siteScope, call.targetId);
      case 'INCIDENT_FIELD_MESSAGE_ACKNOWLEDGE':
        return this.messaging.readEntitled(call.principal, call.siteScope, call.targetId);
    }
  }

  /**
   * A. Field state update.
   *
   * `recordState` threads the gateway transaction to BOTH the site-existence
   * check and the write (D25-16), which matters: the check runs before the
   * repository's own transaction on the human path, so on the orchestrated path
   * the two must share one transaction or the check-to-commit gap is a real
   * race.
   */
  private async recordState(tx: Prisma.TransactionClient, call: DeviceGatewayDomainCall): Promise<DeviceGatewayDomainResult> {
    const payload = call.semanticPayload as unknown as FieldStateSemanticPayload;
    const view = (await this.field.recordState(
      call.principal,
      call.siteScope,
      {
        site_id: call.siteId,
        device_id: call.deviceId,
        state: payload.state,
        location: payload.location,
        source_at: payload.source_at,
        freshness_ms: payload.freshness_ms,
        idempotency_key: call.domainIdempotencyKey,
        trace_id: call.traceId,
      },
      tx,
    )) as FieldOperativeStateView;

    return {
      view,
      authoritative:
        view.site_id === call.siteId &&
        view.user_id === call.principal.user.id &&
        view.device_id === call.deviceId &&
        view.state === payload.state,
    };
  }

  /** B. Assignment acknowledgement — ACCEPT and DECLINE, and nothing else. */
  private async transitionAssignment(
    tx: Prisma.TransactionClient,
    call: DeviceGatewayDomainCall,
    kind: 'ASSIGNMENT_ACCEPT' | 'ASSIGNMENT_DECLINE',
  ): Promise<DeviceGatewayDomainResult> {
    const payload = call.semanticPayload as unknown as AssignmentSemanticPayload;
    const action = DEVICE_GATEWAY_ASSIGNMENT_ACTION[kind];
    const view = (await this.field.transitionAssignment(
      call.principal,
      call.siteScope,
      call.targetId,
      action,
      { expected_status: payload.expected_status, idempotency_key: call.domainIdempotencyKey },
      tx,
    )) as FieldAssignmentView;

    const expected = kind === 'ASSIGNMENT_ACCEPT' ? 'ACCEPTED' : 'DECLINED';
    return {
      view,
      authoritative: view.id === call.targetId && view.status === expected && view.assignee_user_id === call.principal.user.id,
    };
  }

  /**
   * C. Incident Field Message acknowledgement, DELIVERED -> ACKNOWLEDGED.
   *
   * `FieldMessagingService.acknowledge` already permits only the named
   * recipient to acknowledge their own delivery row and already preserves the
   * delivery-state and idempotency behaviour, so a second Delivery
   * implementation is not created. The D25-16A recipient-row lock lives inside
   * it and therefore runs inside this transaction.
   */
  private async acknowledge(tx: Prisma.TransactionClient, call: DeviceGatewayDomainCall): Promise<DeviceGatewayDomainResult> {
    const view = (await this.messaging.acknowledge(
      call.principal,
      call.siteScope,
      call.targetId,
      { idempotency_key: call.domainIdempotencyKey },
      tx,
    )) as IncidentFieldMessageView;

    const recipient = view.recipients.find((row) => row.recipient_user_id === call.principal.user.id);
    return {
      view,
      authoritative: view.id === call.targetId && recipient !== undefined && recipient.delivery_state === 'ACKNOWLEDGED',
    };
  }
}
