import type { DeviceGatewayEventType, DeviceGatewayOutcome } from './device-gateway.constants';
import type { DeviceGatewayOperationKind } from './device-gateway.envelope';

/**
 * WP-25/D25-13 — THE APPEND-ONLY GATEWAY AUDIT PAYLOAD, AS AN ALLOWLIST.
 *
 * TWO PROPERTIES, BOTH STRUCTURAL RATHER THAN PROMISED. This is
 * `device-security-audit.ts`'s discipline, applied to the first device-facing
 * boundary in Sentinel — which is exactly where the temptation to "log the
 * whole request while we debug this" is strongest.
 *
 * 1. THE PAYLOAD IS AN ALLOWLIST, NOT A FILTER.
 *
 *    Every event type is built by its OWN arm returning its OWN object
 *    literal. There is no `{ ...input }`, no `pick(input, keys)`, no generic
 *    redactor and no shared "safe fields" helper — all four are filters, and a
 *    filter fails OPEN the moment somebody adds a field to the input type. A
 *    field not written out by hand below cannot reach a gateway event at all.
 *
 * 2. WHAT MAY NEVER ENTER A PAYLOAD.
 *
 *    No raw signature. No private key — no such field exists anywhere in this
 *    module or in the frozen contracts. No session credential, bearer-like
 *    secret or authentication header. AND NO NONCE: not the device's request
 *    nonce, not the establishment nonce, not any one-shot value. There is no
 *    field for one on any arm below, and the union makes adding one a visible
 *    edit rather than an incidental spread.
 *
 *    An audit table is read by more people, for longer, than anything else in
 *    the system. A replay identity sitting in one is a replay identity that has
 *    left the security boundary.
 *
 *    DIGESTS ARE RECORDED AND VALUES ARE NOT. `payload_digest`,
 *    `statement_fingerprint` and `domain_idempotency_key` are one-way
 *    derivations that an operator can correlate against and an attacker cannot
 *    invert into a nonce or a signature. `context_id` IS recorded, precisely
 *    because it authorises nothing (D25-13).
 */

/**
 * Scalars only, deliberately — the `device-security-audit.ts` argument, quoted:
 * a nested object is where a raw blob hides, and everything D25-13 permits is a
 * scalar.
 */
export type DeviceGatewayEventPayload = Readonly<Record<string, string | number | boolean | null>>;

/** The identifiers a gateway event is filed under, AS RECORDED at the moment of the event. */
export interface DeviceGatewayEventEnvelope {
  readonly organisationId: string;
  readonly contextId: string | null;
  readonly deviceId: string | null;
  readonly actorUserId: string | null;
  readonly operationKind: DeviceGatewayOperationKind | null;
  readonly occurredAt: Date;
  readonly traceId: string;
}

/**
 * The typed input for each event, as a discriminated union.
 *
 * The union is what makes the allowlist checkable: `buildDeviceGatewayEventPayload`
 * switches on `type` and TypeScript proves every member has an arm, so a
 * seventh event type added to `DEVICE_GATEWAY_EVENT_TYPES` without a builder
 * fails to compile rather than silently writing `{}`.
 */
export type DeviceGatewayEventInput =
  | {
      readonly type: 'ESTABLISHMENT_CHALLENGE_ISSUED';
      readonly establishmentId: string;
      readonly proposedContextId: string;
      readonly siteId: string;
      readonly keyId: string;
      readonly keyVersion: number;
      readonly expiresAt: string;
      /** The registry's CURRENT effective standing at issuance. Never live authority. */
      readonly effectiveTrust: string;
    }
  | {
      readonly type: 'ESTABLISHMENT_REFUSED';
      readonly establishmentId: string | null;
      readonly proposedContextId: string | null;
      readonly siteId: string | null;
      /** The PRECISE internal reason. Richer than anything the caller was told. */
      readonly refusal: string;
      readonly contractRefusal: string | null;
    }
  | {
      readonly type: 'CONTEXT_ISSUED';
      readonly establishmentId: string;
      readonly siteId: string;
      readonly keyId: string;
      readonly keyVersion: number;
      readonly issuedAt: string;
      readonly expiresAt: string;
      readonly effectiveTrust: string;
      readonly statementFingerprint: string;
    }
  | {
      readonly type: 'OPERATION_COMMITTED';
      readonly siteId: string;
      readonly targetType: string;
      readonly targetId: string;
      readonly keyId: string;
      readonly keyVersion: number;
      readonly payloadDigest: string;
      readonly statementFingerprint: string;
      readonly domainIdempotencyKey: string;
      readonly effectiveTrust: string;
    }
  | {
      readonly type: 'OPERATION_CONVERGED';
      readonly siteId: string;
      readonly targetType: string;
      readonly targetId: string;
      readonly payloadDigest: string;
      readonly statementFingerprint: string;
      /** The stored outcome reference the retry converged ON, proved against the domain. */
      readonly storedOutcomeRef: string;
    }
  | {
      readonly type: 'OPERATION_REFUSED';
      readonly siteId: string | null;
      readonly targetType: string | null;
      readonly targetId: string | null;
      readonly payloadDigest: string | null;
      readonly refusal: string;
      readonly contractRefusal: string | null;
      readonly effectiveTrust: string | null;
    };

/** The gateway outcome each event type carries, so the two can never disagree. */
export const DEVICE_GATEWAY_EVENT_OUTCOME: Readonly<Record<DeviceGatewayEventType, DeviceGatewayOutcome>> = {
  ESTABLISHMENT_CHALLENGE_ISSUED: 'ISSUED',
  ESTABLISHMENT_REFUSED: 'REFUSED',
  CONTEXT_ISSUED: 'ISSUED',
  OPERATION_COMMITTED: 'COMMITTED',
  OPERATION_CONVERGED: 'CONVERGED',
  OPERATION_REFUSED: 'REFUSED',
};

export function buildDeviceGatewayEventPayload(input: DeviceGatewayEventInput): DeviceGatewayEventPayload {
  switch (input.type) {
    case 'ESTABLISHMENT_CHALLENGE_ISSUED':
      return {
        establishment_id: input.establishmentId,
        proposed_context_id: input.proposedContextId,
        site_id: input.siteId,
        key_id: input.keyId,
        key_version: input.keyVersion,
        expires_at: input.expiresAt,
        effective_trust: input.effectiveTrust,
      };
    case 'ESTABLISHMENT_REFUSED':
      return {
        establishment_id: input.establishmentId,
        proposed_context_id: input.proposedContextId,
        site_id: input.siteId,
        refusal: input.refusal,
        contract_refusal: input.contractRefusal,
      };
    case 'CONTEXT_ISSUED':
      return {
        establishment_id: input.establishmentId,
        site_id: input.siteId,
        key_id: input.keyId,
        key_version: input.keyVersion,
        issued_at: input.issuedAt,
        expires_at: input.expiresAt,
        effective_trust: input.effectiveTrust,
        statement_fingerprint: input.statementFingerprint,
      };
    case 'OPERATION_COMMITTED':
      return {
        site_id: input.siteId,
        target_type: input.targetType,
        target_id: input.targetId,
        key_id: input.keyId,
        key_version: input.keyVersion,
        payload_digest: input.payloadDigest,
        statement_fingerprint: input.statementFingerprint,
        domain_idempotency_key: input.domainIdempotencyKey,
        effective_trust: input.effectiveTrust,
      };
    case 'OPERATION_CONVERGED':
      return {
        site_id: input.siteId,
        target_type: input.targetType,
        target_id: input.targetId,
        payload_digest: input.payloadDigest,
        statement_fingerprint: input.statementFingerprint,
        stored_outcome_ref: input.storedOutcomeRef,
      };
    case 'OPERATION_REFUSED':
      return {
        site_id: input.siteId,
        target_type: input.targetType,
        target_id: input.targetId,
        payload_digest: input.payloadDigest,
        refusal: input.refusal,
        contract_refusal: input.contractRefusal,
        effective_trust: input.effectiveTrust,
      };
  }
}
