import { canonicalDeviceJson, deviceCanonicalDigest } from '@sentinel/contracts';
import { DEVICE_GATEWAY_DOMAIN_IDEMPOTENCY_DOMAIN } from './device-gateway.constants';
import type { DeviceGatewayOperationKind, DeviceGatewayTargetType } from './device-gateway.envelope';

/**
 * WP-25/D25-16B — THE DOWNSTREAM IDEMPOTENCY IDENTITY IS SERVER-DERIVED.
 *
 * THE DEFECT THIS CLOSES
 * ----------------------
 * Every approved domain surface takes an `idempotency_key` from its caller. If
 * the gateway forwarded one the DEVICE chose, a device could present a gateway
 * replay identity of A and a domain idempotency key of B. Two consequences,
 * both fatal:
 *
 *   * two distinct security identities could COLLIDE at the domain layer — one
 *     signed operation converging onto another's downstream row; and
 *   * one signed operation could be represented by unrelated downstream
 *     identities, so the gateway's replay decision and the domain's duplicate
 *     decision would be about different things.
 *
 * So the device never gets a second idempotency namespace. The key is derived
 * here, under its OWN domain separator, over the full identity of the signed
 * operation — and there is no parameter anywhere in this module through which
 * a caller could supply one.
 *
 * THE TWO PROPERTIES, STATED AS THE DIRECTIVE STATES THEM
 * ------------------------------------------------------
 *     same signed operation      -> same downstream identity
 *     different signed semantics -> different downstream identity
 *
 * The first holds because every input is a fact of the signed request and none
 * is a clock, a counter or a random value: a retry of the SAME proof derives
 * the same key, which is what lets the domain's own idempotency row be the
 * thing an EXACT_DUPLICATE converges on. The second holds because
 * `payload_digest` is in the input — a device that changes what it is asking
 * for changes the digest, changes this key, and is refused at the gateway
 * anyway as REUSED_WITH_CHANGED_SEMANTICS rather than quietly acquiring a
 * fresh downstream slot.
 *
 * WHY THE NONCE IS IN IT. Without the nonce, two genuinely distinct
 * operations that happened to have identical semantics — the same operative,
 * the same site, the same state, the same second — would derive one downstream
 * key and the second would converge on the first. The nonce is what makes the
 * downstream identity as one-shot as the gateway identity it accompanies.
 *
 * WHY IT IS LOWERCASE SHA-256 HEX. 64 characters, which fits inside every
 * existing 256-character domain `idempotency_key` bound without truncation —
 * and truncating a security identity to fit a column is how two identities
 * become one.
 *
 * CANONICALISATION IS THE CONTRACT'S (C11-01). Delimiter-joining these values
 * would be unsound: `organisation_id` and every other field is a caller-visible
 * string that may itself contain the delimiter, so `"a\nb" + "c"` and
 * `"a" + "b\nc"` would produce identical bytes and one key would serve two
 * different identities.
 */
export interface DeviceGatewayDomainIdempotencyInput {
  readonly organisationId: string;
  readonly contextId: string;
  readonly actorUserId: string;
  readonly deviceId: string;
  readonly keyId: string;
  readonly keyVersion: number;
  readonly operationKind: DeviceGatewayOperationKind;
  readonly targetType: DeviceGatewayTargetType;
  readonly targetId: string;
  /** The one-shot nonce from the device's own request proof. */
  readonly deviceNonce: string;
  /** The digest of the canonical typed envelope (D25-11). */
  readonly payloadDigest: string;
}

/**
 * One object literal feeds both the canonical form and the digest, for the
 * same reason the envelope has one: a second literal is a second definition of
 * the identity, and the two would eventually disagree.
 */
function domainIdempotencyStatementObject(input: DeviceGatewayDomainIdempotencyInput): Record<string, unknown> {
  return {
    domain: DEVICE_GATEWAY_DOMAIN_IDEMPOTENCY_DOMAIN,
    organisation_id: input.organisationId,
    context_id: input.contextId,
    actor_user_id: input.actorUserId,
    device_id: input.deviceId,
    key_id: input.keyId,
    key_version: input.keyVersion,
    operation_kind: input.operationKind,
    target_type: input.targetType,
    target_id: input.targetId,
    device_nonce: input.deviceNonce,
    payload_digest: input.payloadDigest,
  };
}

/** The canonical statement, exposed so a test can assert on the bytes rather than the hash. */
export function canonicalDeviceGatewayDomainIdempotencyStatement(input: DeviceGatewayDomainIdempotencyInput): string {
  return canonicalDeviceJson(domainIdempotencyStatementObject(input));
}

/** Lowercase SHA-256 hex. The value handed to the domain service as its `idempotency_key`. */
export function deviceGatewayDomainIdempotencyKey(input: DeviceGatewayDomainIdempotencyInput): string {
  return deviceCanonicalDigest(domainIdempotencyStatementObject(input));
}
