/**
 * WP-25 Authenticated Device Gateway — the module's own named values.
 *
 * WHAT IS **NOT** HERE, AND WHY THAT MATTERS MORE THAN WHAT IS
 * ------------------------------------------------------------
 * `DEVICE_CONTEXT_MAX_LIFETIME_MS` (300_000), `DEVICE_REQUEST_PROOF_MAX_AGE_MS`
 * (60_000), `DEVICE_REQUEST_PROOF_MAX_FUTURE_SKEW_MS` (5_000) and
 * `DEVICE_PURPOSE_PERMITTED_TRUST` are FROZEN CONTRACT VALUES. They are
 * imported from `@sentinel/contracts` at every use site and are deliberately
 * not restated, aliased or wrapped anywhere in this module. D25-12 is explicit
 * that WP-25 introduces no second freshness opinion, and the cheapest way to
 * acquire one is to copy a number into a service "for readability" and then
 * edit the copy.
 *
 * Exactly ONE new ceiling is approved by D25-12, and it is below. It has its
 * own name and its own tests precisely so that it can never be mistaken for,
 * or quietly conflated with, the 60-second request-proof freshness bound.
 */

/**
 * D25-12: how long a pre-context establishment challenge stands.
 *
 * Two minutes is the window between a human session asking for an
 * establishment and the device in front of that human answering it. It is NOT
 * a freshness bound on the signed proof — the proof carries its own frozen
 * 60-second ceiling, judged separately — and raising this one would not
 * lengthen the other by a millisecond.
 *
 * Expiry is evaluated AT REQUEST TIME. There is no sweeper, no cron and no
 * background scheduler anywhere in this module: D25-08 carries the WP-24
 * live-suite contention forward as an explicit constraint against adding one,
 * and an expiry that is a comparison rather than a job cannot drift, cannot
 * race the request it is meant to bound, and cannot fail silently at 3am.
 */
export const DEVICE_CONTEXT_ESTABLISHMENT_MAX_AGE_MS = 120_000;

/**
 * The `ceremony` labels WP-25 spends Shield's ONE anti-replay store under.
 *
 * D25-10/D24-11: there is no second replay subsystem. `DeviceReplayService`
 * already owns the enforced `(organisation_id, replay_identity_digest)` key,
 * the compared-not-keyed statement fingerprint, the stored outcome reference a
 * duplicate converges on, and the rule that a consumed identity is never
 * deleted. `ceremony` is a LABEL FOR OPERATORS and is deliberately NOT part of
 * the uniqueness — two ceremonies must never be able to spend the same
 * one-shot identity by disagreeing about what to call it.
 */
export const DEVICE_GATEWAY_ESTABLISHMENT_CEREMONY = 'CONTEXT_ESTABLISHMENT';
export const DEVICE_GATEWAY_OPERATION_CEREMONY = 'GATEWAY_OPERATION';

/**
 * Domain separator for the establishment challenge digest.
 *
 * The device signs `payload_digest = digest of the EXACT challenge`, so the
 * challenge needs one canonical byte form. It is domain-tagged and distinct
 * from the operation envelope's tag for the reason `device-context.ts` gives
 * for keeping the request-proof domain distinct from Whisper's: a signature
 * minted over one statement must never verify as the other, and a shared tag
 * makes that possible the moment two statements happen to share a shape.
 */
export const DEVICE_GATEWAY_ESTABLISHMENT_CHALLENGE_DOMAIN = 'sentinel.wp25.device-gateway.establishment-challenge.v1';

/** Domain separator for the canonical typed operation envelope (D25-11). */
export const DEVICE_GATEWAY_OPERATION_ENVELOPE_DOMAIN = 'sentinel.wp25.device-gateway.operation-envelope.v1';

/**
 * D25-16B: the domain separator for the SERVER-DERIVED downstream idempotency
 * identity. Spelled exactly as the directive spells it.
 */
export const DEVICE_GATEWAY_DOMAIN_IDEMPOTENCY_DOMAIN = 'WP25-GATEWAY-DOMAIN-IDEMPOTENCY-v1';

/** The number of random bytes in a server-generated establishment nonce. */
export const DEVICE_GATEWAY_ESTABLISHMENT_NONCE_BYTES = 32;

/**
 * The event vocabulary of `DeviceGatewayOperationEvent.event_type`.
 *
 * TEXT in the database and a frozen tuple here, for the reason
 * `device-gateway.prisma` states: the vocabulary is owned by reviewable code,
 * not by a Postgres type whose every addition would be a migration.
 */
export const DEVICE_GATEWAY_EVENT_TYPES = [
  'ESTABLISHMENT_CHALLENGE_ISSUED',
  'ESTABLISHMENT_REFUSED',
  'CONTEXT_ISSUED',
  'OPERATION_COMMITTED',
  'OPERATION_CONVERGED',
  'OPERATION_REFUSED',
] as const;
export type DeviceGatewayEventType = (typeof DEVICE_GATEWAY_EVENT_TYPES)[number];

/** The gateway's own outcome vocabulary for `DeviceGatewayOperationEvent.outcome`. */
export const DEVICE_GATEWAY_OUTCOMES = ['ISSUED', 'COMMITTED', 'CONVERGED', 'REFUSED', 'CONFLICT'] as const;
export type DeviceGatewayOutcome = (typeof DEVICE_GATEWAY_OUTCOMES)[number];
