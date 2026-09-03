/**
 * WP-27 — the v2 device-action module's own named values.
 *
 * WHAT IS **NOT** HERE, AND WHY THAT MATTERS MORE THAN WHAT IS
 * ------------------------------------------------------------
 * There is no freshness ceiling, no trust table, no profile string and no
 * domain separator in this file. Every one of those is a FROZEN CONTRACT VALUE
 * imported from `@sentinel/contracts` at its use site:
 *
 *   MAX_WHISPER_RECOGNITION_AGE_MS / _FUTURE_SKEW_MS   whisper.ts (v1, frozen)
 *   DEVICE_PURPOSE_PERMITTED_TRUST                     device-context.ts
 *   WHISPER_DEVICE_ACTION_V2_PROFILE                   whisper-device-action-v2.ts
 *   WHISPER_DEVICE_ACTION_V2_DOMAIN                    whisper-device-action-v2.ts
 *
 * D25-12's rule, restated for WP-27: this module introduces no second opinion
 * about any of them, and the cheapest way to acquire one is to copy a value
 * into a service "for readability" and then edit the copy.
 */

/**
 * The `ceremony` label WP-27 spends Shield's ONE anti-replay store under.
 *
 * D24-11/D25-10: there is no second replay subsystem and no new table.
 * `DeviceReplayService` already owns the enforced
 * `(organisation_id, replay_identity_digest)` key, the compared-not-keyed
 * statement fingerprint, the stored outcome reference a duplicate converges on,
 * and the rule that a consumed identity is never deleted.
 *
 * `ceremony` is A LABEL FOR OPERATORS and is deliberately NOT part of the
 * uniqueness — two ceremonies must never be able to spend the same one-shot
 * identity by disagreeing about what to call it. It is distinct from
 * `GATEWAY_OPERATION` because a device-action statement and the request proof
 * that carried it are two different one-shot identities with two different
 * lifetimes, and an operator investigating one must not be reading rows from
 * the other.
 */
export const WHISPER_DEVICE_ACTION_V2_CEREMONY = 'WHISPER_DEVICE_ACTION_V2';

/**
 * The §62 action the CURRENT human actor must hold, quoted from
 * `identity/roles.ts` rather than re-decided here.
 *
 * W21-12 made this a capability of its own precisely so that reading a signal
 * roster, editing a configuration, approving an activation and FIRING the thing
 * are four different powers. `field.operative` holds it and `admin` does not.
 */
export const ACTION_WHISPER_DEVICE_ACTION_INVOKE = 'whisper.device-action.invoke';
