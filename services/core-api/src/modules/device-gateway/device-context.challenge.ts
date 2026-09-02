import { canonicalDeviceJson, deviceCanonicalDigest } from '@sentinel/contracts';
import { DEVICE_GATEWAY_ESTABLISHMENT_CHALLENGE_DOMAIN } from './device-gateway.constants';

/**
 * WP-25/D25-03A — THE PRE-CONTEXT ESTABLISHMENT CHALLENGE, AS BYTES.
 *
 * THE CIRCLE THIS BREAKS
 * ----------------------
 * The frozen `DeviceRequestProof` is bound to a `context_id`, and its evaluator
 * takes an `AuthenticatedDeviceContext`. Requiring an issued context in order
 * to obtain the FIRST context cannot work. The ceremony breaks the circle
 * without a bearer bootstrap and without inventing a second cryptographic
 * domain: the server proposes a context id and a nonce from ITS OWN STATE, the
 * device signs a frozen proof whose `payload_digest` is the digest of the EXACT
 * challenge, and the server assembles an IN-MEMORY CANDIDATE context purely so
 * the frozen evaluator has something to judge.
 *
 * THIS IS NOT A SECRET, AND NOTHING MAY EVER TREAT IT AS ONE
 * ---------------------------------------------------------
 * Steal every field below — `establishment_id`, `proposed_context_id`, the
 * server `nonce`, the device id, the key id, the key version, the site — and
 * you have ZERO device authority. Issuance still requires BOTH the registered
 * private key, which never leaves the hardware and is stored nowhere in
 * Sentinel, AND the independent current human session, which no amount of
 * challenge material can manufacture. The Crucible proves exactly this: a test
 * that replays every stolen field without the key gets nothing.
 *
 * It is one-shot and short-lived because a one-shot identity is CHEAPER TO
 * REASON ABOUT than a secret — not because it is one. A ceremony usable exactly
 * once has no interesting theft story; a secret does.
 *
 * THE DEVICE NEVER CHOOSES WHAT IT IS ASKED TO SIGN. Every field is
 * server-generated or server-resolved, and there is no parameter in the
 * establishment request through which a caller could propose the nonce, the
 * proposed context id, the key or the key version.
 */

/** The challenge as the server issues it and as the device must hash it. */
export interface DeviceContextEstablishmentChallengeView {
  readonly schema_version: 1;
  readonly establishment_id: string;
  readonly proposed_context_id: string;
  readonly organisation_id: string;
  readonly actor_user_id: string;
  readonly device_id: string;
  readonly site_id: string;
  readonly key_id: string;
  readonly key_version: number;
  readonly nonce: string;
  readonly issued_at: string;
  readonly expires_at: string;
}

/**
 * One object literal feeds both the canonical form and the digest — the same
 * rule the operation envelope and the frozen request-proof statement follow,
 * for the same reason: two literals drift, and a drift would let a signature
 * cover something the server verified a different digest of.
 *
 * Every field is listed rather than spread, so what the device signs is legible
 * in one place and a field added to the challenge cannot slip into the signed
 * bytes without somebody deciding it should be there.
 */
function establishmentChallengeStatementObject(challenge: DeviceContextEstablishmentChallengeView): Record<string, unknown> {
  return {
    domain: DEVICE_GATEWAY_ESTABLISHMENT_CHALLENGE_DOMAIN,
    schema_version: challenge.schema_version,
    establishment_id: challenge.establishment_id,
    proposed_context_id: challenge.proposed_context_id,
    organisation_id: challenge.organisation_id,
    actor_user_id: challenge.actor_user_id,
    device_id: challenge.device_id,
    site_id: challenge.site_id,
    key_id: challenge.key_id,
    key_version: challenge.key_version,
    nonce: challenge.nonce,
    issued_at: challenge.issued_at,
    expires_at: challenge.expires_at,
  };
}

export function canonicalDeviceContextEstablishmentChallenge(challenge: DeviceContextEstablishmentChallengeView): string {
  return canonicalDeviceJson(establishmentChallengeStatementObject(challenge));
}

/** The value a conforming device puts in `DeviceRequestProof.payload_digest`. */
export function deviceContextEstablishmentChallengeDigest(challenge: DeviceContextEstablishmentChallengeView): string {
  return deviceCanonicalDigest(establishmentChallengeStatementObject(challenge));
}
