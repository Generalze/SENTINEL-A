import { DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS, type DeviceSignatureProfile } from '@sentinel/contracts';

/**
 * WP-29B — EVERY SECURITY-RELEVANT EDGE CONSTANT, HARD-WIRED, IN ONE PLACE.
 *
 * WHY NONE OF THIS IS CONFIGURATION
 * ---------------------------------
 * This file is the Edge counterpart of the argument in
 * `patrol-sweep.scheduler.ts` and of the deliberate absence recorded at the
 * bottom of core-api's `env.schema.ts`. It is worth restating here because Edge
 * makes the argument sharper: Edge is a box in a wiring closet at a customer
 * site, physically reachable by more people than a datacentre, and its
 * environment file is the least-guarded surface in the whole system.
 *
 * The dividing line is a question, not a taste: DOES THIS VALUE CHANGE WHAT
 * EDGE IS WILLING TO WITNESS? If yes, it is hard-wired here and changing it is
 * a reviewed diff. If it only says who Edge is, where it points, and where it
 * writes its files, it is configuration (`config/env.schema.ts`).
 *
 * A holdover ceiling as an env var is the clearest case. Set
 * `EDGE_ANCHOR_HOLDOVER_MS=999999999` on one site's Edge and that Edge will
 * keep minting receipts from a week-old anchor, placing operations inside lease
 * windows on the strength of a clock nobody has checked since Tuesday — and it
 * will look completely healthy while doing it. There is no operational need
 * that justifies a per-deployment answer to "how long may we vouch for time we
 * cannot re-verify".
 */

/**
 * The ONE approved signature profile Edge signs receipts with.
 *
 * Deliberately not configurable. `claimed_edge_signature_profile` on the frozen
 * receipt is bound to central's registry profile and refused as
 * EDGE_SIGNATURE_PROFILE_CLAIM_MISMATCH, so a deployment cannot force a weaker
 * algorithm past central — but an env var here would let a mistyped value take
 * an Edge's receipts out of service silently, with the failure visible only
 * hours later at reconciliation. Adding a second profile is a contract change
 * in `DEVICE_SIGNATURE_PROFILES`, not a deployment decision.
 */
export const EDGE_SIGNATURE_PROFILE: DeviceSignatureProfile = 'P256_ECDSA_SHA256';

/**
 * THE ABSOLUTE CEILING ON ANCHOR HOLDOVER, AND WHY IT IS THIS NUMBER.
 *
 * An Edge holding a trusted-time anchor is vouching for wall-clock time it
 * cannot re-verify while the WAN is down. The longest window in which that
 * vouching can matter is the longest life a policy lease can have, because
 * beyond that every operation the anchor could place inside a lease is refused
 * on the lease's own terms anyway. So the ceiling is not an independently
 * chosen number — it IS `DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS`, imported rather
 * than restated so the two cannot drift into disagreeing about what six hours
 * means.
 *
 * FW2-10: central MAY issue an anchor with a SHORTER holdover, and the anchor
 * record carries its own. This is the maximum a record may name, not the value
 * every record has.
 */
export const EDGE_TRUSTED_TIME_ANCHOR_MAX_HOLDOVER_MS = DEVICE_OFFLINE_LEASE_MAX_LIFETIME_MS;

/**
 * Hard deadline on any readiness probe. A probe is a diagnostic; a diagnostic
 * that can hang is an outage of its own, and an Edge whose readiness endpoint
 * stalls looks identical to an Edge that is gone.
 */
export const EDGE_READINESS_PROBE_TIMEOUT_MS = 1_500;
