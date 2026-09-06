import { Module } from '@nestjs/common';
import { CentralTrustedTimeAnchorSigner } from './edge-trusted-time-anchor.signer';
import { EDGE_TRUSTED_TIME_SIGNING_KEY_PROVIDER_BINDING } from './edge-trusted-time-signing-key.provider';

/**
 * WP-29B / FW2-11 — central's trusted-time anchor issuance.
 *
 * NO CONTROLLER. This module registers no HTTP surface at all, following the
 * WP-24 Shield precedent (D24-13), and the reason is sharper here than it was
 * there: an unauthenticated route that returns a signed assertion of the
 * current time, bound to whatever Edge identity the body named, would hand any
 * caller a valid anchor for any Edge. The route that reaches this service is
 * EDGE-B's, it authenticates the Edge, and it resolves `edge_id`,
 * `organisation_id` and `site_id` from that authentication rather than from the
 * request — which is why `EdgeTrustedTimeAnchorRequest` keeps them separate
 * from the Edge-supplied `claim`.
 *
 * THE PROVIDER IS NOT EXPORTED, AND THAT IS THE POINT.
 *
 * `EDGE_TRUSTED_TIME_SIGNING_KEY_PROVIDER` is bound inside this module and
 * exported nowhere. Only `CentralTrustedTimeAnchorSigner` leaves, so no other
 * module in the service can inject the signing key — not by accident, and not
 * by a one-line import. Combined with the branded statement type the provider's
 * sign method requires, reaching this key for any other purpose takes a
 * deliberate, visible change in two files.
 *
 * PURPOSE SEPARATION, RESTATED WHERE IT IS WIRED.
 *
 * This key is not the Android device key (a public key Sentinel VERIFIES), not
 * the Edge enrolment key (likewise), not a TLS key (a transport identity), and
 * not a Whisper key (a frozen M2 domain WP-26 was explicitly forbidden from
 * touching). Those all point inward: they are credentials of principals
 * Sentinel does not control. This one points outward and is the only key
 * Sentinel signs with.
 */
@Module({
  providers: [EDGE_TRUSTED_TIME_SIGNING_KEY_PROVIDER_BINDING, CentralTrustedTimeAnchorSigner],
  exports: [CentralTrustedTimeAnchorSigner],
})
export class EdgeTrustedTimeModule {}
