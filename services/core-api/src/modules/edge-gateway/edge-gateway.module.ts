import { Module } from '@nestjs/common';
import { EdgeRegistryModule } from '../edge-registry/edge-registry.module';
import { ShieldModule } from '../shield/shield.module';
import { EdgeAuthenticationService } from './edge-authentication.service';
import { EdgeWitnessService } from './edge-witness.service';

/**
 * WP-29B EDGE-B — the Edge→Central transport boundary.
 *
 * NO CONTROLLER, DELIBERATELY, and for a sharper reason than round 3's.
 *
 * `EdgeRegistryModule` publishes no route because an unauthenticated route that
 * accepted an Edge's public key would be the trust-on-first-use door the
 * enrolment ceremony exists to close. This module publishes none because the
 * route that reaches it must enforce the TWO-LAYER RULE in its own handler:
 * authenticate the caller with `EdgeAuthenticationService`, and only then hand
 * whatever receipt it carries to `EdgeWitnessService`. A route shipped ahead of
 * a handler that does that would be a surface on which a verified receipt could
 * be mistaken for an authenticated caller, which is the one defect this module
 * exists to make impossible. The seam is two exported services; the integration
 * suite drives them.
 *
 * IT IMPORTS SHIELD AND REUSES TWO COLLABORATORS RATHER THAN COPYING THEM,
 * exactly as `EdgeRegistryModule` does:
 *
 *   `DeviceReplayService` — Sentinel's ONE anti-replay store, consumed with a
 *   new ceremony label. The service classifies and never rules, so consuming it
 *   hands out no authority, and a second replay subsystem beside it would be a
 *   second copy of the FIRST_SEEN / EXACT_DUPLICATE / REUSED_WITH_CHANGED_SEMANTICS
 *   decision in a place nobody reviews as one.
 *
 *   `P256KeyImporter` — the runtime cryptographic boundary (D24-05). An Edge's
 *   request signature and an Edge's receipt signature are verified by the same
 *   code a device's proof is, against a key imported through OpenSSL's own
 *   point decoder. There is no second verification recipe here and none is
 *   permitted.
 *
 * IT ADDS NO TABLE AND NO MIGRATION. Everything it needs already exists:
 * `edge_registry_keys` and `edges` hold the identity, `device_nonce_consumptions`
 * holds the one-shot identities under a new label, and `edge_security_events`
 * holds the audit. A transport boundary that needed its own persistence would
 * be a transport boundary that had started remembering things about callers,
 * which is how a stateless proof becomes a session.
 */
@Module({
  imports: [EdgeRegistryModule, ShieldModule],
  providers: [EdgeAuthenticationService, EdgeWitnessService],
  exports: [EdgeAuthenticationService, EdgeWitnessService],
})
export class EdgeGatewayModule {}
