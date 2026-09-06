import { Module } from '@nestjs/common';
import { EDGE_TRUSTED_TIME_ANCHOR_STORE, NonPersistentEdgeTrustedTimeAnchorStore } from './edge-trusted-time.store';

/**
 * EDGE-C, partial. This module declares NO controller, so it adds no HTTP
 * surface at all — following the WP-24 Shield precedent. Edge's ingress for
 * device operations is EDGE-B's work and arrives with its own authentication
 * argument; a trusted-time module that could be poked over HTTP would be a way
 * to ask a box on a customer LAN what time it thinks it is, and then to tell it.
 *
 * `EdgeTrustedTimeAnchor` itself is deliberately NOT a provider. It is pure
 * logic over an injected reading, constructed by whatever holds the current
 * anchor; making it injectable would invite it to acquire a clock.
 */
@Module({
  providers: [{ provide: EDGE_TRUSTED_TIME_ANCHOR_STORE, useClass: NonPersistentEdgeTrustedTimeAnchorStore }],
  exports: [EDGE_TRUSTED_TIME_ANCHOR_STORE],
})
export class EdgeTrustedTimeModule {}
