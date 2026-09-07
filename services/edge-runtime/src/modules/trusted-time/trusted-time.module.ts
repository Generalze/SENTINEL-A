import { Module } from '@nestjs/common';
import { EdgeTrustedTimeAnchorVerifier } from './edge-trusted-time.verifier';
import { EDGE_TRUSTED_TIME_KEYRING, EDGE_TRUSTED_TIME_KEYRING_BINDING } from './edge-trusted-time.keyring';
import { EDGE_TRUSTED_TIME_ANCHOR_STORE, EDGE_TRUSTED_TIME_ANCHOR_STORE_BINDING } from './edge-trusted-time.store';
import { P256AnchorSignatureVerifier } from './p256-anchor.verifier';

/**
 * EDGE-C. This module declares NO controller, so it adds no HTTP surface at all
 * — the WP-24 Shield precedent, and sharper here: a route that let a caller ask
 * a box on a customer LAN what time it thinks it is, or hand it an anchor to
 * adopt, would be an unauthenticated way to reach the one value every Edge
 * receipt is derived from. The exchange that obtains an anchor is EDGE-B's,
 * authenticated, and outbound.
 *
 * `EdgeTrustedTimeAnchor` itself is deliberately NOT a provider. It is pure
 * logic over a verified statement and an injected reading; making it injectable
 * would invite it to acquire a clock, and the property that it has none is the
 * one a reader can check by looking at its imports.
 *
 * Both the keyring and the store are bound through FACTORIES that choose the
 * safe default when configuration is absent — see each binding for why. The
 * pairing between them is the important part: persistence is selected only when
 * a verification keyring is pinned, because a persisted anchor is worth exactly
 * as much as Edge's ability to verify it.
 */
@Module({
  providers: [
    P256AnchorSignatureVerifier,
    EDGE_TRUSTED_TIME_KEYRING_BINDING,
    EDGE_TRUSTED_TIME_ANCHOR_STORE_BINDING,
    EdgeTrustedTimeAnchorVerifier,
  ],
  exports: [EdgeTrustedTimeAnchorVerifier, EDGE_TRUSTED_TIME_ANCHOR_STORE, EDGE_TRUSTED_TIME_KEYRING],
})
export class EdgeTrustedTimeModule {}
