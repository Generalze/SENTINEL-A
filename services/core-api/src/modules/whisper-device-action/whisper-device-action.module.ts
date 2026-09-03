import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { ShieldModule } from '../shield/shield.module';
import { WhisperDeviceActionKeyResolver } from './whisper-device-action.key-resolver';
import { WhisperDeviceActionService } from './whisper-device-action.service';

/**
 * WP-27 — the M3 device-action verification path.
 *
 * WHAT THIS MODULE OWNS
 * ---------------------
 *   v2 claim parsing and submission assembly
 *   v2 registry key resolution, from Shield, by the DEVICE ROW's own pointer
 *   v2 signature verification, through WP-24's P-256 importer
 *   v2 replay orchestration, through Shield's ONE store, under its own ceremony
 *   the server-owned v2 verification RESULT
 *
 * WHAT IT DOES NOT OWN, AND MAY NOT REIMPLEMENT
 * ---------------------------------------------
 *   registry / trust semantics       Shield owns them
 *   curve arithmetic                 OpenSSL, via `P256KeyImporter`
 *   the frozen evaluators            packages/contracts owns them
 *   WHISPER RECOGNITION              `WhisperModule` owns it, and is FROZEN
 *
 * IT HAS NO CONTROLLER, AND THAT IS THE POINT.
 *
 * WP-21B's `whisper.module.ts` states the rule this module inherits: the
 * runtime is reached through an exported service, so the transport can only be
 * wired by something that can actually establish an authenticated device
 * identity. WP-25's gateway is that something. A route here would be a second
 * ingress with a second authentication story, and the whole reason WP-25 exists
 * is that there is exactly one.
 *
 * `WhisperModule` IS DELIBERATELY NOT IMPORTED
 * --------------------------------------------
 * Not the module, not `WhisperService`, not `WhisperRepository`, not
 * `WhisperSignatureVerifier`, not `WHISPER_DEVICE_KEY_RESOLVER`. D25-07's
 * prohibition is unchanged by WP-27: the v1 resolver verifies Ed25519 under a
 * frozen M2 contract and the Shield registry holds P-256 under the M3 profile,
 * and pointing one at the other would reinterpret a frozen contract rather than
 * version forward from it. `test/whisper-device-action-boundary.architecture.spec.ts`
 * asserts the absence as a SOURCE SCAN, because a property protected by review
 * is a property protected until the first busy week.
 *
 * NO NEW TABLE AND NO NEW MIGRATION. Replay reuses Shield's
 * `DeviceNonceConsumption` with a new `ceremony` label (D24-11), which already
 * holds the whole doctrine: the enforced `(organisation_id,
 * replay_identity_digest)` key, the compared-not-keyed statement fingerprint,
 * the stored outcome reference a duplicate converges on, and the rule that a
 * consumed identity is never deleted because deleting it RE-ADMITS the nonce it
 * retired.
 *
 * NO BACKGROUND SCHEDULER (D25-08). Every expiry this module enforces — the
 * context window, the recognition freshness bounds — is a comparison taken at
 * request time against the authoritative server clock.
 */
@Module({
  imports: [PrismaModule, ShieldModule],
  providers: [WhisperDeviceActionKeyResolver, WhisperDeviceActionService],
  exports: [WhisperDeviceActionService],
})
export class WhisperDeviceActionModule {}
