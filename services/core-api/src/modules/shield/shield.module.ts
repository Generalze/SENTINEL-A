import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { DEVICE_ATTESTATION_EVALUATOR, UnavailableDeviceAttestationEvaluator } from './attestation.evaluator';
import { DeviceEnrollmentService } from './device-enrollment.service';
import { DeviceKeyService } from './device-key.service';
import { DeviceRegistryService } from './device-registry.service';
import { DeviceReplayService } from './device-replay.service';
import { DeviceSecurityAudit } from './device-security-audit';
import { DeviceTrustService } from './device-trust.service';
import { P256KeyImporter } from './p256-key.importer';
import { ShieldRepository } from './shield.repository';

/**
 * WP-24 Shield device registry.
 *
 * NO CONTROLLER, DELIBERATELY (D24-13). THIS IS THE PROHIBITION THAT KEEPS
 * PROOF C HONEST.
 *
 * WP-24 turns the frozen WP-23 contracts into authoritative persistent server
 * state. It adds NO device-facing route — no `POST /devices/enroll`, no
 * `POST /device-context`, no `POST /devices/authenticate`, no
 * `POST /device-actions`, no `POST /whisper/device` — and it also adds no
 * Command-side HTTP management surface, because the controller surface is not
 * enlarged merely to demonstrate that a registry exists. Every ceremony in
 * this module is reachable only as an exported service method, and the
 * integration suite drives those methods with authenticated principal
 * fixtures built by the same `buildPrincipal` the global DevAuthGuard uses.
 *
 * That is not caution about polish. There is still no production facility that
 * authenticates an incoming PHYSICAL DEVICE, and publishing a route before one
 * exists would mean accepting a device identity from a JSON body — the exact
 * trust hole C10-02 named for offline replay and W21-05 named for Whisper,
 * arriving a third time. A successful server-side enrollment test proves the
 * registry works; it proves nothing whatsoever about hardware.
 *
 * **WP-25 IS THE WORK PACKAGE THAT LIFTS THIS.** It owns the authenticated
 * device gateway. WP-26 owns the Field mobile client. WP-27 owns physical-device
 * Whisper. Until WP-25 lands, the seam here is an exported service and whoever
 * builds that gateway wires the transport.
 *
 * THE WHISPER DEVICE-KEY RESOLVER IS DELIBERATELY NOT WIRED TO THIS REGISTRY
 * -------------------------------------------------------------------------
 * `WHISPER_DEVICE_KEY_RESOLVER` resolves Ed25519 keys under the FROZEN Whisper
 * v1 contract. This registry holds P-256 under the M3 signature profile —
 * `device-signature.ts` explains at length why M3 versioned forward rather
 * than reinterpreting v1, and the two are not interchangeable key types. The
 * fail-closed resolver therefore stays exactly as WP-21B shipped it, and
 * connecting a real physical-device Whisper path is WP-27's work, not a side
 * effect of building a registry. This module does not import WhisperModule at
 * all, so there is no accidental route to that wiring.
 *
 * THE ATTESTATION EVALUATOR IS PROVIDED BY TOKEN, for the reason the Whisper
 * key resolver is: the seam must be replaceable by exactly one provider swap,
 * and a test must be able to supply VERIFIED or NEGATIVE evidence and observe
 * what the REGISTRY does with it without being able to reach into the trust
 * rules themselves. The default resolves nothing and reports `UNAVAILABLE`,
 * which is the honest answer when no provider is integrated (D24-07).
 */
@Module({
  imports: [PrismaModule],
  providers: [
    ShieldRepository,
    P256KeyImporter,
    DeviceReplayService,
    DeviceSecurityAudit,
    DeviceRegistryService,
    DeviceEnrollmentService,
    DeviceTrustService,
    DeviceKeyService,
    { provide: DEVICE_ATTESTATION_EVALUATOR, useClass: UnavailableDeviceAttestationEvaluator },
  ],
  // WP-25/D25-10: `DeviceReplayService` is exported so the device gateway can
  // consume Shield's ONE anti-replay store with a new `ceremony` value rather
  // than building a second replay subsystem beside it. It is the store, not a
  // decision: it classifies and never rules, so exporting it hands out no
  // authority. Everything else already had to be exported for WP-24's own
  // acceptance suite.
  exports: [
    ShieldRepository,
    DeviceRegistryService,
    DeviceEnrollmentService,
    DeviceTrustService,
    DeviceKeyService,
    DeviceReplayService,
    P256KeyImporter,
  ],
})
export class ShieldModule {}
