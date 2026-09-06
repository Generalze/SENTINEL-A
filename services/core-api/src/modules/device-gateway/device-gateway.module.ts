import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { FieldMessagingModule } from '../field-messaging/field-messaging.module';
import { FieldModule } from '../field/field.module';
import { ShieldModule } from '../shield/shield.module';
import { WhisperDeviceActionModule } from '../whisper-device-action/whisper-device-action.module';
import { DeviceContextService } from './device-context.service';
import { DeviceGatewayController } from './device-gateway.controller';
import { DeviceGatewayDomainAdapters } from './device-gateway.adapters';
import { DeviceGatewayRepository } from './device-gateway.repository';
import { DeviceGatewayService } from './device-gateway.service';
import { DeviceOfflineIngressService } from './device-offline-ingress.service';
import { DevicePolicyLeaseService } from './device-policy-lease.service';
import { FieldOfflineModule } from '../field-offline/field-offline.module';

/**
 * WP-25 Authenticated Device Gateway.
 *
 * WHAT THIS MODULE OWNS
 * ---------------------
 *   context establishment (the D25-03A ceremony)
 *   proof parsing and the canonical typed operation envelope (D25-11)
 *   registry and key resolution, and cryptographic verification
 *   current-principal assembly — both principals, independently
 *   replay orchestration, through Shield's ONE store
 *   the three domain adapters
 *   the gateway audit, and the REST controller
 *   THE FINAL CROSS-DOMAIN TRANSACTION (D25-02)
 *
 * WHAT IT DOES NOT OWN, AND MAY NOT REIMPLEMENT
 * ---------------------------------------------
 *   Field semantics                 FieldService owns them
 *   acknowledgement semantics       FieldMessagingService owns them
 *   registry / trust semantics      Shield owns them
 *   the frozen evaluators           packages/contracts owns them
 *
 * It imports FieldModule and FieldMessagingModule rather than reaching for
 * their repositories, for the reason `field-offline.module.ts` gives and D25-16
 * repeats: every effect must go through the SAME service entry points the live
 * HTTP routes use, so every domain rule, idempotency table, outbox row and
 * authorisation check applies identically on the human path and on the device
 * path. The gateway may not copy a transition rule, write a Field row,
 * reconstruct DELIVERED -> ACKNOWLEDGED, or create a Field audit or outbox row.
 * `test/device-gateway-boundary.architecture.spec.ts` scans the source for a
 * repository import rather than trusting review to notice one.
 *
 * THERE IS NO SECOND REPLAY SUBSYSTEM (D25-10)
 * --------------------------------------------
 * `DeviceReplayService` is consumed from ShieldModule with new `ceremony`
 * labels. A copy beside it would be two implementations of one security
 * decision, and the failure mode is not that the copy is wrong on the day it is
 * written — it is that the two drift and only one of them is the one an auditor
 * reads.
 *
 * THE FROZEN WHISPER v1 RESOLVER IS STILL NOT WIRED (D25-07), AND WP-27 DOES
 * NOT WIRE IT
 * -------------------------------------------------------------------------
 * WP-25 was the first work package with the technical means to break the
 * Whisper prohibition: it can authenticate a device, and it refused to become
 * the physical-device Whisper path. WP-27 is the sanctioned step forward, and
 * it takes it WITHOUT touching v1. `WHISPER_DEVICE_KEY_RESOLVER` verifies
 * Ed25519 under the frozen Whisper v1 contract; the Shield registry holds P-256
 * under the M3 profile. Pointing one at the other would reinterpret a frozen M2
 * contract, which is exactly what C14-01 versioned forward to avoid.
 *
 * So this module imports `WhisperDeviceActionModule` — the WP-27 v2 path, which
 * has its own contract, its own domain separator, its own key resolver, its own
 * ceremony label and its own result type — and it still imports NOTHING from
 * `../whisper/`. Not the module, not the service, not the verifier, not the
 * resolver token. Both facts are asserted as source scans:
 * `test/device-gateway-boundary.architecture.spec.ts` for this module, and
 * `test/whisper-device-action-boundary.architecture.spec.ts` for the v2 module
 * it now depends on — because an indirection is only a boundary if the far side
 * is guarded too.
 *
 * NO BACKGROUND SCHEDULER (D25-08). Expiry — of a context and of an
 * establishment challenge alike — is evaluated at request time. WP-24's live
 * suite already contends over one shared Postgres, and this module adds no job,
 * no sweeper and no cross-suite state coupling to that.
 *
 * REST ONLY (D25-10). No device WebSocket path; existing realtime untouched.
 */
@Module({
  /**
   * WP-29A adds `FieldOfflineModule`, and adds NOTHING ELSE.
   *
   * It is the WP-20 replay service alone — the module exports exactly that one
   * provider. The offline ingress deliberately does not reach past it into the
   * Field or messaging repositories: WP-20 already owns the cursor, the
   * receipt, the recovery lease and the single domain effect, and a second
   * caller writing those rows directly would be a second replay policy. The
   * architecture scan in `test/device-gateway-boundary.architecture.spec.ts`
   * keeps this honest by refusing repository imports outright.
   */
  imports: [PrismaModule, ShieldModule, FieldModule, FieldMessagingModule, WhisperDeviceActionModule, FieldOfflineModule],
  controllers: [DeviceGatewayController],
  providers: [
    DeviceGatewayRepository,
    DeviceGatewayDomainAdapters,
    DeviceContextService,
    DeviceGatewayService,
    DevicePolicyLeaseService,
    DeviceOfflineIngressService,
  ],
  exports: [DeviceContextService, DeviceGatewayService, DevicePolicyLeaseService, DeviceOfflineIngressService],
})
export class DeviceGatewayModule {}
