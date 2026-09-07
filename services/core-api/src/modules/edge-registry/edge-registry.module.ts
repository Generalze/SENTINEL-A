import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { ShieldModule } from '../shield/shield.module';
import { EdgeEnrolmentService } from './edge-enrolment.service';
import { EdgeRegistryRepository } from './edge-registry.repository';
import { EdgeRegistryService } from './edge-registry.service';
import { EdgeTransportEnrolmentService } from './edge-transport-enrolment.service';

/**
 * WP-29B / migration 26 — the central Edge identity registry.
 *
 * NO CONTROLLER, DELIBERATELY. The WP-24 Shield precedent (D24-13) applies with
 * more force here: an unauthenticated route that accepted an Edge's public key
 * would be exactly the trust-on-first-use door this whole ceremony exists to
 * close, and the transport for an Edge's half of it arrives with EDGE-B, which
 * carries its own authentication argument. Every step is reachable only as an
 * exported service method.
 *
 * IT IMPORTS SHIELD AND REUSES TWO COLLABORATORS RATHER THAN COPYING THEM:
 *
 *   `DeviceReplayService` — Sentinel's ONE anti-replay store, consumed with new
 *   ceremony labels. This is the WP-25/D25-10 precedent verbatim: the service
 *   classifies and never rules, so consuming it hands out no authority, and a
 *   second replay subsystem beside it would be a second copy of the
 *   FIRST_SEEN / EXACT_DUPLICATE / REUSED_WITH_CHANGED_SEMANTICS decision in a
 *   place nobody reviews as one.
 *
 *   `P256KeyImporter` — the runtime cryptographic boundary (D24-05). An Edge's
 *   offered point is imported by the same code a device's is, so an off-curve
 *   key dies at the same gate. There is no second import path and no second
 *   opinion about what a valid P-256 point is.
 *
 * IT WRITES NO SHIELD TABLE. The dependency runs one way: Edge calls Shield's
 * services, never touches its models, and no Shield row is ever consulted to
 * answer "what does Sentinel think of this Edge".
 */
@Module({
  imports: [PrismaModule, ShieldModule],
  providers: [EdgeTransportEnrolmentService, EdgeRegistryRepository, EdgeEnrolmentService, EdgeRegistryService],
  // WP-29B EDGE-B: the REPOSITORY is exported so the Edge transport boundary
  // can resolve a key across tenants and file its audit rows through the ONE
  // door to these tables, rather than opening a second one beside it. That is
  // the `ShieldRepository` precedent, and it costs nothing this module was
  // protecting: the repository holds no rules, so exporting it hands out no
  // authority — every judgement still lives in a service or in a frozen
  // contract, and the transport boundary owns none of them.
  exports: [EdgeTransportEnrolmentService, EdgeEnrolmentService, EdgeRegistryService, EdgeRegistryRepository],
})
export class EdgeRegistryModule {}
