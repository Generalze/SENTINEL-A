/**
 * SENTINEL — Decision Ledger module (WP-08).
 *
 * Exports `LedgerService` so ConstitutionModule can bind it as the real `LEDGER_SINK` (see the
 * authorised wiring change in constitution/constitution.module.ts). Deliberately depends on
 * nothing but `PrismaModule` — it does NOT import ConstitutionModule, so there is no module
 * import cycle: ConstitutionModule imports LedgerModule (one-directional), and its `LEDGER_SINK`
 * factory drains `BufferingLedgerSink` into `LedgerService` explicitly at the point both
 * instances are available to it, rather than LedgerModule reaching back into ConstitutionModule.
 */

import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { LedgerController } from './ledger.controller';
import { LedgerRepository } from './ledger.repository';
import { LedgerService } from './ledger.service';

@Module({
  imports: [PrismaModule],
  controllers: [LedgerController],
  providers: [LedgerRepository, LedgerService],
  exports: [LedgerService],
})
export class LedgerModule {}
