/**
 * SENTINEL — Constitution module (WP-06).
 *
 * Exports `ConstitutionService` so other modules can call `evaluate(request)` in process, and
 * `LEDGER_SINK` so WP-08 can rebind the Decision Ledger sink without touching this module.
 *
 * WP-08 LEDGER_SINK WIRING (authorised exception — see WP-08's directive: this is the one
 * change WP-08 may make in this module, everything else here is WP-06's).
 * ------------------------------------------------------------------------------------------
 * `LEDGER_SINK` is now bound to the durable `LedgerService` (services/core-api/src/modules/
 * ledger) via a factory, not `useExisting: BufferingLedgerSink` as before. `BufferingLedgerSink`
 * stays a provider here purely so the factory can hand it to `LedgerService.drainBuffer`, which
 * flushes anything buffered before this binding took effect into the durable store — the
 * directive's "wire ConstitutionService's buffered stub to the real sink at module init (flush
 * the buffer)" requirement. This only requires ConstitutionModule to import LedgerModule
 * (one-directional: LedgerModule does not import ConstitutionModule back), so there is no
 * module import cycle.
 */

import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { LedgerModule } from '../ledger/ledger.module';
import { LedgerService } from '../ledger/ledger.service';
import { ConstitutionController } from './constitution.controller';
import { ConstitutionPolicyRepository } from './constitution.repository';
import { ConstitutionService } from './constitution.service';
import { BufferingLedgerSink, LEDGER_SINK } from './ledger.sink';

@Module({
  imports: [PrismaModule, LedgerModule],
  controllers: [ConstitutionController],
  providers: [
    ConstitutionPolicyRepository,
    ConstitutionService,
    BufferingLedgerSink,
    {
      provide: LEDGER_SINK,
      useFactory: async (ledgerService: LedgerService, buffer: BufferingLedgerSink): Promise<LedgerService> => {
        await ledgerService.drainBuffer(buffer);
        return ledgerService;
      },
      inject: [LedgerService, BufferingLedgerSink],
    },
  ],
  exports: [ConstitutionService, LEDGER_SINK],
})
export class ConstitutionModule {}
