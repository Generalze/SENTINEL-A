/**
 * SENTINEL — Constitution module (WP-06).
 *
 * Exports `ConstitutionService` so other modules can call `evaluate(request)` in process, and
 * `LEDGER_SINK` so WP-08 can rebind the Decision Ledger sink without touching this module.
 *
 * The sink is bound to the in-memory `BufferingLedgerSink` stub via `useExisting`, so the same
 * instance is reachable under both tokens — a test (or WP-08's migration) can inject the
 * concrete class to drain it while production code only ever sees the `LedgerSink` interface.
 */

import { Module } from '@nestjs/common';
import { PrismaModule } from '../../prisma/prisma.module';
import { ConstitutionController } from './constitution.controller';
import { ConstitutionPolicyRepository } from './constitution.repository';
import { ConstitutionService } from './constitution.service';
import { BufferingLedgerSink, LEDGER_SINK } from './ledger.sink';

@Module({
  imports: [PrismaModule],
  controllers: [ConstitutionController],
  providers: [
    ConstitutionPolicyRepository,
    ConstitutionService,
    BufferingLedgerSink,
    { provide: LEDGER_SINK, useExisting: BufferingLedgerSink },
  ],
  exports: [ConstitutionService, LEDGER_SINK],
})
export class ConstitutionModule {}
